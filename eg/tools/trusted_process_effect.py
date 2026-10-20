"""Operator-pinned bounded subprocess adapter for an independently controlled E3 worker.

No agent-supplied executable, argv, shell, environment or working directory.
Must be hosted behind the existing separate-UID Unix RPC dispatcher.
"""
from __future__ import annotations
import base64, hashlib, os, stat, subprocess, time
from datetime import datetime
from pathlib import Path
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from tools.durable_hitl_ledger import ApprovalLedger
from tools.high_effect_admission import action_fingerprint
from tools.signed_hitl_approval import verify_approval
from app.execution_receipts import body, sign
from tools.typed_payload_contract import validate_document,TypedPayloadDenied

class ProcessDenied(RuntimeError): pass

class TrustedProcessEffect:
    def __init__(self, *, journal_dir, private_key, adapter_id, hitl_key_b64,
                 executable, fixed_args, target, timeout=20, max_stdout=262144,
                 input_schema=None, input_schema_sha256=None,
                 output_schema=None, output_schema_sha256=None):
        if (not isinstance(adapter_id,str) or not adapter_id.startswith("trusted-adapter-")
            or not isinstance(executable,str) or not Path(executable).is_absolute()
            or not isinstance(fixed_args,tuple) or not all(isinstance(a,str) for a in fixed_args)
            or not isinstance(target,str) or not target.startswith("/")):
            raise ProcessDenied("INVALID_OPERATOR_POLICY")
        info=os.stat(executable,follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or not info.st_mode & stat.S_IXUSR
            or info.st_mode & 0o022):
            raise ProcessDenied("UNSAFE_EXECUTABLE")
        if not 0<timeout<=30 or not 0<max_stdout<=524288:
            raise ProcessDenied("UNBOUNDED_EXECUTION")
        if ((input_schema is None)!=(input_schema_sha256 is None)
            or (output_schema is None)!=(output_schema_sha256 is None)):
            raise ProcessDenied("UNPINNED_OPERATOR_SCHEMA")
        self.input_schema=input_schema
        self.input_schema_sha256=input_schema_sha256
        self.output_schema=output_schema
        self.output_schema_sha256=output_schema_sha256
        self.ledger=ApprovalLedger(journal_dir)
        self.private=private_key
        self.adapter_id=adapter_id
        self.hitl_key_b64=hitl_key_b64
        self.executable=executable
        self.fixed_args=fixed_args
        self.target=target
        self.timeout=timeout
        self.max_stdout=max_stdout

    def execute(self, *, task_id, step_key, action, approval, gate, gate_created_at, stdin):
        if (not isinstance(stdin,bytes) or not stdin or len(stdin)>524288
            or not isinstance(action,dict) or action.get("action_type")!="bounded_process_run"
            or action.get("effect_class")!="E3" or action.get("real_world_effect") is not True
            or action.get("target")!=self.target
            or action.get("payload_bytes")!=len(stdin)
            or action.get("payload_sha256")!=hashlib.sha256(stdin).hexdigest()):
            raise ProcessDenied("PROCESS_ACTION_NOT_BOUND")
        if self.input_schema is not None:
            try:
                validate_document(self.input_schema,stdin,
                    expected_schema_sha256=self.input_schema_sha256,max_bytes=524288)
            except TypedPayloadDenied as exc:
                raise ProcessDenied("INPUT_SCHEMA_DENIED_NO_EFFECT") from exc
        fp=action_fingerprint(action)
        pin=gate.get("high_effect_pin") if isinstance(gate,dict) else None
        key=base64.b64encode(self.private.public_key().public_bytes(
            Encoding.Raw,PublicFormat.Raw)).decode()
        if (not isinstance(pin,dict) or pin.get("adapter_id")!=self.adapter_id
            or pin.get("public_key_b64")!=key or pin.get("approval_nonce")!=approval.get("nonce")
            or pin.get("action_fingerprint")!=fp or gate.get("task_id")!=task_id
            or gate.get("step_key")!=step_key or gate.get("verdict")!="READY_TO_EXECUTE"
            or not gate.get("hitl_approved") or gate.get("action_fingerprint")!=fp):
            raise ProcessDenied("ORIGINAL_CANONICAL_PRE_REQUIRED")
        cp=gate.get("checkpoint_no")
        if type(cp) is not int or cp<1:
            raise ProcessDenied("INVALID_GATE_NO")
        try:
            epoch=datetime.fromisoformat(gate_created_at).timestamp()
        except (TypeError,ValueError,OverflowError) as exc:
            raise ProcessDenied("INVALID_GATE_TIME") from exc
        now=time.time()
        if now<epoch-30 or now-epoch>300:
            raise ProcessDenied("PRE_EXPIRED")
        verify_approval(approval,self.hitl_key_b64,task_id=task_id,step_key=step_key,
            gate_checkpoint_no=cp,action_fingerprint=fp,adapter_id=self.adapter_id,now=now)
        scope=dict(task_id=task_id,step_key=step_key,gate_checkpoint_no=cp,
                   action_fingerprint=fp,adapter_id=self.adapter_id)
        nonce=approval["nonce"]
        if self.ledger.claim_status(nonce,**scope) is not None:
            raise ProcessDenied("UNKNOWN_EFFECT_NO_REPLAY")
        self.ledger.consume(approval,self.hitl_key_b64,now=now,**scope)
        try:
            child=subprocess.run((self.executable,*self.fixed_args),input=stdin,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False,timeout=self.timeout,
                env={"PATH":"/usr/bin:/bin","PYTHONNOUSERSITE":"1","HOME":"/nonexistent"},
                close_fds=True,start_new_session=True)
        except Exception as exc:
            raise ProcessDenied("EXECUTION_UNKNOWN_NO_REPLAY") from exc
        if child.returncode!=0 or not 0<len(child.stdout)<=self.max_stdout:
            raise ProcessDenied("EXECUTION_FAILED_OR_OVERSIZE_NO_REPLAY")
        if self.output_schema is not None:
            try:
                validate_document(self.output_schema,child.stdout,
                    expected_schema_sha256=self.output_schema_sha256,
                    max_bytes=self.max_stdout)
            except TypedPayloadDenied as exc:
                # Subprocess already ran: never retry this nonce. Do not sign
                # or submit a receipt for malformed or untrusted output.
                raise ProcessDenied("OUTPUT_SCHEMA_DENIED_UNKNOWN_NO_REPLAY") from exc
        receipt=sign(body(task_id,step_key,cp,fp,"trusted-worker-"+self.adapter_id,
                          self.target,child.stdout,nonce,
                          completed_ns=max(time.time_ns(),int(epoch*1e9))),self.private)
        return {"status":"EXECUTED_POST_NOT_VERIFIED",
                "receipt":self.ledger.seal_receipt(nonce,receipt,**scope),
                "output":child.stdout}
