"""Operator-pinned, bounded capability execution for independently controlled E3–E5 workers.

No agent-supplied executable, argv, shell, environment or working directory.
Must be hosted behind the existing separate-UID Unix RPC dispatcher.
"""
from __future__ import annotations
import base64, hashlib, os, signal, stat, subprocess, time
from datetime import datetime
from pathlib import Path
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from tools.durable_hitl_ledger import ApprovalLedger
from tools.high_effect_admission import action_fingerprint
from tools.signed_hitl_approval import verify_approval
from app.execution_receipts import body, sign
from app.no_effect_receipts import sign_no_effect
from tools.typed_payload_contract import validate_document,TypedPayloadDenied

class ProcessDenied(RuntimeError): pass

def _bounded_process(executable, args, data, timeout):
    """Terminate the entire action process group, including grandchildren."""
    child = subprocess.Popen((executable, *args), stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH":"/usr/bin:/bin", "PYTHONNOUSERSITE":"1", "HOME":"/nonexistent"},
        close_fds=True, start_new_session=True)
    try:
        stdout, stderr = child.communicate(data, timeout=timeout)
        return subprocess.CompletedProcess(child.args, child.returncode, stdout, stderr)
    finally:
        # A successful or timed-out child may leave effects in its process group.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()

class TrustedProcessEffect:
    def __init__(self, *, journal_dir, private_key, adapter_id, hitl_key_b64,
                 executable, fixed_args, target, timeout=20, max_stdout=262144,
                 input_schema=None, input_schema_sha256=None,
                 output_schema=None, output_schema_sha256=None,
                 effect_class="E3", action_type="bounded_process_run"):
        if (effect_class not in ("E3","E4","E5") or
            not isinstance(action_type,str) or not action_type or len(action_type)>200 or
            not isinstance(adapter_id,str) or not adapter_id.startswith("trusted-adapter-")
            or not isinstance(executable,str) or not Path(executable).is_absolute()
            or not isinstance(fixed_args,tuple) or not all(isinstance(a,str) for a in fixed_args)
            or not isinstance(target,str) or not target.startswith("/")):
            raise ProcessDenied("INVALID_OPERATOR_POLICY")
        info=os.stat(executable,follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or not info.st_mode & stat.S_IXUSR
            or info.st_mode & 0o022):
            raise ProcessDenied("UNSAFE_EXECUTABLE")
        # Mode bits on the executable alone are insufficient: an untrusted
        # parent can rename/replace an otherwise owner-pinned file.
        for parent in Path(executable).parents:
            directory=parent.lstat()
            if (not stat.S_ISDIR(directory.st_mode)
                or directory.st_uid not in (0,os.geteuid())
                or directory.st_mode & 0o022):
                raise ProcessDenied("UNSAFE_EXECUTABLE_PATH")
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
        self.effect_class=effect_class
        self.action_type=action_type
        self.hitl_key_b64=hitl_key_b64
        self.executable=executable
        self.fixed_args=fixed_args
        self.target=target
        self.timeout=timeout
        self.max_stdout=max_stdout

    def reconcile_no_effect(self, *, task_id, step_key, action, approval, gate):
        """Retire an unclaimed original nonce atomically; never guess physical state."""
        if (not isinstance(action,dict) or not isinstance(approval,dict)
            or action.get("action_type")!=self.action_type
            or action.get("effect_class")!=self.effect_class
            or action.get("target")!=self.target
            or (self.effect_class=="E4" and action.get("reversible") is not True)
            or (self.effect_class=="E5" and action.get("reversible") is not False)
            or not isinstance(gate,dict) or gate.get("task_id")!=task_id
            or gate.get("step_key")!=step_key or gate.get("verdict")!="READY_TO_EXECUTE"):
            raise ProcessDenied("ORIGINAL_PRE_REQUIRED_NO_EFFECT")
        fp=action_fingerprint(action)
        cp=gate.get("checkpoint_no")
        pin=gate.get("high_effect_pin")
        key=base64.b64encode(self.private.public_key().public_bytes(
            Encoding.Raw,PublicFormat.Raw)).decode()
        if (type(cp) is not int or cp<=0 or not isinstance(pin,dict)
            or pin.get("adapter_id")!=self.adapter_id
            or pin.get("public_key_b64")!=key
            or pin.get("approval_nonce")!=approval.get("nonce")
            or pin.get("action_fingerprint")!=fp
            or gate.get("action_fingerprint")!=fp or gate.get("hitl_approved") is not True):
            raise ProcessDenied("PINNED_PRE_REQUIRED_NO_EFFECT")
        verify_approval(approval,self.hitl_key_b64,task_id=task_id,step_key=step_key,
            gate_checkpoint_no=cp,action_fingerprint=fp,adapter_id=self.adapter_id,
            now=approval.get("issued_at"))
        scope=dict(task_id=task_id,step_key=step_key,gate_checkpoint_no=cp,
                   action_fingerprint=fp,adapter_id=self.adapter_id)
        # Journal retirement is atomic with checking that no effect was claimed.
        # An UNKNOWN claim fails closed even after a crash.
        self.ledger.retire_no_effect(approval["nonce"],**scope)
        return sign_no_effect(self.private,task_id=task_id,step_key=step_key,
            gate_checkpoint_no=cp,action_fingerprint=fp,target=self.target,
            executor_id="trusted-worker-"+self.adapter_id)

    def execute(self, *, task_id, step_key, action, approval, gate, gate_created_at, stdin):
        if (not isinstance(stdin,bytes) or not stdin or len(stdin)>524288
            or not isinstance(action,dict) or action.get("action_type")!=self.action_type
            or action.get("effect_class")!=self.effect_class or action.get("real_world_effect") is not True
            or (self.effect_class=="E5" and action.get("reversible") is not False)
            or (self.effect_class=="E4" and action.get("reversible") is not True)
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
            child=_bounded_process(self.executable,self.fixed_args,stdin,self.timeout)
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
