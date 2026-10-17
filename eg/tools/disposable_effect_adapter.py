"""Isolated disposable E3/E4/E5 effect adapter for GitHub CI only.

Never operates on host services. The only allowed effect is an exclusive,
payload-bound creation inside a private disposable sandbox. High-effect class
is preserved, not silently downgraded to E2. This is NOT a production adapter.
"""
from __future__ import annotations
import hashlib
import json
import os
import stat
import time
from datetime import datetime
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from app.execution_receipts import body, sign
from tools.durable_hitl_ledger import ApprovalLedger
from tools.high_effect_admission import AdapterCapability, action_fingerprint
from tools.signed_hitl_approval import verify_approval

class EffectDenied(RuntimeError): pass

ALLOWED={"E3":"sandbox_cutover","E4":"sandbox_critical_update","E5":"sandbox_irreversible_commit"}

class DisposableAdapter:
    def __init__(self,root,ledger_dir,executor_private,adapter_id,effect_class):
        self.root=Path(root).resolve(strict=True)
        self.ledger=ApprovalLedger(ledger_dir)
        if not self.root.is_dir() or self.root.is_symlink() or stat.S_IMODE(self.root.stat().st_mode)&0o077:
            raise EffectDenied("SANDBOX_ROOT_NOT_PRIVATE")
        if effect_class not in ALLOWED:raise EffectDenied("UNSUPPORTED_EFFECT_CLASS")
        self.effect_class=effect_class
        self.action_type=ALLOWED[effect_class]
        if not adapter_id.startswith("trusted-adapter-"):raise EffectDenied("INVALID_ADAPTER")
        self.adapter_id=adapter_id
        self.private=executor_private

    def execute(self,*,task_id,step_key,gate_checkpoint_no,gate_created_at,
                action,data,approval,hitl_public_key_b64,ready_gate,now=None,fault_hook=None):
        # No alternate runner/shell: require an authenticated gate snapshot from
        # a future EG integration. CI supplies a deterministic signed-policy fixture.
        if not ready_gate or ready_gate.get("task_id")!=task_id or ready_gate.get("step_key")!=step_key or ready_gate.get("checkpoint_no")!=gate_checkpoint_no or ready_gate.get("verdict")!="READY_TO_EXECUTE" or ready_gate.get("action_fingerprint")!=action_fingerprint(action):
            raise EffectDenied("EG_READY_PRE_REQUIRED")
        if action.get("action_type")!=self.action_type or action.get("effect_class")!=self.effect_class or len(data)==0 or len(data)>512*1024:
            raise EffectDenied("ACTION_CLASS_OR_PAYLOAD_DENIED")
        if action.get("payload_sha256")!=hashlib.sha256(data).hexdigest() or action.get("payload_bytes")!=len(data):
            raise EffectDenied("PRE_PAYLOAD_MISMATCH")
        target=Path(action.get("target",""))
        if (not target.is_absolute() or target.is_symlink() or target.resolve(strict=False).parent!=self.root or
            target.suffix!=".json"):
            raise EffectDenied("TARGET_OUTSIDE_DISPOSABLE_SCOPE")
        try:json.loads(data)
        except (UnicodeError,ValueError) as exc:raise EffectDenied("INVALID_JSON_EFFECT") from exc
        current=time.time() if now is None else now
        try:
            gate_epoch=datetime.fromisoformat(gate_created_at).timestamp()
        except (TypeError,ValueError,OverflowError) as exc:
            raise EffectDenied("INVALID_PRE_TIMESTAMP") from exc
        if current < gate_epoch-30 or current-gate_epoch>300:
            raise EffectDenied("PRE_LEASE_EXPIRED")
        fp=action_fingerprint(action)
        verify_approval(approval,hitl_public_key_b64,task_id=task_id,step_key=step_key,
                        gate_checkpoint_no=gate_checkpoint_no,action_fingerprint=fp,
                        adapter_id=self.adapter_id,now=current)
        scope={"task_id":task_id,"step_key":step_key,"gate_checkpoint_no":gate_checkpoint_no,
               "action_fingerprint":fp,"adapter_id":self.adapter_id}
        claimed=self.ledger.claim_status(approval["nonce"],**scope)
        if claimed is not None:
            # Restart reconciliation: never execute again. Exact physical readback
            # may recover the original receipt; absent/mismatched effect stays UNKNOWN.
            if not target.exists():
                raise EffectDenied("CLAIMED_EFFECT_UNKNOWN_NO_REPLAY")
            try: observed=target.read_bytes()
            except OSError as exc: raise EffectDenied("CLAIMED_EFFECT_UNKNOWN_NO_REPLAY") from exc
            if observed!=data:
                raise EffectDenied("CLAIMED_EFFECT_MISMATCH_NO_REPLAY")
            receipt=sign(body(task_id,step_key,gate_checkpoint_no,fp,
                              "trusted-worker-"+self.adapter_id,str(target),observed,
                              approval["nonce"],completed_ns=max(int(current*1e9),int(gate_epoch*1e9))),self.private)
            return {"status":"RECOVERED_EXECUTED_POST_NOT_VERIFIED","receipt":receipt}
        if target.exists():raise EffectDenied("PREEXISTING_EFFECT_RETROACTIVE_DENIED")
        # Claim before physical effect. A crash after this point never permits replay.
        self.ledger.consume(approval,hitl_public_key_b64,now=current,**scope)
        if fault_hook is not None:fault_hook("after_claim")
        fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            with os.fdopen(fd,"wb") as output:
                output.write(data);output.flush();os.fsync(output.fileno())
        except BaseException:
            # Unknown effect: nonce remains durably claimed.
            raise
        if fault_hook is not None:fault_hook("after_effect")
        observed=target.read_bytes()
        if observed!=data:raise EffectDenied("READBACK_MISMATCH")
        dirfd=os.open(self.root,os.O_DIRECTORY|os.O_RDONLY|os.O_NOFOLLOW)
        try:os.fsync(dirfd)
        finally:os.close(dirfd)
        receipt=sign(body(task_id,step_key,gate_checkpoint_no,fp,
                          "trusted-worker-"+self.adapter_id,str(target),observed,
                          approval["nonce"],completed_ns=max(int(current*1e9),int(gate_epoch*1e9))),self.private)
        return {"status":"EXECUTED_POST_NOT_VERIFIED","receipt":receipt}
