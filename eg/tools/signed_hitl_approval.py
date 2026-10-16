"""Verify independently signed, action-bound HITL decisions.

This verifies authorization only. It never authorizes an executor by itself.
The protected adapter must durably consume the approval nonce atomically before
any effect; until that implementation exists E3–E5 remain blocked.
"""
from __future__ import annotations
import base64
import json
import math
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FIELDS={"version","task_id","step_key","gate_checkpoint_no","action_fingerprint",
        "adapter_id","decision","issued_at","expires_at","nonce"}
class HitlDenied(RuntimeError):
    pass

def canonical(obj):
    return json.dumps(obj,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()

def verify_approval(envelope, public_key_b64, *, task_id,step_key,
                    gate_checkpoint_no,action_fingerprint,adapter_id,now=None):
    if not isinstance(envelope,dict) or set(envelope)!=FIELDS|{"signature_b64"}:
        raise HitlDenied("HITL_INVALID_ENVELOPE")
    body={k:envelope[k] for k in FIELDS}
    if (type(body["version"]) is not int or body["version"]!=1 or
        body["decision"]!="APPROVED" or type(body["gate_checkpoint_no"]) is not int or
        body["gate_checkpoint_no"]!=gate_checkpoint_no or
        any(body[k]!=v for k,v in {
            "task_id":task_id,"step_key":step_key,
            "action_fingerprint":action_fingerprint,"adapter_id":adapter_id}.items())):
        raise HitlDenied("HITL_SCOPE_OR_DECISION_DENIED")
    issued,expiry=body["issued_at"],body["expires_at"]
    instant=time.time() if now is None else now
    if (any(type(x) not in (int,float) or not math.isfinite(x) for x in (issued,expiry,instant))
        or expiry<=issued or expiry-issued>300 or issued>instant+30 or instant>=expiry
        or not isinstance(body["nonce"],str) or not 16<=len(body["nonce"])<=128):
        raise HitlDenied("HITL_EXPIRED_OR_INVALID_WINDOW")
    try:
        pub=base64.b64decode(public_key_b64,validate=True)
        sig=base64.b64decode(envelope["signature_b64"],validate=True)
        if len(pub)!=32 or len(sig)!=64:
            raise ValueError("invalid key length")
        Ed25519PublicKey.from_public_bytes(pub).verify(sig,canonical(body))
    except Exception as exc:
        raise HitlDenied("HITL_INVALID_SIGNATURE") from exc
    return {"status":"SIGNED_APPROVAL_VERIFIED_NOT_CONSUMED",
            "nonce":body["nonce"],"expires_at":expiry}
