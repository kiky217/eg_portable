"""Verify independently signed, action-bound HITL decisions.

HITL is authorization only. Approval and revocation are independently signed,
short-lived and scope-bound. Durable consumption/revocation is enforced by the
protected adapter ledger, not by this verifier.
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

def verify_decision(envelope, public_key_b64, *, task_id,step_key,
                    gate_checkpoint_no,action_fingerprint,adapter_id,
                    allowed_decisions,now=None):
    if not isinstance(envelope,dict) or set(envelope)!=FIELDS|{"signature_b64"}:
        raise HitlDenied("HITL_INVALID_ENVELOPE")
    body={k:envelope[k] for k in FIELDS}
    if (type(body["version"]) is not int or body["version"]!=1 or
        body["decision"] not in allowed_decisions or
        type(body["gate_checkpoint_no"]) is not int or
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
    return {"status":"SIGNED_"+body["decision"]+"_VERIFIED_NOT_DURABLE",
            "nonce":body["nonce"],"expires_at":expiry}

def verify_approval(envelope, public_key_b64, **scope):
    result=verify_decision(envelope,public_key_b64,allowed_decisions={"APPROVED"},**scope)
    return {"status":"SIGNED_APPROVAL_VERIFIED_NOT_CONSUMED",
            "nonce":result["nonce"],"expires_at":result["expires_at"]}

def verify_revocation(envelope, public_key_b64, **scope):
    result=verify_decision(envelope,public_key_b64,allowed_decisions={"REVOKED"},**scope)
    return {"status":"SIGNED_REVOCATION_VERIFIED_NOT_DURABLE",
            "nonce":result["nonce"],"expires_at":result["expires_at"]}


def verify_denial(envelope, public_key_b64, **scope):
    result=verify_decision(envelope,public_key_b64,allowed_decisions={"DENIED"},**scope)
    return {"status":"SIGNED_DENIAL_VERIFIED_EFFECT_DENIED",
            "nonce":result["nonce"],"expires_at":result["expires_at"]}
