"""Portable high-effect admission contract. This module does NOT execute effects.

Every adapter must be independently provisioned, isolated, signed and verified
before connecting to the canonical EG gate. No fallback to E2 or agent shell.
"""
from __future__ import annotations
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any
from tools.signed_hitl_approval import verify_approval, HitlDenied

class AdmissionDenied(RuntimeError):
    pass

def canonical(value: Any) -> bytes:
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()

def action_fingerprint(action: dict) -> str:
    return hashlib.sha256(canonical(action)).hexdigest()

@dataclass(frozen=True)
class AdapterCapability:
    adapter_id: str
    action_type: str
    effect_class: str
    target_prefix: str
    maximum_payload_bytes: int
    isolated: bool
    public_key_b64: str

    def validate(self) -> None:
        if (not self.adapter_id.startswith("trusted-adapter-") or
            self.effect_class not in ("E3","E4","E5") or
            not self.action_type or not self.target_prefix.startswith("/") or
            not 0 < self.maximum_payload_bytes <= 512*1024 or
            not self.isolated or not self.public_key_b64):
            raise AdmissionDenied("HIGH_EFFECT_ADAPTER_NOT_PROVISIONED")

def admit_high_effect(*, action: dict, capability: AdapterCapability | None,
                      approval: dict | None, task_id: str, step_key: str,
                      gate_checkpoint_no: int, now: float | None = None,
                      signed_approval: dict | None = None,
                      hitl_public_key_b64: str | None = None) -> dict:
    """Fail-closed admission policy, not authorization to execute from an agent."""
    if not isinstance(action,dict) or action.get("effect_class") not in ("E3","E4","E5"):
        raise AdmissionDenied("NOT_A_HIGH_EFFECT_ACTION")
    if capability is None:
        raise AdmissionDenied("HIGH_EFFECT_ADAPTER_UNAVAILABLE")
    capability.validate()
    if (action.get("action_type") != capability.action_type or
        action.get("effect_class") != capability.effect_class or
        not isinstance(action.get("target"),str) or
        not action["target"].startswith(capability.target_prefix) or
        action.get("payload_bytes",0) > capability.maximum_payload_bytes):
        raise AdmissionDenied("HIGH_EFFECT_CAPABILITY_SCOPE_MISMATCH")
    if not isinstance(approval,dict):
        raise AdmissionDenied("EXPLICIT_HITL_REQUIRED")
    expected={"task_id":task_id,"step_key":step_key,"gate_checkpoint_no":gate_checkpoint_no,
              "action_fingerprint":action_fingerprint(action),"adapter_id":capability.adapter_id}
    if any(approval.get(k)!=v for k,v in expected.items()):
        raise AdmissionDenied("HITL_APPROVAL_SCOPE_MISMATCH")
    if (approval.get("status")!="APPROVED" or approval.get("consumed") is not False or
        type(approval.get("expires_at")) not in (int,float) or
        approval["expires_at"] <= (time.time() if now is None else now)):
        raise AdmissionDenied("HITL_EXPIRED_DENIED_OR_CONSUMED")
    if signed_approval is None or hitl_public_key_b64 is None:
        raise AdmissionDenied("HITL_SIGNED_APPROVAL_REQUIRED")
    try:
        verify_approval(signed_approval, hitl_public_key_b64,
                        task_id=task_id,step_key=step_key,
                        gate_checkpoint_no=gate_checkpoint_no,
                        action_fingerprint=action_fingerprint(action),
                        adapter_id=capability.adapter_id,now=now)
    except HitlDenied as exc:
        raise AdmissionDenied("HITL_SIGNATURE_OR_SCOPE_DENIED") from exc
    return {"status":"CAPABILITY_AND_SIGNED_HITL_ADMITTED",
            "adapter_id":capability.adapter_id,
            "action_fingerprint":action_fingerprint(action),
            "approval_nonce":signed_approval["nonce"]}
