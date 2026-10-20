"""Cross-adapter read-only recovery decisions; never reauthorize an unknown effect.

Inputs must originate from independently authenticated journal and EG
observations. A state classification is NOT proof and never signs receipts.
"""
from __future__ import annotations

class RecoveryDenied(ValueError):
    pass

def classify_recovery(*, gate:dict, journal:str, receipt_valid:bool,
                      effect_independently_verified:bool,
                      post_verified:bool=False)->dict:
    if (not isinstance(gate,dict) or
        set(gate)!={"task_id","step_key","gate_checkpoint_no","action_fingerprint"}
        or not isinstance(gate["task_id"],str) or not gate["task_id"]
        or not isinstance(gate["step_key"],str) or not gate["step_key"]
        or type(gate["gate_checkpoint_no"]) is not int or gate["gate_checkpoint_no"]<1
        or not isinstance(gate["action_fingerprint"],str) or len(gate["action_fingerprint"])!=64
        or any(c not in "0123456789abcdef" for c in gate["action_fingerprint"])
        or journal not in ("ABSENT","CLAIMED_UNKNOWN","SEALED_RECEIPT",
                           "RETIRED_NO_EFFECT","COMPENSATED","MANUAL_REVIEW")
        or any(type(x) is not bool for x in (receipt_valid,effect_independently_verified,post_verified))):
        raise RecoveryDenied("INVALID_RECOVERY_OBSERVATION")
    if post_verified:
        if not (journal in ("SEALED_RECEIPT","COMPENSATED") and receipt_valid and effect_independently_verified):
            raise RecoveryDenied("UNSUPPORTED_VERIFIED_POST")
        status,next_action="POST_VERIFIED","NONE"
    elif journal=="MANUAL_REVIEW":
        status,next_action="MANUAL_REVIEW","INDEPENDENT_OPERATOR_RECONCILIATION"
    elif journal=="ABSENT":
        if receipt_valid or effect_independently_verified:
            raise RecoveryDenied("UNCLAIMED_EFFECT_INCONSISTENT")
        status,next_action="NOT_STARTED","RECHECK_CANONICAL_PRE"
    elif journal=="RETIRED_NO_EFFECT":
        if receipt_valid or effect_independently_verified:
            raise RecoveryDenied("RETIRED_EFFECT_INCONSISTENT")
        status,next_action="SIGNED_NO_EFFECT","RECONCILE_ORIGINAL_GATE"
    elif journal=="SEALED_RECEIPT" and receipt_valid and effect_independently_verified:
        status,next_action="VERIFIED_EFFECT","SUBMIT_CANONICAL_POST"
    elif journal=="COMPENSATED" and receipt_valid and effect_independently_verified:
        status,next_action="COMPENSATED","SUBMIT_COMPENSATION_POST"
    else:
        status,next_action="CLAIMED_UNKNOWN","INDEPENDENT_OPERATOR_RECONCILIATION"
    return {"status":status,"next_action":next_action,
            "allow_new_effect":False,"authorization":False,
            "task_id":gate["task_id"],"step_key":gate["step_key"],
            "gate_checkpoint_no":gate["gate_checkpoint_no"],
            "action_fingerprint":gate["action_fingerprint"]}
