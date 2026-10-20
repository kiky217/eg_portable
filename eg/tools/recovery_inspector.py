"""Read-only, cross-adapter independent signed receipt recovery inspector.

The operator supplies independently authenticated current EG state, immutable
checkpoint detail and its own private ledger. This NEVER mutates canonical EG,
grants a new effect, or fabricates evidence after an ambiguous commit.
"""
from __future__ import annotations
import base64
from app.execution_receipts import verify as verify_receipt
from tools.high_effect_admission import action_fingerprint
from tools.generic_recovery import classify_recovery

class RecoveryInspectionDenied(RuntimeError):pass

def inspect(*,task_id,step_key,action,approval_nonce,adapter_id,
            eg_state,eg_detail,ledger):
    if (not all(isinstance(x,str) and x for x in
                (task_id,step_key,approval_nonce,adapter_id))
        or not isinstance(action,dict) or
        not isinstance(eg_state,dict) or not isinstance(eg_detail,dict)
        or not hasattr(ledger,"claim_status") or not hasattr(ledger,"read_sealed_receipt")):
        raise RecoveryInspectionDenied("INVALID_READONLY_RECONCILIATION_INPUT")
    gate=eg_state.get("pending_execution_gate")
    latest=eg_state.get("latest_checkpoint")
    fp=action_fingerprint(action)
    pin=gate.get("high_effect_pin") if isinstance(gate,dict) else None
    if (eg_state.get("status")!="IN_PROGRESS"
        or eg_state.get("current_step")!=step_key
        or eg_detail.get("task",{}).get("contract_status")!="OPEN"
        or not isinstance(gate,dict) or not isinstance(latest,dict)
        or not isinstance(pin,dict) or gate.get("task_id")!=task_id
        or gate.get("step_key")!=step_key
        or gate.get("action_fingerprint")!=fp
        or pin.get("action_fingerprint")!=fp
        or pin.get("adapter_id")!=adapter_id
        or pin.get("approval_nonce")!=approval_nonce
        or latest.get("checkpoint_no")!=gate.get("checkpoint_no")
        or latest.get("verdict")!="READY_TO_EXECUTE"):
        return {"status":"MANUAL_REVIEW","next_action":"RECONCILE_CANONICAL_GATE",
                "allow_new_effect":False,"authorization":False}
    cp=gate.get("checkpoint_no")
    if type(cp) is not int or cp<1:
        raise RecoveryInspectionDenied("INVALID_CANONICAL_GATE")
    record=next((row for row in eg_detail.get("checkpoints",[])
                 if row.get("checkpoint_no")==cp),None)
    if not record or record.get("verdict")!="READY_TO_EXECUTE":
        raise RecoveryInspectionDenied("ORIGINAL_PRE_CHECKPOINT_MISSING")
    scope=dict(task_id=task_id,step_key=step_key,gate_checkpoint_no=cp,
               action_fingerprint=fp,adapter_id=adapter_id)
    claim=ledger.claim_status(approval_nonce,**scope)
    receipt=ledger.read_sealed_receipt(approval_nonce,**scope)
    public=pin.get("public_key_b64")
    valid=False
    if receipt is not None:
        valid,reason=verify_receipt(receipt,public_b64=public,
          task_id=task_id,step_key=step_key,gate_checkpoint_no=cp,
          action_fingerprint=fp,target=action["target"],
          gate_created_at=record["created_at"])
        if not valid or receipt.get("executor_id")!="trusted-worker-"+adapter_id:
            raise RecoveryInspectionDenied("SEALED_RECEIPT_FAILED_INDEPENDENT_VERIFICATION")
    label="ABSENT" if claim is None else "SEALED_RECEIPT" if valid else "CLAIMED_UNKNOWN"
    report=classify_recovery(gate={"task_id":task_id,"step_key":step_key,
         "gate_checkpoint_no":cp,"action_fingerprint":fp},
         journal=label,receipt_valid=valid,effect_independently_verified=valid)
    if valid:
        # Only independently signed ORIGINAL worker receipt can be returned;
        # the EG canonical POST still decides the step.
        report["execution_receipt"]=receipt
    report["mutated"]=False
    return report
