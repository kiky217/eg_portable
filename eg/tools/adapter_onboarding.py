"""Operator-side read-only onboarding requirements for generic external adapters.

No key generation, self-registration or automatic trust elevation.
"""
from __future__ import annotations
from tools.high_effect_admission import AdapterCapability, AdmissionDenied

def inspect_onboarding(record: dict, *, gateway_uid: int, worker_uid: int,
                       notary_key: str, executor_key: str | None = None, hitl_key: str = "") -> dict:
    """Return stable missing prerequisites, never execution authorization."""
    problems=[]
    try:
        cap=AdapterCapability(**record)
        cap.validate(allow_external=True)
        if cap.ci_only:
            problems.append("CI_FIXTURE_NOT_PRODUCTION")
    except (TypeError, ValueError, AdmissionDenied):
        return {"status":"INVALID_ADAPTER_DESCRIPTOR","admission":False,
                "missing":["VALID_TYPED_ADAPTER_DESCRIPTOR"]}
    if (type(gateway_uid) is not int or type(worker_uid) is not int
            or gateway_uid<=0 or worker_uid<=0 or gateway_uid==worker_uid):
        problems.append("INDEPENDENT_WORKER_UID")
    roots=(notary_key,hitl_key,cap.public_key_b64)
    has_e2_root=executor_key not in (None, "")
    if has_e2_root:  # Bundled E2 is optional for an independent E3-only gateway.
        roots+=(executor_key,)
    if any(not isinstance(root,str) or not root for root in roots) or len(set(roots))!=len(roots):
        problems.append("FOUR_INDEPENDENT_SIGNING_ROOTS" if has_e2_root else "THREE_INDEPENDENT_SIGNING_ROOTS")
    problems.extend(["WORKER_RUNTIME_ATTESTATION","SCOPED_SIGNED_HITL",
                     "CANONICAL_PRE_AND_POST"])
    return {"status":"OPERATOR_PROVISIONING_REQUIRED","admission":False,
            "adapter_id":cap.adapter_id,"missing":problems,
            "next_action":"INDEPENDENT_OPERATOR_ONBOARDING",
            "note":"Static descriptor and distinct key values do not prove protected custody."}
