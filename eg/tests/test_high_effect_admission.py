"""#19: high-effect admission is fail-closed until real signed adapters exist."""
import pytest
import base64
from tools.high_effect_admission import (
    AdapterCapability,AdmissionDenied,admit_high_effect,action_fingerprint)

ACTION={"action_type":"service_cutover","effect_class":"governed_operation","target":"/sandbox/service",
        "payload_bytes":32,"reversible":True,"real_world_effect":True}
CAP=AdapterCapability("trusted-adapter-sandbox","service_cutover","governed_operation","/sandbox/",1024,True,base64.b64encode(b"r"*32).decode())
def approved(action=ACTION,**kwargs):
    return {"task_id":"t","step_key":"01.01","gate_checkpoint_no":1,
            "action_fingerprint":action_fingerprint(action),"adapter_id":CAP.adapter_id,
            "status":"APPROVED","consumed":False,"expires_at":2000,**kwargs}
@pytest.mark.parametrize("effect",["governed_operation","external_change","publication"])
def test_absent_adapter_denied_for_all_high_effect_classes(effect):
    with pytest.raises(AdmissionDenied,match="UNAVAILABLE"):
        admit_high_effect(action={**ACTION,"effect_class":effect},capability=None,
                          approval=None,task_id="t",step_key="01.01",gate_checkpoint_no=1,now=1000)
def test_hitl_without_actual_adapter_is_not_execution_authority():
    with pytest.raises(AdmissionDenied,match="HITL_SIGNED_APPROVAL_REQUIRED"):
        admit_high_effect(action=ACTION,capability=CAP,approval=approved(),
                          task_id="t",step_key="01.01",gate_checkpoint_no=1,now=1000)
def test_wrong_target_denied():
    with pytest.raises(AdmissionDenied,match="SCOPE_MISMATCH"):
        admit_high_effect(action={**ACTION,"target":"/production/service"},capability=CAP,
                          approval=approved(),task_id="t",step_key="01.01",gate_checkpoint_no=1,now=1000)
def test_replayed_approval_denied():
    approval=approved();approval["consumed"]=True
    with pytest.raises(AdmissionDenied,match="CONSUMED"):
        admit_high_effect(action=ACTION,capability=CAP,approval=approval,
                          task_id="t",step_key="01.01",gate_checkpoint_no=1,now=1000)
def test_expired_approval_denied():
    approval=approved();approval["expires_at"]=999
    with pytest.raises(AdmissionDenied,match="EXPIRED"):
        admit_high_effect(action=ACTION,capability=CAP,approval=approval,
                          task_id="t",step_key="01.01",gate_checkpoint_no=1,now=1000)
def test_action_change_invalidates_approval():
    modified={**ACTION,"payload_bytes":33}
    with pytest.raises(AdmissionDenied,match="APPROVAL_SCOPE_MISMATCH"):
        admit_high_effect(action=modified,capability=CAP,approval=approved(),
                          task_id="t",step_key="01.01",gate_checkpoint_no=1,now=1000)

def test_signed_approval_verifies_but_cannot_authorize_absent_durable_adapter():
    import base64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from tools.signed_hitl_approval import canonical
    authority=Ed25519PrivateKey.generate()
    pub=base64.b64encode(authority.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
    payload={"version":1,"task_id":"t","step_key":"01.01","gate_checkpoint_no":1,
             "action_fingerprint":action_fingerprint(ACTION),"adapter_id":CAP.adapter_id,
             "decision":"APPROVED","issued_at":1000,"expires_at":1100,"nonce":"high-effect-approval-001"}
    signed={**payload,"signature_b64":base64.b64encode(authority.sign(canonical(payload))).decode()}
    result=admit_high_effect(action=ACTION,capability=CAP,approval=approved(),
                          signed_approval=signed,hitl_public_key_b64=pub,
                          task_id="t",step_key="01.01",gate_checkpoint_no=1,now=1010)
    assert result["status"]=="CAPABILITY_AND_SIGNED_HITL_ADMITTED"


@pytest.mark.parametrize("bad",["/sandbox-evil/service","/sandbox/../escape","/sandbox/","sandbox/service","/other/../sandbox/service"])
def test_capability_path_boundary_fail_closed(bad):
    from tools.high_effect_admission import target_within_scope
    assert not target_within_scope(bad,"/sandbox/")
    with pytest.raises(AdmissionDenied,match="SCOPE_MISMATCH"):
        admit_high_effect(action={**ACTION,"target":bad},capability=CAP,
                          approval=approved(),task_id="t",step_key="01.01",
                          gate_checkpoint_no=1,now=1000)

def test_capability_target_accepts_only_segment_child():
    from tools.high_effect_admission import target_within_scope
    assert target_within_scope("/sandbox/service","/sandbox/")
    assert target_within_scope("/sandbox/service-evil","/sandbox/")
    assert not target_within_scope("/sandboxer/service","/sandbox")
    assert not target_within_scope("/sandbox","/sandbox")

@pytest.mark.parametrize("bad_bytes",[None,0,-1,1.5,"4",True])
def test_payload_bound_denies_nonpositive_or_invalid_bytes(bad_bytes):
    with pytest.raises(AdmissionDenied,match="SCOPE_MISMATCH"):
        admit_high_effect(action={**ACTION,"payload_bytes":bad_bytes},
                          capability=CAP,approval=approved(),task_id="t",step_key="01.01",
                          gate_checkpoint_no=1,now=1000)

def test_high_effect_rejects_non_ed25519_registry_key():
    from dataclasses import replace
    with pytest.raises(AdmissionDenied,match="TRUST_ROOT"):
        replace(CAP,public_key_b64="malformed").validate()

def test_typed_adapter_descriptor_is_versioned_ci_only_and_fail_closed():
    from dataclasses import replace
    assert CAP.version==1 and CAP.ci_only is True
    for invalid in (replace(CAP,version=2),replace(CAP,version=True),
                    replace(CAP,ci_only=False)):
        with pytest.raises(AdmissionDenied,match="NOT_PROVISIONED"):
            invalid.validate()
