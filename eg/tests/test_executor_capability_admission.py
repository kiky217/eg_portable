"""#8: only configured worker capabilities may authorize a new PRE gate."""
import pytest
from harness import gw,CLIENT,HEAD,HITL,register,raw_eval,claim,step_ref,bounded_write_action

@pytest.mark.parametrize("action_type,effect",[
    ("service_cutover","governed_operation"),("delete","bounded_change")])
def test_unsupported_action_rejected_without_checkpoint(action_type,effect):
    task,ch=register()
    a={"action_type":action_type,"target":"service","effect_class":effect,
       "reversible":True,"real_world_effect":True,"proofs":[]}
    r=raw_eval(task,ch,0,claims=[claim(step_ref(task,"PRE_EXECUTION",0))],action=a)
    assert r.status_code==409 and r.json()["detail"]["code"]=="UNSUPPORTED_ACTION_CAPABILITY_FAIL_CLOSED"
    assert CLIENT.get(f"/v1/tasks/{task}/state",headers=HEAD).json()["latest_checkpoint"] is None

@pytest.mark.parametrize("target",["/tmp/bad.txt","relative.txt","/tmp/bad.sh"])
def test_outside_worker_scope_rejected(target):
    task,ch=register()
    a={"action_type":"read","target":target,"effect_class":"observation",
       "reversible":False,"real_world_effect":False,"proofs":[]}
    r=raw_eval(task,ch,0,claims=[claim(step_ref(task,"PRE_EXECUTION",0))],action=a)
    assert r.status_code==409 and r.json()["detail"]["code"]=="EXECUTOR_TARGET_OUTSIDE_PROVISIONED_BOUNDS"

@pytest.mark.parametrize("action_type", ["read", "write", "replace"])
def test_canonical_action_can_omit_internal_class_without_changing_signed_payload(action_type):
    legacy={"action_type":action_type,"target":"workspace/example.txt",
            "effect_class":("observation" if action_type=="read" else "bounded_change"),
            "reversible":action_type!="read"}
    plain={k:v for k,v in legacy.items() if k!="effect_class"}
    assert gw.Action.model_validate(plain).model_dump(mode="json")==gw.Action.model_validate(legacy).model_dump(mode="json")


def test_unknown_action_without_class_is_rejected():
    from pydantic import ValidationError
    with pytest.raises(ValidationError,match="operation is not supported"):
        gw.Action.model_validate({"action_type":"service_control","target":"server"})


def test_e1_unimplemented_class_rejected_at_action_schema():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        gw.Action.model_validate({"action_type":"shell","target":"/tasks/example",
                                  "effect_class":"undefined_scope"})


def test_supported_write_can_ready_and_capabilities_advertised():
    task,ch=register(physical=True)
    a=bounded_write_action(task,0)
    r=raw_eval(task,ch,0,claims=[claim(step_ref(task,"PRE_EXECUTION",0))],action=a)
    assert r.status_code==200 and r.json()["verdict"]=="READY_TO_EXECUTE"
    p=CLIENT.get("/v1/protocol",headers=HEAD).json()
    assert {(c["action_type"],c["effect_class"]) for c in p["executor_capabilities"]}=={("read","observation"),("write","bounded_change"),("replace","bounded_change")}
    assert p["executor_target_root_provisioned"]
    assert CLIENT.get("/v1/audit/verify",headers=HEAD).json()["status"]=="PASS"

def test_missing_worker_configuration_rejects_new_pre(monkeypatch):
    task,ch=register()
    a=bounded_write_action(task,0)
    monkeypatch.setattr(gw,"EXECUTOR_OUTPUT_ROOT","")
    r=raw_eval(task,ch,0,claims=[claim(step_ref(task,"PRE_EXECUTION",0))],action=a)
    assert r.status_code==409 and r.json()["detail"]["code"]=="EXECUTOR_OUTPUT_ROOT_NOT_PROVISIONED"

@pytest.mark.parametrize("effect",["governed_operation","external_change","publication"])
def test_hitl_approval_alone_cannot_admit_unsupported_effect(effect):
    """Hybrid HITL must never convert absent executor capability into READY."""
    task,ch=register()
    action={"action_type":"service_cutover","target":"unsupported-service",
            "effect_class":effect,"reversible":False,
            "real_world_effect":True,"proofs":[]}
    r=raw_eval(task,ch,0,claims=[claim(step_ref(task,"PRE_EXECUTION",0))],
               action=action,headers=HITL)
    assert r.status_code==409,r.text
    assert r.json()["detail"]["code"]=="UNSUPPORTED_ACTION_CAPABILITY_FAIL_CLOSED"
    st=CLIENT.get(f"/v1/tasks/{task}/state",headers=HEAD).json()
    assert st["latest_checkpoint"] is None
    assert CLIENT.get("/v1/audit/verify",headers=HEAD).json()["status"]=="PASS"
