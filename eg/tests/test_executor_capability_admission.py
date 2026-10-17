"""#8: only configured worker capabilities may authorize a new PRE gate."""
import pytest
from harness import gw,CLIENT,HEAD,HITL,register,raw_eval,claim,step_ref,e2_action,WORKER_OUTPUT

@pytest.mark.parametrize("action_type,effect",[
    ("service_cutover","E3"),("shell","E1"),("delete","E2")])
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
    a={"action_type":"read","target":target,"effect_class":"E0",
       "reversible":False,"real_world_effect":False,"proofs":[]}
    r=raw_eval(task,ch,0,claims=[claim(step_ref(task,"PRE_EXECUTION",0))],action=a)
    assert r.status_code==409 and r.json()["detail"]["code"]=="EXECUTOR_TARGET_OUTSIDE_PROVISIONED_BOUNDS"

def test_supported_write_can_ready_and_capabilities_advertised():
    task,ch=register(physical=True)
    a=e2_action(task,0)
    r=raw_eval(task,ch,0,claims=[claim(step_ref(task,"PRE_EXECUTION",0))],action=a)
    assert r.status_code==200 and r.json()["verdict"]=="READY_TO_EXECUTE"
    p=CLIENT.get("/v1/protocol",headers=HEAD).json()
    assert len(p["executor_capabilities"])==2
    assert p["executor_target_root_provisioned"]
    assert CLIENT.get("/v1/audit/verify",headers=HEAD).json()["status"]=="PASS"

def test_missing_worker_configuration_rejects_new_pre(monkeypatch):
    task,ch=register()
    a=e2_action(task,0)
    monkeypatch.setattr(gw,"EXECUTOR_OUTPUT_ROOT","")
    r=raw_eval(task,ch,0,claims=[claim(step_ref(task,"PRE_EXECUTION",0))],action=a)
    assert r.status_code==409 and r.json()["detail"]["code"]=="EXECUTOR_OUTPUT_ROOT_NOT_PROVISIONED"

@pytest.mark.parametrize("effect",["E3","E4","E5"])
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
