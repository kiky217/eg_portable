"""Issue #5: physical gates cannot be superseded without reconciliation."""
from harness import CLIENT,HEAD,register,do_pre,do_post,e2_action,claim,step_ref,raw_eval
from test_vnext_suspend import req as suspend


def test_concrete_pre_cannot_replace_original_unconsumed_gate():
    task,ch=register(physical=True)
    action=e2_action(task,0)
    pre,_=do_pre(task,ch,0,action=action)
    assert pre.json()["verdict"]=="READY_TO_EXECUTE"
    replacement=raw_eval(task,ch,1,
        claims=[claim(step_ref(task,"PRE_EXECUTION",1))],action=action)
    assert replacement.status_code==409
    assert replacement.json()["detail"]["code"]=="UNRESOLVED_ACTION_GATE_NO_NEW_PRE"
    state=CLIENT.get(f"/v1/tasks/{task}/state",headers=HEAD).json()
    assert state["pending_execution_gate"]["pre_checkpoint_no"]==1
    post,_=do_post(task,ch,pre,action=action)
    assert post.status_code==200 and post.json()["step_verified"] is True
    assert CLIENT.get("/v1/audit/verify",headers=HEAD).json()["status"]=="PASS"


def test_failed_post_keeps_recovery_pending_until_same_gate_verified():
    task,ch=register(physical=True)
    action=e2_action(task,0)
    pre,_=do_pre(task,ch,0,action=action)
    assert suspend(task,ch,1,"pause").status_code==200
    resumed=suspend(task,ch,1,"resume")
    assert resumed.status_code==200 and resumed.json()["status"]=="RECOVERY_PENDING"
    bad,_=do_post(task,ch,pre,action=action,stdout="NO_MATCH")
    assert bad.status_code==200 and bad.json()["verdict"]=="UNVERIFIED"
    s=CLIENT.get(f"/v1/tasks/{task}/state",headers=HEAD).json()
    assert s["status"]=="RECOVERY_PENDING"
    assert s["pending_execution_gate"]["pre_checkpoint_no"]==1
    r=raw_eval(task,ch,bad.json()["checkpoint_no"],
      claims=[claim(step_ref(task,"PRE_EXECUTION",bad.json()["checkpoint_no"]))],
      action=action)
    assert r.status_code==409
    assert r.json()["detail"]["code"]=="RECOVERY_PENDING_NO_NEW_EXECUTION"
    good,_=do_post(task,ch,pre,action=action,req_cp=bad.json()["checkpoint_no"])
    assert good.status_code==200 and good.json()["step_verified"] is True
    s2=CLIENT.get(f"/v1/tasks/{task}/state",headers=HEAD).json()
    assert s2["status"]=="IN_PROGRESS"
    assert CLIENT.get("/v1/audit/verify",headers=HEAD).json()["status"]=="PASS"
