"""Reconciliation is audited and never replays a physical effect."""
from harness import CLIENT, HEAD, gw, eid, register, e2_action, do_pre, EXEC_PRIV, CRIT
from app.no_effect_receipts import sign_no_effect

def test_signed_no_effect_closes_gate_without_advancing_step():
    task,ch=register()
    action=e2_action(task,0)
    pre,_=do_pre(task,ch,0,action=action)
    assert pre.json()["verdict"]=="READY_TO_EXECUTE"
    cp=pre.json()["checkpoint_no"]
    base={"contract_hash":ch,"protocol_hash":gw.protocol_hash(),"checkpoint_no":cp,
          "reason":"controlled pause before worker RPC"}
    pause=CLIENT.post("/v1/tasks/"+task+"/pause",headers=HEAD,json={"event_id":eid("pause"),**base})
    assert pause.status_code==200,pause.text
    resume=CLIENT.post("/v1/tasks/"+task+"/resume",headers=HEAD,json={"event_id":eid("resume"),**base})
    assert resume.status_code==200,resume.text
    assert resume.json()["status"]=="RECOVERY_PENDING"
    proof=sign_no_effect(EXEC_PRIV,task_id=task,step_key="01.01",
                         gate_checkpoint_no=cp,action_fingerprint=pre.json()["action_fingerprint"],
                         target=action["target"],executor_id="trusted-worker-test-fixture")
    req={"event_id":eid("reconcile"),"contract_hash":ch,
         "protocol_hash":gw.protocol_hash(),"checkpoint_no":cp,
         "step_key":"01.01","action":action,"proof":proof}
    bad=dict(req,event_id=eid("bad-proof"),proof=dict(proof,signature_b64="invalid"))
    invalid=CLIENT.post("/v1/tasks/"+task+"/reconcile",headers=HEAD,json=bad)
    assert invalid.status_code==409
    result=CLIENT.post("/v1/tasks/"+task+"/reconcile",headers=HEAD,json=req)
    assert result.status_code==200,result.text
    assert result.json()["reconciled_effect"]=="NOT_EXECUTED"
    assert result.json()["checkpoint_no"]==cp
    again=CLIENT.post("/v1/tasks/"+task+"/reconcile",headers=HEAD,json=req)
    assert again.status_code==200 and again.json()["idempotent_replay"] is True
    assert CLIENT.get("/v1/audit/verify",headers=HEAD).json()["status"]=="PASS"
    # A fresh PRE remains subject to a new payload/proof and all admission gates.
    next_action=e2_action(task,cp)
    fresh,_=do_pre(task,ch,cp,action=next_action)
    assert fresh.json()["verdict"]=="READY_TO_EXECUTE"
    assert CLIENT.get("/v1/audit/verify",headers=HEAD).json()["status"]=="PASS"
