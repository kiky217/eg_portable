"""PRE readiness is independently attested before a different POST condition."""
from harness import CLIENT,HEAD,gw,eid,step_ref,claim,raw_eval

def test_precondition_does_not_require_future_postcondition():
    task=eid("separate-criteria")
    body={"event_id":eid("reg"),"task_id":task,"protocol_hash":gw.protocol_hash(),
          "agent":"ChatGPT","original_instruction":"perform staged logical verification",
          "acceptance_criteria":["completion evidenced"],
          "steps":[{"step_key":"01","title":"Parent", "acceptance_criteria":["parent verification"]},
                   {"step_key":"01.01","title":"Staged verification",
                    "preconditions":["baseline ready"],
                    "acceptance_criteria":["new output exists"]}]}
    reg=CLIENT.post("/v1/tasks/register",headers=HEAD,json=body)
    assert reg.status_code==200,reg.text
    ch=reg.json()["contract_hash"]
    ref=step_ref(task,"PRE_EXECUTION",0,step="01.01",
                 criteria=[(0,"baseline ready")])
    pre=raw_eval(task,ch,0,step="01.01",
                 claims=[claim(ref,0,"baseline ready")])
    assert pre.status_code==200,pre.text
    assert pre.json()["verdict"]=="READY_TO_EXECUTE"
    ref2=step_ref(task,"POST_EXECUTION",pre.json()["gate_checkpoint_no"],
                  step="01.01",criteria=[(0,"new output exists")])
    post=raw_eval(task,ch,pre.json()["checkpoint_no"],step="01.01",
                  claims=[claim(ref2,0,"new output exists")],
                  finalize=True,task_claims=[])
    assert post.status_code==409 or post.json().get("verdict")!="VERIFIED_PASS"
    assert CLIENT.get("/v1/audit/verify",headers=HEAD).json()["status"]=="PASS"
