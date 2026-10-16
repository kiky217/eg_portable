"""PRE readiness is independently attested before a different POST condition."""
from harness import CLIENT,HEAD,gw,eid,step_ref,claim,raw_eval

def test_precondition_does_not_require_future_postcondition():
    task=eid("separate-criteria")
    body={"event_id":eid("reg"),"task_id":task,"protocol_hash":gw.protocol_hash(),
          "agent":"ChatGPT","original_instruction":"perform staged logical verification",
          "acceptance_criteria":["completion evidenced"],
          "steps":[{"step_key":"01","title":"Parent", "acceptance_criteria":["parent verification"],"execution_required":False},
                   {"step_key":"01.01","title":"Staged verification",
                    "preconditions":["baseline ready"],
                    "acceptance_criteria":["new output exists"],"execution_required":False}]}
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
                  phase="POST_EXECUTION",claims=[claim(ref2,0,"new output exists")])
    assert post.status_code==200,post.text
    assert post.json()["verdict"]=="VERIFIED_PASS"
    assert post.json()["step_verified"] is True
    assert post.json()["contract_status"]=="OPEN"
    assert CLIENT.get("/v1/audit/verify",headers=HEAD).json()["status"]=="PASS"

def test_postcondition_missing_cannot_verify_step():
    task=eid("missing-result")
    body={"event_id":eid("reg"),"task_id":task,"protocol_hash":gw.protocol_hash(),
          "agent":"ChatGPT","original_instruction":"verify only true postconditions",
          "acceptance_criteria":["completed"],
          "steps":[{"step_key":"01","title":"Parent","acceptance_criteria":["parent"],"execution_required":False},
                   {"step_key":"01.01","title":"Child","preconditions":["ready"],
                    "acceptance_criteria":["actual result"],"execution_required":False}]}
    reg=CLIENT.post("/v1/tasks/register",headers=HEAD,json=body)
    assert reg.status_code==200,reg.text
    ch=reg.json()["contract_hash"]
    ref=step_ref(task,"PRE_EXECUTION",0,step="01.01",criteria=[(0,"ready")])
    pre=raw_eval(task,ch,0,step="01.01",claims=[claim(ref,0,"ready")])
    assert pre.status_code==200 and pre.json()["verdict"]=="READY_TO_EXECUTE"
    # PRE witness cannot be recycled to claim an independent POST result.
    post=raw_eval(task,ch,pre.json()["checkpoint_no"],step="01.01",
                  phase="POST_EXECUTION",claims=[claim(ref,0,"actual result")])
    assert post.status_code==200,post.text
    assert post.json()["verdict"]=="UNVERIFIED"
    assert post.json()["step_verified"] is False
    assert CLIENT.get("/v1/audit/verify",headers=HEAD).json()["status"]=="PASS"

def test_invariant_is_mandatory_before_and_after_step():
    task=eid("pre-post-invariant")
    body={"event_id":eid("reg"),"task_id":task,"protocol_hash":gw.protocol_hash(),
          "agent":"ChatGPT","original_instruction":"verify bounded staged operation",
          "acceptance_criteria":["finished"],
          "steps":[{"step_key":"01","title":"Parent","execution_required":False,
                    "acceptance_criteria":["parent"]},
                   {"step_key":"01.01","title":"Child","execution_required":False,
                    "preconditions":["baseline ready"],
                    "invariants":["rollback remains available"],
                    "acceptance_criteria":["result exists"]}]}
    reg=CLIENT.post("/v1/tasks/register",headers=HEAD,json=body)
    assert reg.status_code==200,reg.text
    ch=reg.json()["contract_hash"]
    pre_ref=step_ref(task,"PRE_EXECUTION",0,step="01.01",
                     criteria=[(0,"baseline ready"),(1,"rollback remains available")])
    incomplete=raw_eval(task,ch,0,step="01.01",
             claims=[claim(pre_ref,0,"baseline ready")])
    assert incomplete.status_code==409
    pre=raw_eval(task,ch,0,step="01.01",
            claims=[claim(pre_ref,0,"baseline ready"),
                    claim(pre_ref,1,"rollback remains available")])
    assert pre.status_code==200 and pre.json()["verdict"]=="READY_TO_EXECUTE"
    gate=pre.json()["gate_checkpoint_no"]
    post_ref=step_ref(task,"POST_EXECUTION",gate,step="01.01",
                      criteria=[(0,"result exists"),(1,"rollback remains available")])
    incomplete_post=raw_eval(task,ch,pre.json()["checkpoint_no"],
                    step="01.01",phase="POST_EXECUTION",
                    claims=[claim(post_ref,0,"result exists")])
    assert incomplete_post.status_code==409
    post=raw_eval(task,ch,pre.json()["checkpoint_no"],step="01.01",
                  phase="POST_EXECUTION",claims=[
                      claim(post_ref,0,"result exists"),
                      claim(post_ref,1,"rollback remains available")])
    assert post.status_code==200 and post.json()["step_verified"] is True
    assert CLIENT.get("/v1/audit/verify",headers=HEAD).json()["status"]=="PASS"
