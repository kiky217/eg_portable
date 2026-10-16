"""Execution-required steps cannot be converted to logical checks after intake."""
from harness import CLIENT, HEAD, gw, eid, raw_eval, step_ref, claim

def test_immutable_action_required_rejects_null_before_checkpoint():
    task=eid("physical-step")
    body={
        "event_id":eid("reg"),"task_id":task,"protocol_hash":gw.protocol_hash(),
        "agent":"ChatGPT","original_instruction":"create an output via admitted executor",
        "acceptance_criteria":["output was created by executor"],
        "steps":[
            {"step_key":"01","title":"Verify physical work",
             "acceptance_criteria":["output is created"],"execution_required":True}
        ],
    }
    registered=CLIENT.post("/v1/tasks/register",headers=HEAD,json=body)
    assert registered.status_code==200,registered.text
    contract=registered.json()["contract_hash"]
    ref=step_ref(task,"PRE_EXECUTION",0,step="01",criteria=[(0,"output is created")])
    for phase in ("PRE_EXECUTION","POST_EXECUTION"):
        response=raw_eval(task,contract,0,step="01",phase=phase,
                          claims=[claim(ref,0,"output is created")],action=None)
        assert response.status_code==409,response.text
        assert response.json()["detail"]["code"]=="IMMUTABLE_STEP_REQUIRES_ACTION"
    state=CLIENT.get("/v1/tasks/"+task+"/state",headers=HEAD).json()
    assert state["latest_checkpoint"] is None
    assert CLIENT.get("/v1/audit/verify",headers=HEAD).json()["status"]=="PASS"
