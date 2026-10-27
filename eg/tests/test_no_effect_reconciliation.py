"""Reconciliation is audited and never replays a physical effect."""
from harness import CLIENT, HEAD, gw, eid, register, e2_action, do_pre, EXEC_PRIV
from app.no_effect_receipts import sign_no_effect

def test_signed_no_effect_closes_gate_without_advancing_step():
    task,ch=register(physical=True)
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
         "step_key":"01.01","action":action,"proof":proof,
         "executor_public_key_b64":gw.EXECUTOR_PUBLIC_KEY_B64}
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

def test_actual_worker_attests_no_effect_and_gateway_reauthorizes(tmp_path,monkeypatch):
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
    import harness as H
    from tools import trusted_execution_worker as worker
    task,ch=register(physical=True)
    output=tmp_path/"outputs";journal=tmp_path/"journal"
    output.mkdir(mode=0o700);journal.mkdir(mode=0o700)
    monkeypatch.setattr(gw,"EXECUTOR_OUTPUT_ROOT",str(output))
    action=e2_action(task,0,target=str(output/"result.txt"),payload=b"APPROVED")
    key=tmp_path/"worker.key"
    key.write_bytes(EXEC_PRIV.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
    key.chmod(0o600)
    def local_api(_url,_key,which):
        state=CLIENT.get("/v1/tasks/"+which+"/state",headers=HEAD)
        detail=CLIENT.get("/v1/tasks/"+which,headers=HEAD)
        assert state.status_code==200 and detail.status_code==200
        return state.json(),detail.json()
    monkeypatch.setattr(worker,"api",local_api)
    w=worker.TrustedWriter(output,journal,key,"http://127.0.0.1:18766","fixture-key",
                           "trusted-worker-e2e-recovery")
    pre,_=do_pre(task,ch,0,action=action)
    assert pre.json()["verdict"]=="READY_TO_EXECUTE"
    cp=pre.json()["checkpoint_no"]
    base={"contract_hash":ch,"protocol_hash":gw.protocol_hash(),"checkpoint_no":cp,
          "reason":"no worker RPC was issued"}
    assert CLIENT.post("/v1/tasks/"+task+"/pause",headers=HEAD,
                       json={"event_id":eid("pause"),**base}).status_code==200
    assert CLIENT.post("/v1/tasks/"+task+"/resume",headers=HEAD,
                       json={"event_id":eid("resume"),**base}).json()["status"]=="RECOVERY_PENDING"
    proof=w.reconcile({"operation":"reconcile_no_effect","task_id":task,
                       "step_key":"01.01","action":action})
    response=CLIENT.post("/v1/tasks/"+task+"/reconcile",headers=HEAD,
           json={"event_id":eid("reconcile"),"contract_hash":ch,
                 "protocol_hash":gw.protocol_hash(),"checkpoint_no":cp,
                 "step_key":"01.01","action":action,"proof":proof,
                 "executor_public_key_b64":gw.EXECUTOR_PUBLIC_KEY_B64})
    assert response.status_code==200,response.text
    assert not (output/"result.txt").exists()
    assert CLIENT.get("/v1/audit/verify",headers=HEAD).json()["status"]=="PASS"
    fresh=e2_action(task,cp,target=str(output/"result.txt"),payload=b"APPROVED")
    next_pre,_=do_pre(task,ch,cp,action=fresh)
    assert next_pre.json()["verdict"]=="READY_TO_EXECUTE"

def test_durable_intent_before_create_is_reconciled_without_write(tmp_path,monkeypatch):
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
    import json
    from tools import trusted_execution_worker as worker
    task,ch=register(physical=True)
    output=tmp_path/"outputs";journal=tmp_path/"journal"
    output.mkdir(mode=0o700);journal.mkdir(mode=0o700)
    monkeypatch.setattr(gw,"EXECUTOR_OUTPUT_ROOT",str(output))
    payload=b"CANONICAL"
    target=output/"new.txt"
    action=e2_action(task,0,target=str(target),payload=payload)
    key=tmp_path/"key.pem"
    key.write_bytes(EXEC_PRIV.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
    key.chmod(0o600)
    def local_api(_url,_key,which):
        state=CLIENT.get("/v1/tasks/"+which+"/state",headers=HEAD)
        detail=CLIENT.get("/v1/tasks/"+which,headers=HEAD)
        assert state.status_code==200 and detail.status_code==200
        return state.json(),detail.json()
    monkeypatch.setattr(worker,"api",local_api)
    w=worker.TrustedWriter(output,journal,key,"http://127.0.0.1:18766","fixture-key",
                           "trusted-worker-durable-recovery")
    pre,_=do_pre(task,ch,0,action=action)
    cp=pre.json()["checkpoint_no"]
    durable=journal/(task+"-01.01.json")
    import hashlib
    raw={"stage":"INTENT_DURABLE","task_id":task,"step_key":"01.01",
         "gate":cp,"target":str(target),
         "action_fingerprint":pre.json()["action_fingerprint"],
         "data_sha256":hashlib.sha256(payload).hexdigest()}
    worker.store_exclusive(durable,worker.canon(raw))
    base={"contract_hash":ch,"protocol_hash":gw.protocol_hash(),"checkpoint_no":cp,
          "reason":"worker crash after durable intent and before exclusive output"}
    assert CLIENT.post("/v1/tasks/"+task+"/pause",headers=HEAD,
                       json={"event_id":eid("pause"),**base}).status_code==200
    assert CLIENT.post("/v1/tasks/"+task+"/resume",headers=HEAD,
                       json={"event_id":eid("resume"),**base}).json()["status"]=="RECOVERY_PENDING"
    request={"operation":"reconcile_no_effect","task_id":task,"step_key":"01.01",
             "action":action}
    proof=w.reconcile(request)
    assert not target.exists() and not durable.exists()
    retired=journal/(task+"-01.01-"+str(cp)+".no-effect.json")
    assert retired.is_file() and json.loads(retired.read_text())==raw
    assert w.reconcile(request)["status"]=="NOT_EXECUTED"
    result=CLIENT.post("/v1/tasks/"+task+"/reconcile",headers=HEAD,
           json={"event_id":eid("reconcile"),"contract_hash":ch,
                 "protocol_hash":gw.protocol_hash(),"checkpoint_no":cp,
                 "step_key":"01.01","action":action,"proof":proof,
                 "executor_public_key_b64":gw.EXECUTOR_PUBLIC_KEY_B64})
    assert result.status_code==200,result.text
    assert CLIENT.get("/v1/audit/verify",headers=HEAD).json()["status"]=="PASS"
    new_action=e2_action(task,cp,target=str(target),payload=payload)
    pre2,_=do_pre(task,ch,cp,action=new_action)
    assert pre2.json()["verdict"]=="READY_TO_EXECUTE"
