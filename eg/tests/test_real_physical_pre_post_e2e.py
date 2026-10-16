"""Real bounded worker E2E: distinct preconditions, effect once, receipt and POST."""
import base64
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from harness import CLIENT,HEAD,gw,eid,step_ref,claim,raw_eval,e2_action,EXEC_PRIV
from tools import trusted_execution_worker as worker


def test_physical_pre_execute_once_and_distinct_post(tmp_path,monkeypatch):
    task=eid("physical-e2e")
    output=tmp_path/"output";journal=tmp_path/"journal"
    output.mkdir(mode=0o700);journal.mkdir(mode=0o700)
    monkeypatch.setattr(gw,"EXECUTOR_OUTPUT_ROOT",str(output))
    target=output/"created.txt"
    body={"event_id":eid("register"),"task_id":task,
          "protocol_hash":gw.protocol_hash(),"agent":"ChatGPT",
          "original_instruction":"create bounded output under verified PRE",
          "acceptance_criteria":["all physical results verified"],
          "steps":[
              {"step_key":"01","title":"Finalize","execution_required":False,
               "acceptance_criteria":["parent done"]},
              {"step_key":"01.01","title":"Create file","execution_required":True,
               "preconditions":["target absent and executor ready"],
               "acceptance_criteria":["new target contains OK"]}]}
    reg=CLIENT.post("/v1/tasks/register",headers=HEAD,json=body)
    assert reg.status_code==200,reg.text
    ch=reg.json()["contract_hash"]
    payload=b"OK"
    action=e2_action(task,0,target=str(target),payload=payload)
    assert not target.exists()
    ref=step_ref(task,"PRE_EXECUTION",0,step="01.01",
                 criteria=[(0,"target absent and executor ready")],
                 stdout="TARGET=ABSENT",value="TARGET=ABSENT")
    pre=raw_eval(task,ch,0,step="01.01",
                 claims=[claim(ref,0,"target absent and executor ready")],action=action)
    assert pre.status_code==200,pre.text
    assert pre.json()["verdict"]=="READY_TO_EXECUTE"
    bad=raw_eval(task,ch,pre.json()["checkpoint_no"],step="01.01",
                 phase="POST_EXECUTION",action=None,
                 claims=[claim(ref,0,"new target contains OK")])
    assert bad.status_code==409
    assert bad.json()["detail"]["code"]=="IMMUTABLE_STEP_REQUIRES_ACTION"
    key=tmp_path/"worker.key"
    key.write_bytes(EXEC_PRIV.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
    key.chmod(0o600)
    def local_api(_url,_key,which):
        state=CLIENT.get("/v1/tasks/"+which+"/state",headers=HEAD)
        detail=CLIENT.get("/v1/tasks/"+which,headers=HEAD)
        assert state.status_code==200 and detail.status_code==200
        return state.json(),detail.json()
    monkeypatch.setattr(worker,"api",local_api)
    w=worker.TrustedWriter(output,journal,key,"http://127.0.0.1:18766",
                           "fixture-key","trusted-worker-physical-e2e")
    req={"task_id":task,"step_key":"01.01","action":action,
         "data_b64":base64.b64encode(payload).decode()}
    receipt=w.execute(req)
    original_inode=target.stat().st_ino
    assert w.execute(req)==receipt
    assert target.read_bytes()==payload
    ref2=step_ref(task,"POST_EXECUTION",pre.json()["gate_checkpoint_no"],
                  step="01.01",criteria=[(0,"new target contains OK")],
                  stdout="TARGET_CONTENT=OK",value="TARGET_CONTENT=OK")
    post=raw_eval(task,ch,pre.json()["checkpoint_no"],step="01.01",
                  phase="POST_EXECUTION",action=action,execution_receipt=receipt,
                  claims=[claim(ref2,0,"new target contains OK")])
    assert post.status_code==200,post.text
    assert post.json()["verdict"]=="VERIFIED_PASS"
    assert target.stat().st_ino==original_inode
    assert CLIENT.get("/v1/audit/verify",headers=HEAD).json()["status"]=="PASS"
