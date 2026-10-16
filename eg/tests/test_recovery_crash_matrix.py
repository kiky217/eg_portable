"""Crash matrix: recover executed effect without replay; unknown effect stays locked."""
import base64
import hashlib
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption
import pytest
import harness as H
from harness import CLIENT,HEAD,gw,eid,register,e2_action,do_pre,do_post,EXEC_PRIV
from tools import trusted_execution_worker as worker

def make_worker(tmp_path,monkeypatch,task):
    output=tmp_path/"outputs";journal=tmp_path/"journal"
    output.mkdir(mode=0o700);journal.mkdir(mode=0o700)
    monkeypatch.setattr(gw,"EXECUTOR_OUTPUT_ROOT",str(output))
    key=tmp_path/"worker.pem"
    key.write_bytes(EXEC_PRIV.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
    key.chmod(0o600)
    def local_api(_url,_key,which):
        a=CLIENT.get("/v1/tasks/"+which+"/state",headers=HEAD)
        b=CLIENT.get("/v1/tasks/"+which,headers=HEAD)
        assert a.status_code==200 and b.status_code==200
        return a.json(),b.json()
    monkeypatch.setattr(worker,"api",local_api)
    w=worker.TrustedWriter(output,journal,key,"http://127.0.0.1:18766",
                           "fixture-key","trusted-worker-crash-matrix")
    return w,output,journal

def resume(task,ch,cp):
    base={"contract_hash":ch,"protocol_hash":gw.protocol_hash(),
          "checkpoint_no":cp,"reason":"simulate interrupted execution"}
    a=CLIENT.post("/v1/tasks/"+task+"/pause",headers=HEAD,
                  json={"event_id":eid("pause"),**base})
    assert a.status_code==200,a.text
    b=CLIENT.post("/v1/tasks/"+task+"/resume",headers=HEAD,
                  json={"event_id":eid("resume"),**base})
    assert b.status_code==200 and b.json()["status"]=="RECOVERY_PENDING"

def test_crash_after_physical_write_uses_original_receipt_path(tmp_path,monkeypatch):
    task,ch=register()
    w,output,journal=make_worker(tmp_path,monkeypatch,task)
    target=output/"written.txt"
    payload=b"WRITTEN_AFTER_PRE"
    action=e2_action(task,0,target=str(target),payload=payload)
    pre,_=do_pre(task,ch,0,action=action)
    assert pre.json()["verdict"]=="READY_TO_EXECUTE"
    cp=pre.json()["checkpoint_no"]
    initial={"stage":"INTENT_DURABLE","task_id":task,"step_key":"01.01",
             "gate":cp,"target":str(target),
             "action_fingerprint":pre.json()["action_fingerprint"],
             "data_sha256":hashlib.sha256(payload).hexdigest()}
    worker.store_exclusive(journal/(task+"-01.01.json"),worker.canon(initial))
    worker.store_exclusive(target,payload)
    ino=target.stat().st_ino
    resume(task,ch,cp)
    with pytest.raises(worker.WorkerDenied,match="NO_EFFECT_UNPROVEN_OR_TARGET_PRESENT"):
        w.reconcile({"operation":"reconcile_no_effect","task_id":task,
                     "step_key":"01.01","action":action})
    request={"task_id":task,"step_key":"01.01","action":action,
             "data_b64":base64.b64encode(payload).decode()}
    receipt=w.execute(request)
    assert target.stat().st_ino==ino
    assert w.execute(request)==receipt
    post,_=do_post(task,ch,pre,action=action,execution_receipt=receipt)
    assert post.status_code==200 and post.json()["step_verified"] is True
    assert CLIENT.get("/v1/audit/verify",headers=HEAD).json()["status"]=="PASS"

def test_unknown_journal_remains_blocked_without_replay(tmp_path,monkeypatch):
    task,ch=register()
    w,output,journal=make_worker(tmp_path,monkeypatch,task)
    target=output/"unknown.txt"
    action=e2_action(task,0,target=str(target))
    pre,_=do_pre(task,ch,0,action=action)
    assert pre.json()["verdict"]=="READY_TO_EXECUTE"
    cp=pre.json()["checkpoint_no"]
    worker.store_exclusive(journal/(task+"-01.01.json"),b"{}")
    resume(task,ch,cp)
    with pytest.raises(worker.WorkerDenied,match="INTENT_NOT_SAFE_TO_RETIRE"):
        w.reconcile({"operation":"reconcile_no_effect","task_id":task,
                     "step_key":"01.01","action":action})
    assert not target.exists()
    state=CLIENT.get("/v1/tasks/"+task+"/state",headers=HEAD).json()
    assert state["status"]=="RECOVERY_PENDING"
    assert CLIENT.get("/v1/audit/verify",headers=HEAD).json()["status"]=="PASS"
