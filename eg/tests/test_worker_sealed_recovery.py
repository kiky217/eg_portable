"""Issue #15: recover signed sealed journal after a failed POST without replay."""
import base64
from pathlib import Path
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
import pytest
import harness as H
from harness import CLIENT, HEAD, register, do_pre, do_post, e2_action
from tools import trusted_execution_worker as worker


def test_sealed_receipt_survives_failed_post_and_retries_without_new_effect(tmp_path,monkeypatch):
    task,contract=register()
    output=tmp_path/'outputs'
    journal=tmp_path/'journal'
    output.mkdir(mode=0o700)
    journal.mkdir(mode=0o700)
    target=output/'result.txt'
    action=e2_action(task,0,target=str(target))
    key=tmp_path/'worker.key'
    key.write_bytes(H.EXEC_PRIV.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
    key.chmod(0o600)
    def local_api(_url,_key,which):
        assert which==task
        a=CLIENT.get(f'/v1/tasks/{which}/state',headers=HEAD)
        b=CLIENT.get(f'/v1/tasks/{which}',headers=HEAD)
        assert a.status_code==200 and b.status_code==200,(a.text,b.text)
        return a.json(),b.json()
    monkeypatch.setattr(worker,'api',local_api)
    w=worker.TrustedWriter(output,journal,key,'http://127.0.0.1:18766','fixture-key','trusted-worker-replay-test')
    pre,_=do_pre(task,contract,0,action=action)
    assert pre.json()['verdict']=='READY_TO_EXECUTE'
    payload=b'AFTER_PRE_ONLY'
    request={'task_id':task,'step_key':'01.01','action':action,
             'data_b64':base64.b64encode(payload).decode()}
    receipt=w.execute(request)
    original_inode=target.stat().st_ino
    original_mtime=target.stat().st_mtime_ns
    assert w.execute(request)==receipt
    failed,_=do_post(task,contract,pre,action=action,stdout='WRONG_EVIDENCE',
                     execution_receipt=receipt)
    assert failed.status_code==200 and failed.json()['verdict']=='UNVERIFIED'
    again=w.execute(request)
    assert again==receipt
    assert target.read_bytes()==payload
    assert target.stat().st_ino==original_inode
    assert target.stat().st_mtime_ns==original_mtime
    with pytest.raises(worker.WorkerDenied,match='INTENT_REPLAY_OR_MISMATCH'):
        w.execute({**request,'data_b64':base64.b64encode(b'UNAPPROVED').decode()})
    final,_=do_post(task,contract,pre,action=action,req_cp=failed.json()['checkpoint_no'],
                    execution_receipt=again)
    assert final.status_code==200 and final.json()['step_verified']
    assert CLIENT.get('/v1/audit/verify',headers=HEAD).json()['status']=='PASS'
