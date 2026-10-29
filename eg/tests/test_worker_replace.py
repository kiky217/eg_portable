"""Bounded bounded_change edits: exact preimage, one physical effect, signed POST, no replay."""
import base64, hashlib
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption
import pytest
import harness as H
from harness import CLIENT,HEAD,register,do_pre,do_post
from tools import trusted_execution_worker as worker


def _action(task, target, old, new):
    base={"action_type":"replace","effect_class":"bounded_change","reversible":True,
          "real_world_effect":False,"target":str(target),
          "previous_sha256":hashlib.sha256(old).hexdigest(),
          "payload_sha256":hashlib.sha256(new).hexdigest(),"payload_bytes":len(new)}
    values={"sandbox_pass":"SANDBOX=PASS","rollback_ready":"ROLLBACK=READY","reversible":"REVERSIBLE=YES"}
    ref=H.notarized(H.eid("replace-proofs"),stdout="\n".join(values.values()),
        bindings=[H.pb(task,"01.01",purpose,base,0,marker) for purpose,marker in values.items()])
    return {**base,"proofs":[{"purpose":purpose,"evidence":H.evp(ref)} for purpose in values]}


def _worker(tmp_path,monkeypatch):
    output=tmp_path/"outputs";journal=tmp_path/"journal"
    output.mkdir(mode=0o700);journal.mkdir(mode=0o700)
    monkeypatch.setattr(H.gw,'EXECUTOR_OUTPUT_ROOT',str(output))
    key=tmp_path/"executor.pem"
    key.write_bytes(H.EXEC_PRIV.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()));key.chmod(0o600)
    def current(_url,_key,task):
        r=CLIENT.get('/v1/tasks/'+task+'/state',headers=HEAD)
        d=CLIENT.get('/v1/tasks/'+task,headers=HEAD)
        assert r.status_code==200 and d.status_code==200
        return r.json(),d.json()
    monkeypatch.setattr(worker,'api',current)
    return worker.TrustedWriter(output,journal,key,'http://127.0.0.1:18766','test-token','trusted-worker-replace-test'),output


def test_replace_verified_and_recovery_no_duplicate(tmp_path,monkeypatch):
    task,contract=register(physical=True)
    w,output=_worker(tmp_path,monkeypatch)
    original=b'<h1>Old menu</h1>\n';next_version=b'<h1>New menu</h1>\n'
    target=output/'index.txt';target.write_bytes(original)
    action=_action(task,target,original,next_version)
    pre,_=do_pre(task,contract,0,action=action)
    assert pre.json()['verdict']=='READY_TO_EXECUTE'
    payload={"task_id":task,"step_key":"01.01","action":action,"data_b64":base64.b64encode(next_version).decode()}
    receipt=w.execute(payload)
    assert target.read_bytes()==next_version
    old_stat=target.stat()
    assert w.execute(payload)==receipt  # Original sealed receipt; not second physical effect.
    assert target.stat().st_ino==old_stat.st_ino
    assert target.stat().st_mtime_ns==old_stat.st_mtime_ns
    failed,_=do_post(task,contract,pre,action=action,stdout='NO_VALID_EVIDENCE',
                     execution_receipt=receipt)
    assert failed.status_code==200 and failed.json()['verdict']=='UNVERIFIED',failed.text
    assert w.execute(payload)==receipt  # Failed POST cannot trigger second file edit.
    assert target.stat().st_ino==old_stat.st_ino
    post,_=do_post(task,contract,pre,action=action,
                   req_cp=failed.json()['checkpoint_no'],execution_receipt=receipt)
    assert post.status_code==200 and post.json()['verdict']=='VERIFIED_PASS',post.text
    assert CLIENT.get('/v1/audit/verify',headers=HEAD).json()['status']=='PASS'


def test_wrong_preimage_never_modifies_target(tmp_path,monkeypatch):
    task,contract=register(physical=True)
    w,output=_worker(tmp_path,monkeypatch)
    actual=b'one\n';expected_old=b'different\n';new=b'two\n'
    target=output/'menu.txt';target.write_bytes(actual)
    action=_action(task,target,expected_old,new)
    pre,_=do_pre(task,contract,0,action=action)
    assert pre.json()['verdict']=='READY_TO_EXECUTE'
    with pytest.raises(worker.WorkerDenied,match='REPLACE_PREIMAGE_MISMATCH'):
        w.execute({"task_id":task,"step_key":"01.01","action":action,"data_b64":base64.b64encode(new).decode()})
    assert target.read_bytes()==actual
    assert not list((tmp_path/'journal').iterdir())
