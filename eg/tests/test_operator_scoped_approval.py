"""One non-AI signer grants bounded, operator-approved E3 actions to one agent."""
import base64
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption,PublicFormat
from tools.signed_hitl_approval import verify_approval
from tools.high_effect_admission import action_fingerprint
from tools.operator_scoped_approval import Grants,PolicyDenied,configure

AGENT=65534
SIGNER=65531


def _scope():
    content=b'{"message":"compile cafe"}'
    action={'action_type':'bounded_process_run','effect_class':'E3',
            'real_world_effect':True,'reversible':True,'target':'/tasks/staging/cafe/build',
            'payload_sha256':hashlib.sha256(content).hexdigest(),'payload_bytes':len(content)}
    return {'task_id':'cafe-123','step_key':'01.03','gate_checkpoint_no':4,'action':action}


def _config(tmp,uid):
    directory=tmp/'owner';directory.mkdir(mode=0o700)
    work=directory/'ledger';work.mkdir(mode=0o700)
    socket_dir=tmp/'sock';socket_dir.mkdir()
    if os.geteuid()==0:
        for p in (directory,work):os.chown(p,uid,uid)
        os.chown(socket_dir,uid,AGENT)
        socket_dir.chmod(0o2710)
    key=Ed25519PrivateKey.generate()
    secret=directory/'hitl.pem'
    secret.write_bytes(key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
    policy={'key_file':str(secret),'ledger_dir':str(work),'socket_path':str(socket_dir/'approve.sock'),
           'controller_uid':AGENT,'controller_group_gid':AGENT,'adapter_id':'trusted-adapter-cafe',
           'target_prefix':'/tasks/staging','expires_at':int(time.time())+180,
           'max_grants':1,'max_payload_bytes':8192}
    config=directory/'config.json';config.write_text(json.dumps(policy))
    for path in (secret,config):
        if os.geteuid()==0:os.chown(path,uid,uid)
        path.chmod(0o600)
    pub=base64.b64encode(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
    return config,policy,pub


def test_scoped_signatures_single_use_and_fail_closed(tmp_path,monkeypatch):
    owner=os.geteuid() or 1000
    cfg,policy,pub=_config(tmp_path,owner)
    if os.geteuid()==0:
        monkeypatch.setattr(os,'geteuid',lambda:owner)
    grants=Grants(configure(cfg))
    req=_scope()
    approval=grants.issue(req)
    assert grants.issue(req)==approval
    assert verify_approval(approval,pub,task_id=req['task_id'],step_key=req['step_key'],
        gate_checkpoint_no=req['gate_checkpoint_no'],
        action_fingerprint=action_fingerprint(req['action']),adapter_id=policy['adapter_id'])
    wrong={**req,'action':{**req['action'],'target':'/tasks/production/cafe'}}
    with pytest.raises(PolicyDenied,match='OUTSIDE_OPERATOR_POLICY'):
        grants.issue(wrong)
    with pytest.raises(PolicyDenied,match='QUOTA_EXHAUSTED'):
        grants.issue({**req,'step_key':'01.04'})
    with pytest.raises(PolicyDenied,match='OUTSIDE_OPERATOR_POLICY'):
        grants.issue({**req,'action':{**req['action'],'action_type':'arbitrary_shell'}})


@pytest.mark.skipif(os.geteuid()!=0,reason='independent OS UID test requires isolated root fixture')
def test_unprivileged_agent_cannot_read_signer_key_but_can_request_scoped_grant():
    tmp=Path(tempfile.mkdtemp(prefix='eg-scoped-operator-',dir='/tmp'))
    tmp.chmod(0o755)
    child=None
    try:
        cfg,policy,pub=_config(tmp,SIGNER)
        source=Path(os.environ.get('EG_TEST_SOURCE',Path(__file__).resolve().parents[1]))
        def user(uid):
            def fn():os.setgroups([]);os.setgid(uid);os.setuid(uid)
            return fn
        denied=subprocess.run([sys.executable,'-c',
                'from pathlib import Path;import sys;Path(sys.argv[1]).read_bytes()',policy['key_file']],
                preexec_fn=user(AGENT),capture_output=True,timeout=5)
        assert denied.returncode!=0 and b'PermissionError' in denied.stderr
        child=subprocess.Popen([sys.executable,'-m','tools.operator_scoped_approval',str(cfg)],
                cwd=source,env={**os.environ,'PYTHONPATH':str(source)},
                preexec_fn=user(SIGNER),stderr=subprocess.PIPE)
        for _ in range(100):
            if Path(policy['socket_path']).is_socket():break
            assert child.poll() is None,child.stderr.read()
            time.sleep(.04)
        assert Path(policy['socket_path']).is_socket()
        req=json.dumps(_scope())+'\n'
        script='''import json,sys
from tools.governed_agent_dispatcher import request_scoped_approval
print(json.dumps(request_scoped_approval(json.load(sys.stdin))))'''
        response=subprocess.run([sys.executable,'-c',script],
                input=req.encode(),preexec_fn=user(AGENT),capture_output=True,timeout=5,
                cwd=source,env={**os.environ,'PYTHONPATH':str(source),
                'EVALUATION_GATEWAY_STANDING_APPROVAL_SOCKET':policy['socket_path'],
                'EVALUATION_GATEWAY_HITL_PUBLIC_KEY_B64':pub})
        assert response.returncode==0,response.stderr
        proof=json.loads(response.stdout)
        assert verify_approval(proof,pub,task_id='cafe-123',step_key='01.03',
            gate_checkpoint_no=4,action_fingerprint=action_fingerprint(_scope()['action']),
            adapter_id=policy['adapter_id'])
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as peer:
            peer.settimeout(2)
            peer.connect(policy['socket_path'])
            # Peer-UID denial occurs before request parsing. Sending a payload
            # can race the server close and spuriously raise BrokenPipeError.
            response=json.loads(peer.recv(8192))
            assert response['status']=='DENIED' and 'UNAUTHORIZED_AGENT_IDENTITY' in response['reason']
        stale_inode=Path(policy['socket_path']).stat().st_ino
        child.kill();child.wait(timeout=3)  # Deliberately leave crashed Unix socket behind.
        child=subprocess.Popen([sys.executable,'-m','tools.operator_scoped_approval',str(cfg)],
                cwd=source,env={**os.environ,'PYTHONPATH':str(source)},
                preexec_fn=user(SIGNER),stderr=subprocess.PIPE)
        for _ in range(100):
            if (Path(policy['socket_path']).is_socket()
                and Path(policy['socket_path']).stat().st_ino!=stale_inode):break
            assert child.poll() is None,child.stderr.read()
            time.sleep(.04)
        restored=subprocess.run([sys.executable,'-c',script],input=req.encode(),
                preexec_fn=user(AGENT),capture_output=True,timeout=5,cwd=source,
                env={**os.environ,'PYTHONPATH':str(source),
                'EVALUATION_GATEWAY_STANDING_APPROVAL_SOCKET':policy['socket_path'],
                'EVALUATION_GATEWAY_HITL_PUBLIC_KEY_B64':pub})
        assert restored.returncode==0,restored.stderr
        assert json.loads(restored.stdout)==proof  # Same sealed nonce, no new grant.
    finally:
        if child and child.poll() is None:
            child.terminate()
            try:child.wait(timeout=3)
            except subprocess.TimeoutExpired:child.kill();child.wait()
        shutil.rmtree(tmp,ignore_errors=True)
