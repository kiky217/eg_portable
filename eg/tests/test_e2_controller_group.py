"""One unprivileged controller talks to a different-UID E2 worker after canonical PRE."""
import base64
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption,PublicFormat
import harness as H
from tools import trusted_execution_worker as W

pytestmark=pytest.mark.skipif(os.geteuid()!=0,reason='needs independent-UID CI operator')
WORKER=65533
CONTROLLER=65534


def _as(uid):
    def switch():
        os.setgroups([]);os.setgid(uid);os.setuid(uid)
    return switch


def test_real_unprivileged_agent_creates_file_through_eg_pre_and_signed_post(monkeypatch):
    base=Path(tempfile.mkdtemp(prefix='eg-e2-controller-',dir='/tmp'))
    base.chmod(0o755)
    child=None
    http=None
    try:
        root=base/'worker';root.mkdir(mode=0o700)
        output=root/'outputs';output.mkdir(mode=0o700)
        journal=root/'journal';journal.mkdir(mode=0o700)
        sockdir=base/'socket';sockdir.mkdir(mode=0o700)
        os.chown(root,WORKER,WORKER)
        for p in (output,journal):os.chown(p,WORKER,WORKER)
        os.chown(sockdir,WORKER,CONTROLLER);sockdir.chmod(0o2710)
        key=Ed25519PrivateKey.generate()
        pub=base64.b64encode(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
        keypath=root/'worker.pem';keypath.write_bytes(key.private_bytes(
            Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
        os.chown(keypath,WORKER,WORKER);keypath.chmod(0o600)
        class Proxy(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.headers.get('X-Evaluation-Key')!=H.API_KEY:
                    self.send_response(403);self.end_headers();return
                reply=H.CLIENT.get(self.path,headers=H.HEAD)
                self.send_response(reply.status_code)
                self.send_header('Content-Type','application/json')
                self.end_headers();self.wfile.write(reply.content)
            def log_message(self,*args):pass
        http=ThreadingHTTPServer(('127.0.0.1',0),Proxy)
        thread=threading.Thread(target=http.serve_forever,daemon=True);thread.start()
        url=f'http://127.0.0.1:{http.server_port}'
        config={'output_root':str(output),'journal_root':str(journal),
                'private_key':str(keypath),'eg_url':url,'eg_api_key':H.API_KEY,
                'executor_id':'trusted-worker-cross-uid-e2',
                'socket_path':str(sockdir/'worker.sock'),
                'controller_uid':CONTROLLER,'controller_group_gid':CONTROLLER}
        cfg=root/'config.json';cfg.write_text(json.dumps(config));os.chown(cfg,WORKER,WORKER);cfg.chmod(0o600)
        monkeypatch.setattr(H.gw,'EXECUTOR_OUTPUT_ROOT',str(output))
        monkeypatch.setattr(H.gw,'EXECUTOR_PUBLIC_KEY_B64',pub)
        monkeypatch.setattr(H.gw,'ADMISSION_MODE','enabled')
        source=Path(os.environ.get('EG_E2_TEST_SOURCE',str(H.ROOT)))
        cmd=[sys.executable,str(source/'tools/trusted_execution_worker.py'),str(cfg)]
        child=subprocess.Popen(cmd,cwd=source,env={**os.environ,'PYTHONPATH':str(source)},
                               preexec_fn=_as(WORKER),stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        for _ in range(80):
            if Path(config['socket_path']).is_socket():break
            assert child.poll() is None,child.stderr.read().decode()
            time.sleep(.04)
        assert Path(config['socket_path']).is_socket()
        task,contract=H.register(physical=True)
        content=b'E2_PRE_EXECUTED_AND_VERIFIED\n'
        target=output/'first.txt'
        action=H.e2_action(task,0,target=str(target),payload=content)
        pre,_=H.do_pre(task,contract,0,action=action)
        assert pre.json()['verdict']=='READY_TO_EXECUTE',pre.text
        packet={'task_id':task,'step_key':'01.01','action':action,
                'data_b64':base64.b64encode(content).decode()}
        script='''import base64,json,sys\nfrom tools.governed_agent_dispatcher import dispatch_action\nq=json.load(sys.stdin)\nr=dispatch_action(q,eg_url=sys.argv[1],api_key=sys.argv[2])\nprint(json.dumps(r))'''
        agent=subprocess.run([sys.executable,'-c',script,url,H.API_KEY],input=json.dumps(packet),text=True,
                   cwd=source,env={**os.environ,'PYTHONPATH':str(source),
                   'EVALUATION_GATEWAY_WORKER_SOCKET':config['socket_path'],
                   'EVALUATION_GATEWAY_EXECUTOR_PUBLIC_KEY_B64':pub},
                   preexec_fn=_as(CONTROLLER),capture_output=True,timeout=12)
        assert agent.returncode==0,agent.stderr
        result=json.loads(agent.stdout)
        assert result['status']=='RECEIPT_VERIFIED_POST_REQUIRED'
        assert target.read_bytes()==content
        assert target.stat().st_uid==WORKER
        post,_=H.do_post(task,contract,pre,action=action,
                         execution_receipt=result['execution_receipt'])
        assert post.json()['verdict']=='VERIFIED_PASS',post.text
        assert H.CLIENT.get('/v1/audit/verify',headers=H.HEAD).json()['status']=='PASS'
        with socket.socket(socket.AF_UNIX) as bad:
            bad.settimeout(2)
            bad.connect(config['socket_path']) # Root bypasses DAC but fails SO_PEERCRED.
            # The worker verifies peer UID before reading an RPC payload and may
            # close the socket immediately. Sending after that close races with
            # the denial response and can spuriously raise BrokenPipeError.
            denied=json.loads(bad.recv(8192))
        assert denied['status']=='DENIED'
        assert 'UNAUTHORIZED_CONTROLLER_UID' in denied['reason']
    finally:
        if child and child.poll() is None:
            child.terminate()
            try:child.wait(timeout=3)
            except subprocess.TimeoutExpired:child.kill();child.wait()
        if http:http.shutdown();http.server_close()
        shutil.rmtree(base,ignore_errors=True)
