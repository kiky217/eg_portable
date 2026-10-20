"""CI-only separate-UID E3 transport roundtrip. Does NOT certify production worker."""
import base64
import hashlib
import json
import os
import shutil
import socket
import tempfile
import threading
import time
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import harness as H
from harness import raw_eval, claim, step_ref
from test_high_effect_gateway_integration import pub, signed, register_high_effect, high_pre_ref, high_pre_claim
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tools.adapter_liveness import canon, attest
from tools.high_effect_admission import AdapterCapability
from tools.disposable_effect_adapter import DisposableAdapter
from tools.governed_agent_dispatcher import dispatch_action
import tools.disposable_rpc_worker as rpc

pytestmark = pytest.mark.skipif(os.getuid()!=0, reason="Privileged isolated cross-UID CI only")


@pytest.mark.parametrize("operation", ["execute", "no_effect"])
@pytest.mark.parametrize("effect,atype,worker_uid", [
    ("E3","sandbox_cutover",65534),
    ("E4","sandbox_critical_update",65533),
])
def test_distinct_uid_external_rpc_pre_receipt_post(monkeypatch,operation,effect,atype,worker_uid):
    shared=Path(tempfile.mkdtemp(prefix="eg-uid-",dir="/tmp"))
    shared.chmod(0o755)
    root=shared/"effects";root.mkdir(mode=0o700)
    journal=shared/"journal";journal.mkdir(mode=0o700)
    os.chown(root,worker_uid,worker_uid);os.chown(journal,worker_uid,worker_uid)
    workerkey=Ed25519PrivateKey.generate();human=Ed25519PrivateKey.generate()
    task,ch=register_high_effect()
    adapter_id=f"trusted-adapter-external-uid-{effect.lower()}-test"
    payload=b'{"scanner":"pass"}'
    target=root/"project.json"
    action={"action_type":atype,"target":str(target),"effect_class":effect,
            "reversible":True,"real_world_effect":True,"payload_sha256":hashlib.sha256(payload).hexdigest(),
            "payload_bytes":len(payload),"proofs":[]}
    cap=AdapterCapability(adapter_id=adapter_id,action_type=atype,effect_class=effect,
            target_prefix=str(root)+"/",maximum_payload_bytes=524288,isolated=True,
            public_key_b64=pub(workerkey),ci_only=False)
    sockpath=str(root/"worker.sock")
    class Proxy(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.headers.get("X-Evaluation-Key") != H.API_KEY:
                self.send_response(403);self.end_headers();return
            result=H.CLIENT.get(self.path,headers=H.HEAD)
            self.send_response(result.status_code)
            self.send_header("Content-Type","application/json");self.end_headers()
            self.wfile.write(result.content)
        def log_message(self,*args):pass
    http=ThreadingHTTPServer(("127.0.0.1",0),Proxy)
    thread=threading.Thread(target=http.serve_forever,daemon=True);thread.start()
    url=f"http://127.0.0.1:{http.server_address[1]}"
    capsha=hashlib.sha256(canon(asdict(cap))).hexdigest()
    pid=os.fork()
    if pid==0:
        try:
            os.setgroups([])
            os.setgid(worker_uid);os.setuid(worker_uid)
            adapter=DisposableAdapter(root,journal,workerkey,adapter_id,effect)
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
                listener.bind(sockpath);listener.listen(5)
                for _ in range(2):
                    with listener.accept()[0] as peer:
                        with peer.makefile("rb") as inp:
                            request=json.loads(inp.readline())
                        if request.get("operation") == "attest":
                            response=attest(request["challenge"],adapter_id=adapter_id,
                                capability_sha256=capsha,private_key=workerkey)
                        else:
                            result=rpc.execute_once(request,adapter=adapter,eg_url=url,
                                eg_key=H.API_KEY,hitl_key=pub(human))
                            response={"status":"PASS","result":result}
                        peer.sendall(canon(response)+b"\n")
            os._exit(0)
        except BaseException:
            import traceback
            traceback.print_exc()
            os._exit(2)
    try:
        for _ in range(150):
            if Path(sockpath).exists():break
            time.sleep(.02)
        assert Path(sockpath).exists()
        monkeypatch.setattr(H.gw,"HIGH_EFFECT_CI_FIXTURE_ENABLED",False)
        monkeypatch.setattr(H.gw,"EXTERNAL_ADAPTER_MODE","enabled")
        monkeypatch.setattr(H.gw,"EXTERNAL_ADAPTER_UID",worker_uid)
        monkeypatch.setattr(H.gw,"EXTERNAL_ADAPTER_SOCKET",sockpath)
        monkeypatch.setattr(H.gw,"HIGH_EFFECT_CAPABILITIES_JSON",json.dumps([asdict(cap)]))
        monkeypatch.setattr(H.gw,"HITL_PUBLIC_KEY_B64",pub(human))
        monkeypatch.setattr(H.gw,"ADMISSION_MODE","enabled")
        approval=signed(human,task,action,adapter_id,1,time.time())
        pre=raw_eval(task,ch,0,claims=[high_pre_claim(high_pre_ref(task,0))],
                    phase="PRE_EXECUTION",action=action,hitl_approval=approval)
        assert pre.status_code==200 and pre.json()["verdict"]=="READY_TO_EXECUTE",pre.text
        result=dispatch_action(
            request={"task_id":task,"step_key":"01.01","action":action,
                     "data_b64":base64.b64encode(payload).decode() if operation=="execute" else ""},
            eg_url=url,api_key=H.API_KEY,executor_public_key_b64=pub(H.EXEC_PRIV),
            external_worker_socket=sockpath,external_worker_uid=worker_uid,
            external_adapter_id=adapter_id,external_public_key_b64=pub(workerkey),
            hitl_public_key_b64=pub(human),hitl_approval=approval,operation=operation)
        if operation=="no_effect":
            assert result["status"]=="SIGNED_NO_EFFECT_RECONCILIATION_REQUIRED"
            assert result["no_effect_proof"]["status"]=="NOT_EXECUTED"
            assert not target.exists()
        else:
            assert result["status"]=="RECEIPT_VERIFIED_POST_REQUIRED"
            assert target.read_bytes()==payload
            post=raw_eval(task,ch,pre.json()["checkpoint_no"],step="01.01",
                claims=[claim(step_ref(task,"POST_EXECUTION",pre.json()["gate_checkpoint_no"]))],
                phase="POST_EXECUTION",action=action,execution_receipt=result["execution_receipt"])
            assert post.status_code==200 and post.json()["verdict"]=="VERIFIED_PASS",post.text
            parent_pre,_=H.do_pre(task,ch,post.json()["checkpoint_no"],step="01",
                criteria=[(0,"parent criterion")],stdout="PARENT=PASS",value="PARENT=PASS")
            global_ref=H.task_ref(task,parent_pre.json()["gate_checkpoint_no"],criterion="all steps evidenced")
            final,_=H.do_post(task,ch,parent_pre,step="01",criteria=[(0,"parent criterion")],
                finalize=True,task_claims=[H.task_claim(global_ref)],stdout="PARENT=PASS",value="PARENT=PASS")
            assert final.status_code==200 and final.json()["contract_status"]=="SATISFIED",final.text
        _,code=os.waitpid(pid,0);pid=0
        assert os.waitstatus_to_exitcode(code)==0
        monkeypatch.setattr(H.gw,"EXTERNAL_ADAPTER_MODE","disabled")
        assert H.CLIENT.get("/v1/audit/verify",headers=H.HEAD).json()["status"]=="PASS"
    finally:
        if pid:
            try:os.kill(pid,9)
            except ProcessLookupError:pass
            os.waitpid(pid,0)
        http.shutdown();http.server_close()
        shutil.rmtree(shared,ignore_errors=True)
