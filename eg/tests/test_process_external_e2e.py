"""Third consumer: real bounded process worker, separate UID, canonical EG E2E (CI only)."""
import base64
import hashlib
import os
import shutil
import tempfile
import threading
import time
import sys
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import harness as H
from harness import raw_eval,claim,step_ref
from test_high_effect_gateway_integration import (
    pub,signed,register_high_effect,high_pre_ref,high_pre_claim,
)
from tools.adapter_liveness import canon
from tools.operator_adapter_binding import canonical as signed_canonical
from tools.operator_runtime_registry import OperatorAdapterRegistry
from tools.high_effect_admission import AdapterCapability
from tools.trusted_generic_rpc import serve
from tools.trusted_process_effect import TrustedProcessEffect
from tools.typed_payload_contract import canonical as json_canonical
from tools.governed_agent_dispatcher import dispatch_action

pytestmark=pytest.mark.skipif(os.getuid()!=0,reason="distinct-UID CI only")


@pytest.mark.parametrize("example", ("echo", "cafe_build_test_http"))
def test_third_process_consumer_signed_registry_physical_post(monkeypatch,example):
    uid=65532
    base=Path(tempfile.mkdtemp(prefix="eg-process-",dir="/tmp"))
    base.chmod(0o755)
    socket_dir=base/"socket";socket_dir.mkdir(mode=0o700)
    journal=base/"journal";journal.mkdir(mode=0o700)
    project=base/"project";project.mkdir(mode=0o700)
    if example=="cafe_build_test_http":
        # Operator-owned pinned verifier: compile, validate a menu and serve an
        # actual loopback API; it is never an agent-controlled shell command.
        checker=project/"verify_app.py"
        checker.write_text('''import json,sys,threading,urllib.request
from http.server import BaseHTTPRequestHandler,HTTPServer
source='def menu(): return [{"name": "Espresso", "price": 19000}]'
namespace={}
exec(compile(source,'cafe_api.py','exec'),namespace)
expected=namespace['menu']()
assert expected[0]['price']==19000
class Api(BaseHTTPRequestHandler):
 def do_GET(self):
  data=json.dumps(expected).encode()
  self.send_response(200 if self.path=='/menu' else 404)
  self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
 def log_message(self,*args): pass
server=HTTPServer(('127.0.0.1',0),Api)
thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
try:
 with urllib.request.urlopen('http://127.0.0.1:%s/menu'%server.server_port,timeout=3) as response:
  assert response.status==200 and json.loads(response.read())==expected
finally:
 server.shutdown();server.server_close();thread.join(timeout=3)
sys.stdout.buffer.write(sys.stdin.buffer.read())
''')
        os.chown(checker,65532,65532)
    for folder in (socket_dir,journal,project):os.chown(folder,uid,uid)
    sock=str(socket_dir/"worker.sock")
    operator,worker,human=(Ed25519PrivateKey.generate() for _ in range(3))
    task,contract=register_high_effect()
    adapter="trusted-adapter-process-third"
    payload=b'{"message":"bounded-process"}'
    target="/tasks/process/third"
    input_schema={"schema_version":1,"schema_id":"generic/message-v1",
                  "required":["message"],"additional_properties":False,
                  "properties":{"message":{"type":"string","minimum":1,"maximum":80}}}
    schema_hash=hashlib.sha256(json_canonical(input_schema)).hexdigest()
    cap=AdapterCapability(adapter_id=adapter,action_type="bounded_process_run",
        effect_class="E3",target_prefix="/tasks/process/",maximum_payload_bytes=4096,
        isolated=True,public_key_b64=pub(worker),ci_only=False)
    capsha=hashlib.sha256(canon(asdict(cap))).hexdigest()
    action={"action_type":"bounded_process_run","effect_class":"E3","target":target,
            "real_world_effect":True,"reversible":True,
            "payload_sha256":hashlib.sha256(payload).hexdigest(),
            "payload_bytes":len(payload),"proofs":[]}

    class Proxy(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.headers.get("X-Evaluation-Key")!=H.API_KEY:
                self.send_response(403);self.end_headers();return
            result=H.CLIENT.get(self.path,headers=H.HEAD)
            self.send_response(result.status_code)
            self.send_header("Content-Type","application/json")
            self.end_headers()
            self.wfile.write(result.content)
        def log_message(self,*args):pass

    server=ThreadingHTTPServer(("127.0.0.1",0),Proxy)
    listener=threading.Thread(target=server.serve_forever,daemon=True)
    listener.start()
    url=f"http://127.0.0.1:{server.server_address[1]}"
    pid=os.fork()
    if pid==0:
        try:
            os.setgroups([])
            os.setgid(uid);os.setuid(uid)
            process=TrustedProcessEffect(journal_dir=journal,private_key=worker,
                adapter_id=adapter,hitl_key_b64=pub(human),
                executable=str(next(p for p in (Path("/usr/bin/python3.12"),Path("/usr/bin/python3.13")) if p.is_file())) if example=="cafe_build_test_http" else "/usr/bin/cat",
                fixed_args=(str(checker),) if example=="cafe_build_test_http" else (),
                target=target,timeout=5,max_stdout=4096,
                input_schema=input_schema,input_schema_sha256=schema_hash,
                output_schema=input_schema,output_schema_sha256=schema_hash)
            serve(socket_path=sock,adapter=process,capability_sha256=capsha,
                  eg_url=url,eg_key=H.API_KEY,hitl_public_key_b64=pub(human),
                  controller_uid=0,max_requests=3)
            os._exit(0)
        except BaseException:
            import traceback
            traceback.print_exc()
            os._exit(2)

    try:
        for _ in range(150):
            if Path(sock).is_socket():break
            time.sleep(.02)
        assert Path(sock).is_socket()
        reg_dir=base/"operator";reg_dir.mkdir(mode=0o700)
        now=int(time.time())
        binding={"version":1,"adapter_id":adapter,"capability_sha256":capsha,
                 "worker_uid":uid,"socket_path":sock,"worker_public_key_b64":pub(worker),
                 "issued_at":now-1,"expires_at":now+120,"environment":"ci",
                 "operator_nonce":"operator-signed-process-third"}
        binding["signature_b64"]=base64.b64encode(
            operator.sign(signed_canonical(binding))).decode()
        registry=OperatorAdapterRegistry(reg_dir,pub(operator))
        assert registry.activate(binding,adapter_id=adapter,
                                 capability_sha256=capsha)["status"]=="ACTIVE_CONFIG_ONLY"
        monkeypatch.setattr(H.gw,"HIGH_EFFECT_CI_FIXTURE_ENABLED",False)
        monkeypatch.setattr(H.gw,"EXTERNAL_ADAPTER_MODE","enabled")
        monkeypatch.setattr(H.gw,"EXTERNAL_ADAPTER_UID",-1)
        monkeypatch.setattr(H.gw,"EXTERNAL_ADAPTER_SOCKET","")
        monkeypatch.setattr(H.gw,"EXTERNAL_REGISTRY_DIR",str(reg_dir))
        monkeypatch.setattr(H.gw,"EXTERNAL_REGISTRY_KEY",pub(operator))
        monkeypatch.setattr(H.gw,"HIGH_EFFECT_CAPABILITIES_JSON",
                            __import__("json").dumps([asdict(cap)]))
        monkeypatch.setattr(H.gw,"HITL_PUBLIC_KEY_B64",pub(human))
        monkeypatch.setenv("EVALUATION_GATEWAY_EXTERNAL_REGISTRY_DIR",str(reg_dir))
        monkeypatch.setenv("EVALUATION_GATEWAY_EXTERNAL_REGISTRY_OPERATOR_PUBLIC_KEY_B64",
                           pub(operator))
        approval=signed(human,task,action,adapter,1,time.time())
        pre=raw_eval(task,contract,0,
                     claims=[high_pre_claim(high_pre_ref(task,0))],
                     phase="PRE_EXECUTION",action=action,hitl_approval=approval)
        assert pre.status_code==200 and pre.json()["verdict"]=="READY_TO_EXECUTE",pre.text
        result=dispatch_action(
            request={"task_id":task,"step_key":"01.01","action":action,
                     "data_b64":base64.b64encode(payload).decode()},
            eg_url=url,api_key=H.API_KEY,executor_public_key_b64=pub(H.EXEC_PRIV),
            external_adapter_id=adapter,hitl_public_key_b64=pub(human),
            hitl_approval=approval)
        assert result["status"]=="RECEIPT_VERIFIED_POST_REQUIRED"
        assert result["execution_receipt"]["output_sha256"]==hashlib.sha256(payload).hexdigest()
        post=raw_eval(task,contract,pre.json()["checkpoint_no"],step="01.01",
                 claims=[claim(step_ref(task,"POST_EXECUTION",pre.json()["gate_checkpoint_no"]))],
                 phase="POST_EXECUTION",action=action,
                 execution_receipt=result["execution_receipt"])
        assert post.status_code==200 and post.json()["verdict"]=="VERIFIED_PASS",post.text
        parent,_=H.do_pre(task,contract,post.json()["checkpoint_no"],step="01",
              criteria=[(0,"parent criterion")],stdout="PARENT=PASS",value="PARENT=PASS")
        task_evidence=H.task_ref(task,parent.json()["gate_checkpoint_no"],
                                 criterion="all steps evidenced")
        final,_=H.do_post(task,contract,parent,step="01",
                 criteria=[(0,"parent criterion")],finalize=True,
                 task_claims=[H.task_claim(task_evidence)],stdout="PARENT=PASS",value="PARENT=PASS")
        assert final.status_code==200 and final.json()["contract_status"]=="SATISFIED"
        _,status=os.waitpid(pid,0);pid=0
        assert os.waitstatus_to_exitcode(status)==0
        # CI harness runs its gateway as root. Production external admission
        # rejects that identity, so restore the harness mode for audit readback.
        monkeypatch.setattr(H.gw,"EXTERNAL_ADAPTER_MODE","disabled")
        audit=H.CLIENT.get("/v1/audit/verify",headers=H.HEAD)
        assert audit.status_code==200 and audit.json()["status"]=="PASS",audit.text
    finally:
        if pid:
            try:os.kill(pid,9)
            except ProcessLookupError:pass
            os.waitpid(pid,0)
        server.shutdown();server.server_close()
        shutil.rmtree(base,ignore_errors=True)
