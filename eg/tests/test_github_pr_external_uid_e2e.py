"""PR creation and merge: real local HTTP effect via UID-isolated generic EG RPC PRE/POST."""
import base64
import hashlib
import json
import os
import shutil
import tempfile
import threading
import time
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import harness as H
from harness import raw_eval, claim, step_ref
from test_high_effect_gateway_integration import (
    pub, signed, register_high_effect, high_pre_ref, high_pre_claim,
)
from test_github_pull_request_adapter import CREATE, MERGE, POL, LocalGitHub
from tools.no_redirect_http import urlopen
from tools.adapter_liveness import canon
from tools.operator_adapter_binding import canonical as signed_canonical
from tools.operator_runtime_registry import OperatorAdapterRegistry
from tools.high_effect_admission import AdapterCapability
from tools.trusted_generic_rpc import serve
from tools.github_pull_request_adapter import (
    GitHubPullRequestAdapter, perform_pr_effect, preflight_merge_scope, verify_pr_effect,
)
from tools.governed_agent_dispatcher import dispatch_action

pytestmark = pytest.mark.skipif(os.getuid()!=0, reason="distinct-UID CI only")


def test_independent_github_pr_create_and_merge_canonical_pre_post(monkeypatch):
    uid = 65532
    root = Path(tempfile.mkdtemp(prefix="eg-pr-", dir="/tmp"))
    root.chmod(0o755)
    sock_dir = root / "socket"; sock_dir.mkdir(mode=0o700)
    journal = root / "journal"; journal.mkdir(mode=0o700)
    for d in (sock_dir, journal):os.chown(d, uid, uid)
    sock = str(sock_dir / "worker.sock")
    operator, worker, human = (Ed25519PrivateKey.generate() for _ in range(3))
    adapter_id = "trusted-adapter-github-pr-e2e"
    cap = AdapterCapability(adapter_id=adapter_id, action_type="github_pull_request",
        effect_class="E4", target_prefix="/github/example/project/pulls/",
        maximum_payload_bytes=8192, isolated=True, public_key_b64=pub(worker), ci_only=False)
    capsha = hashlib.sha256(canon(asdict(cap))).hexdigest()

    LocalGitHub.state = {"writes": [], "reads": 0, "created": False, "merged": False, "merge_sha": ""}
    github = ThreadingHTTPServer(("127.0.0.1", 0), LocalGitHub)
    def opener(req, *, timeout):
        url = req.full_url.replace("https://api.github.com", f"http://127.0.0.1:{github.server_port}")
        return urlopen(Request(url, data=req.data, method=req.get_method(),
                               headers=dict(req.header_items())), timeout=timeout)
    class Proxy(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.headers.get("X-Evaluation-Key") != H.API_KEY:
                self.send_response(403);self.end_headers();return
            answer = H.CLIENT.get(self.path, headers=H.HEAD)
            self.send_response(answer.status_code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(answer.content)
        def log_message(self,*a):pass
    eg_server = ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
    eg_url = f"http://127.0.0.1:{eg_server.server_port}"
    pid = os.fork()
    if pid == 0:
        try:
            os.setgroups([]);os.setgid(uid);os.setuid(uid)
            effect = GitHubPullRequestAdapter(journal_dir=journal, private_key=worker,
                adapter_id=adapter_id, hitl_public_key_b64=pub(human), policy=POL,
                github_token="ephemeral-ci-only",
                write=lambda op,*,token:perform_pr_effect(op,token=token,opener=opener),
                readback=lambda op,ack,*,token,policy:verify_pr_effect(
                    op,ack,token=token,policy=policy,opener=opener),
                preflight=lambda op,policy,*,token:preflight_merge_scope(
                    op,policy,token=token,opener=opener))
            serve(socket_path=sock, adapter=effect, capability_sha256=capsha,
                  eg_url=eg_url, eg_key=H.API_KEY, hitl_public_key_b64=pub(human),
                  controller_uid=0, max_requests=11)
            os._exit(0)
        except BaseException:
            import traceback
            traceback.print_exc()
            os._exit(2)
    try:
        github_thread = threading.Thread(target=github.serve_forever, daemon=True)
        eg_thread = threading.Thread(target=eg_server.serve_forever, daemon=True)
        github_thread.start(); eg_thread.start()
        for _ in range(150):
            if Path(sock).is_socket():break
            time.sleep(.02)
        assert Path(sock).is_socket()
        regdir = root / "operator"; regdir.mkdir(mode=0o700)
        now = int(time.time())
        binding = {"version": 1, "adapter_id": adapter_id, "capability_sha256": capsha,
                   "worker_uid": uid, "socket_path": sock, "worker_public_key_b64": pub(worker),
                   "issued_at": now-1, "expires_at": now+120, "environment": "ci-local",
                   "operator_nonce": "operator-signed-pr-e2e-123456789"}
        binding["signature_b64"] = base64.b64encode(operator.sign(
            signed_canonical(binding))).decode()
        registry = OperatorAdapterRegistry(regdir,pub(operator))
        assert registry.activate(binding, adapter_id=adapter_id,
                                 capability_sha256=capsha)["status"] == "ACTIVE_CONFIG_ONLY"
        monkeypatch.setattr(H.gw,"HIGH_EFFECT_CI_FIXTURE_ENABLED",False)
        monkeypatch.setattr(H.gw,"EXTERNAL_ADAPTER_MODE","enabled")
        monkeypatch.setattr(H.gw,"EXTERNAL_ADAPTER_UID",-1)
        monkeypatch.setattr(H.gw,"EXTERNAL_ADAPTER_SOCKET","")
        monkeypatch.setattr(H.gw,"EXTERNAL_REGISTRY_DIR",str(regdir))
        monkeypatch.setattr(H.gw,"EXTERNAL_REGISTRY_KEY",pub(operator))
        monkeypatch.setattr(H.gw,"HIGH_EFFECT_CAPABILITIES_JSON",json.dumps([asdict(cap)]))
        monkeypatch.setattr(H.gw,"HITL_PUBLIC_KEY_B64",pub(human))
        monkeypatch.setenv("EVALUATION_GATEWAY_EXTERNAL_REGISTRY_DIR",str(regdir))
        monkeypatch.setenv("EVALUATION_GATEWAY_EXTERNAL_REGISTRY_OPERATOR_PUBLIC_KEY_B64",pub(operator))
        for operation in (CREATE,MERGE):
            payload=json.dumps({"version":1,"operation":operation},sort_keys=True,
                               separators=(",", ":"),ensure_ascii=False).encode()
            target=("/github/example/project/pulls/head/"+operation["head"]
                    if operation["operation"]=="create_pull_request"
                    else "/github/example/project/pulls/"+str(operation["number"]))
            action={"action_type":"github_pull_request","effect_class":"E4",
                    "target":target,"real_world_effect":True,"reversible":False,
                    "payload_sha256":hashlib.sha256(payload).hexdigest(),
                    "payload_bytes":len(payload),"proofs":[]}
            task,contract=register_high_effect()
            approval=signed(human,task,action,adapter_id,1,time.time())
            pre=raw_eval(task,contract,0,
                claims=[high_pre_claim(high_pre_ref(task,0))],
                phase="PRE_EXECUTION",action=action,hitl_approval=approval)
            assert pre.status_code==200 and pre.json()["verdict"]=="READY_TO_EXECUTE",pre.text
            result=dispatch_action(request={"task_id":task,"step_key":"01.01",
                 "action":action,"data_b64":base64.b64encode(payload).decode()},
                 eg_url=eg_url,api_key=H.API_KEY,executor_public_key_b64=pub(H.EXEC_PRIV),
                 hitl_public_key_b64=pub(human),
                 hitl_approval=approval)
            assert result["status"]=="RECEIPT_VERIFIED_POST_REQUIRED"
            post=raw_eval(task,contract,pre.json()["checkpoint_no"],step="01.01",
                 claims=[claim(step_ref(task,"POST_EXECUTION",pre.json()["gate_checkpoint_no"]))],
                 phase="POST_EXECUTION",action=action,
                 execution_receipt=result["execution_receipt"])
            assert post.status_code==200 and post.json()["verdict"]=="VERIFIED_PASS",post.text
            parent,_=H.do_pre(task,contract,post.json()["checkpoint_no"],step="01",
                  criteria=[(0,"parent criterion")],stdout="PARENT=PASS",value="PARENT=PASS")
            final,_=H.do_post(task,contract,parent,step="01",
                  criteria=[(0,"parent criterion")],finalize=True,
                  task_claims=[H.task_claim(H.task_ref(task,parent.json()["gate_checkpoint_no"],
                                 criterion="all steps evidenced"))],
                  stdout="PARENT=PASS",value="PARENT=PASS")
            assert final.status_code==200 and final.json()["contract_status"]=="SATISFIED",final.text
        assert LocalGitHub.state["writes"]==["create","merge"]
        monkeypatch.setattr(H.gw,"EXTERNAL_ADAPTER_MODE","disabled")
        audit=H.CLIENT.get("/v1/audit/verify",headers=H.HEAD)
        assert audit.status_code==200 and audit.json()["status"]=="PASS",audit.text
    finally:
        if pid:
            try:os.kill(pid,9)
            except ProcessLookupError:pass
            os.waitpid(pid,0)
        eg_server.shutdown();eg_server.server_close()
        github.shutdown();github.server_close()
        shutil.rmtree(root,ignore_errors=True)
