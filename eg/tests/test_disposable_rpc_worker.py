"""CI-only real UDS subprocess E3/E4/E5 EG-PRE -> effect -> receipt -> EG-POST."""
import base64
import hashlib
import json
import os
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import harness as H
from harness import gw,raw_eval,step_ref,claim
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption
from test_high_effect_gateway_integration import (
    pub,signed,register_high_effect,high_pre_ref,high_pre_claim,HIGH_PRE)
from tools.adapter_liveness import canon


@pytest.mark.parametrize("effect,atype",[("E3","sandbox_cutover"),
                                         ("E4","sandbox_critical_update"),
                                         ("E5","sandbox_irreversible_commit")])
def test_separate_process_worker_validates_live_eg_pre_and_signed_post(monkeypatch,tmp_path,effect,atype):
    root=tmp_path/"worker";root.mkdir(mode=0o700)
    effect_root=root/"effects";effect_root.mkdir(mode=0o700)
    journal=root/"journal";journal.mkdir(mode=0o700)
    key=Ed25519PrivateKey.generate()
    keyfile=root/"signer.pem"
    keyfile.write_bytes(key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
    keyfile.chmod(0o600)
    eg_keyfile=root/"eg-key"
    eg_keyfile.write_text(H.API_KEY);eg_keyfile.chmod(0o600)
    sock=root/"effect.sock"

    # A real HTTP transport forwards authenticated live reads to canonical EG.
    class ReadOnlyProxy(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.headers.get("X-Evaluation-Key")!=H.API_KEY:
                self.send_response(403);self.end_headers();return
            res=H.CLIENT.get(self.path,headers=H.HEAD)
            self.send_response(res.status_code)
            self.send_header("Content-Type","application/json")
            self.end_headers()
            self.wfile.write(res.content)
        def log_message(self,*args):pass
    server=ThreadingHTTPServer(("127.0.0.1",0),ReadOnlyProxy)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    task,ch=register_high_effect()
    human=Ed25519PrivateKey.generate()
    adapter_id="trusted-adapter-rpc-"+effect.lower()
    data=json.dumps({"effect":effect,"applied":True}).encode()
    target=effect_root/(effect+".json")
    action={"action_type":atype,"target":str(target),"effect_class":effect,
            "reversible":effect!="E5","real_world_effect":True,
            "payload_sha256":hashlib.sha256(data).hexdigest(),
            "payload_bytes":len(data),"proofs":[]}
    cap={"adapter_id":adapter_id,"action_type":atype,"effect_class":effect,
         "target_prefix":str(effect_root)+"/","maximum_payload_bytes":524288,
         "isolated":True,"public_key_b64":pub(key)}
    monkeypatch.setattr(gw,"HIGH_EFFECT_CI_FIXTURE_ENABLED",True)
    monkeypatch.setattr(gw,"HIGH_EFFECT_CAPABILITIES_JSON",json.dumps([cap]))
    monkeypatch.setattr(gw,"HITL_PUBLIC_KEY_B64",pub(human))
    ap=signed(human,task,action,adapter_id,1,time.time())
    monkeypatch.setattr(gw,"HIGH_EFFECT_REQUIRE_RPC_LIVENESS",True)
    monkeypatch.setattr(gw,"HIGH_EFFECT_RPC_SOCKET",str(sock))
    monkeypatch.setattr(gw,"HIGH_EFFECT_RPC_WORKER_UID",os.getuid())
    argv=[sys.executable,"-m","tools.disposable_rpc_worker",
          "--socket",str(sock),"--output-root",str(effect_root),
          "--ledger-root",str(journal),"--private-key",str(keyfile),
          "--eg-url",f"http://127.0.0.1:{server.server_address[1]}",
          "--eg-api-key-file",str(eg_keyfile),"--adapter-id",adapter_id,
          "--effect-class",effect,"--hitl-public-key-b64",pub(human),
          "--controller-uid",str(os.getuid()),"--max-requests","3"]
    env={**os.environ,"PYTHONPATH":str(Path(__file__).resolve().parents[1])}
    proc=subprocess.Popen(argv,env=env)
    try:
        for _ in range(100):
            if sock.exists() or proc.poll() is not None:break
            time.sleep(0.02)
        assert proc.poll() is None,"worker initialization failed"
        pre=raw_eval(task,ch,0,claims=[high_pre_claim(high_pre_ref(task,0))],
                     action=action,hitl_approval=ap)
        assert pre.status_code==200 and pre.json()["verdict"]=="READY_TO_EXECUTE",pre.text
        signed_live=pre.json()["high_effect_liveness"]
        from tools.adapter_liveness import verify as verify_liveness
        assert signed_live["status"]=="SIGNED_LIVENESS_ONLY_NOT_EXECUTION_ADMITTED"
        assert verify_liveness(signed_live["challenge"],signed_live["signed_response"],
               adapter_id=adapter_id,
               capability_sha256=signed_live["challenge"]["capability_sha256"],
               public_key_b64=pub(key))

        req={"task_id":task,"step_key":"01.01","action":action,"approval":ap,
             "data_b64":base64.b64encode(data).decode(),"operation":"execute"}
        def rpc(r):
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
                client.settimeout(10);client.connect(str(sock))
                client.sendall(canon(r)+b"\n")
                return json.loads(client.makefile("rb").readline(1048576))
        # Wrong scope cannot turn into an effect; subsequent correct invocation still works.
        wrong=rpc({**req,"action":{**action,"target":str(effect_root/"alien.json")}})
        assert wrong["status"]=="DENIED" and not target.exists()
        result=rpc(req)
        assert result["status"]=="PASS",result
        receipt=result["result"]["receipt"]
        assert target.read_bytes()==data
        assert proc.wait(timeout=10)==0
        inode=target.stat().st_ino
        # Restart same worker with same independent key and durable ledger.
        argv[-1]="1"  # max-requests: serve exactly one recovery RPC
        replay_worker=subprocess.Popen(argv,env=env)
        try:
            for _ in range(100):
                if sock.exists() or replay_worker.poll() is not None:break
                time.sleep(0.02)
            assert replay_worker.poll() is None,"restart failed"
            repeated=rpc(req)
            assert repeated["status"]=="PASS",repeated
            assert repeated["result"]["status"]=="RECOVERED_EXECUTED_POST_NOT_VERIFIED"
            assert repeated["result"]["receipt"]==receipt
            assert target.stat().st_ino==inode and target.read_bytes()==data
            assert replay_worker.wait(timeout=10)==0
        finally:
            if replay_worker.poll() is None:
                replay_worker.kill();replay_worker.wait(timeout=5)
        post=raw_eval(task,ch,pre.json()["checkpoint_no"],phase="POST_EXECUTION",
                      claims=[claim(step_ref(task,"POST_EXECUTION",1))],
                      action=action,execution_receipt=receipt)
        assert post.status_code==200 and post.json()["verdict"]=="VERIFIED_PASS",post.text
        ppre,_=H.do_pre(task,ch,post.json()["checkpoint_no"],step="01",
                        criteria=[(0,"parent criterion")],stdout="PARENT=PASS",value="PARENT=PASS")
        gref=H.task_ref(task,ppre.json()["gate_checkpoint_no"],criterion="all steps evidenced")
        final,_=H.do_post(task,ch,ppre,step="01",criteria=[(0,"parent criterion")],
                          finalize=True,task_claims=[H.task_claim(gref)],
                          stdout="PARENT=PASS",value="PARENT=PASS")
        assert final.status_code==200 and final.json()["contract_status"]=="SATISFIED",final.text
        assert H.CLIENT.get("/v1/audit/verify",headers=H.HEAD).json()["status"]=="PASS"
    finally:
        if proc.poll() is None:proc.kill();proc.wait(timeout=5)
        server.shutdown();server.server_close()


def test_worker_denies_wrong_signing_identity_before_effect(monkeypatch,tmp_path):
    """A PRE bound to a different key must not physically write a target."""
    from datetime import datetime,timezone
    from tools.disposable_rpc_worker import execute_once,RpcDenied
    from tools.high_effect_admission import action_fingerprint
    import tools.disposable_rpc_worker as rpc_module
    actual=Ed25519PrivateKey.generate()
    original=Ed25519PrivateKey.generate()
    fp_data=b'{"safe":true}'
    target=tmp_path/"never-created.json"
    action={"action_type":"sandbox_cutover","effect_class":"E3",
            "target":str(target),"payload_sha256":hashlib.sha256(fp_data).hexdigest(),
            "payload_bytes":len(fp_data),"reversible":True,"real_world_effect":True,
            "proofs":[]}
    fp=action_fingerprint(action)
    task="task-wrong-worker-key"
    adapter_id="trusted-adapter-rpc-e3"
    nonce="signed-original-approval"
    pin={"adapter_id":adapter_id,"public_key_b64":pub(original),
         "action_fingerprint":fp,"approval_nonce":nonce}
    now=datetime.now(timezone.utc).isoformat()
    state={"status":"IN_PROGRESS","current_step":"01.01",
           "pending_execution_gate":{"task_id":task,"step_key":"01.01",
                "verdict":"READY_TO_EXECUTE","hitl_approved":True,
                "action_fingerprint":fp,"checkpoint_no":1,
                "high_effect_pin":pin},
           "latest_checkpoint":{"checkpoint_no":1,"verdict":"READY_TO_EXECUTE"}}
    detail={"task":{"contract_status":"OPEN"},
            "checkpoints":[{"checkpoint_no":1,"created_at":now,
                            "verdict":"READY_TO_EXECUTE"}]}
    monkeypatch.setattr(rpc_module,"eg_get",
        lambda _url,_key,_task,suffix:state if suffix=="/state" else detail)
    class MustNotExecute:
        private=actual
        def execute(self,**kwargs):
            raise AssertionError("unsafe effect was called")
    MustNotExecute.adapter_id=adapter_id
    req={"task_id":task,"step_key":"01.01","action":action,
         "approval":{"nonce":nonce},
         "data_b64":base64.b64encode(fp_data).decode(),"operation":"execute"}
    with pytest.raises(RpcDenied,match="ORIGINAL_PRE_EXECUTOR_IDENTITY_MISMATCH"):
        execute_once(req,adapter=MustNotExecute(),eg_url="http://127.0.0.1:8765",
                     eg_key="test",hitl_key="test")
    assert not target.exists()

def test_high_effect_pre_requires_live_rpc_not_just_registry(monkeypatch,tmp_path):
    task,ch=register_high_effect()
    human=Ed25519PrivateKey.generate()
    key=Ed25519PrivateKey.generate()
    adapter_id="trusted-adapter-offline"
    payload=b'{"offline":true}'
    action={"action_type":"sandbox_cutover","effect_class":"E3",
            "target":str(tmp_path/"offline.json"),"reversible":True,
            "real_world_effect":True,"payload_sha256":hashlib.sha256(payload).hexdigest(),
            "payload_bytes":len(payload),"proofs":[]}
    cap={"adapter_id":adapter_id,"action_type":"sandbox_cutover","effect_class":"E3",
         "target_prefix":str(tmp_path)+"/","maximum_payload_bytes":524288,
         "isolated":True,"public_key_b64":pub(key)}
    monkeypatch.setattr(gw,"HIGH_EFFECT_CI_FIXTURE_ENABLED",True)
    monkeypatch.setattr(gw,"HIGH_EFFECT_CAPABILITIES_JSON",json.dumps([cap]))
    monkeypatch.setattr(gw,"HITL_PUBLIC_KEY_B64",pub(human))
    monkeypatch.setattr(gw,"HIGH_EFFECT_REQUIRE_RPC_LIVENESS",True)
    monkeypatch.setattr(gw,"HIGH_EFFECT_RPC_SOCKET",str(tmp_path/"offline.sock"))
    monkeypatch.setattr(gw,"HIGH_EFFECT_RPC_WORKER_UID",os.getuid())
    approval=signed(human,task,action,adapter_id,1,time.time())
    r=raw_eval(task,ch,0,claims=[high_pre_claim(high_pre_ref(task,0))],
               action=action,hitl_approval=approval)
    assert r.status_code==200 and r.json()["verdict"]=="REQUIRES_HITL",r.text
    assert "HIGH_EFFECT_LIVE_EXECUTOR_UNAVAILABLE" in r.json()["reason"]
    assert r.json()["high_effect_liveness"] is None
    assert not (tmp_path/"offline.json").exists()
