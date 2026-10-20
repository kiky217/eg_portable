"""Sandbox E3 canonical roundtrip: actual Cargo fmt, independent signed receipt, EG POST."""
import base64,hashlib,json,os,subprocess,sys,tempfile,time,threading
from pathlib import Path
from dataclasses import asdict
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat,PrivateFormat,NoEncryption
import harness as H
from harness import raw_eval,claim,step_ref
from tools.high_effect_admission import AdapterCapability,action_fingerprint
from tools.signed_hitl_approval import canonical
from tools.production_cargo_worker import CargoWorker
from tools.production_cargo_rpc import Server
from tools.production_cargo_dispatch import dispatch
from test_high_effect_gateway_integration import high_pre_ref,high_pre_claim,HIGH_PRE
from app import main as gw
def cargo_fixture(directory):
 root=directory/"rust-project"
 root.mkdir(mode=0o700)
 (root/"src").mkdir()
 (root/"Cargo.toml").write_text('[package]\nname = "eg-cargo-fixture"\nversion = "0.1.0"\nedition = "2021"\n')
 (root/"src"/"lib.rs").write_text("pub fn ping() -> bool {\n    true\n}\n")
 return root
def toolchain_env(build):
 home=Path.home()
 return {"CARGO_ADAPTER_RUSTUP_HOME":str(Path(os.getenv("RUSTUP_HOME",home/".rustup"))),
         "CARGO_ADAPTER_CARGO_HOME":str(Path(os.getenv("CARGO_HOME",home/".cargo"))),
         "CARGO_ADAPTER_TARGET_DIR":str(build)}
def pub(k):return base64.b64encode(k.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
def test_real_cargo_sandbox_pre_execute_post(monkeypatch):
 task="task-knid-solana-"+H.eid("production-cargo-e2e")
 registration={"event_id":H.eid("register"),"task_id":task,"protocol_hash":gw.protocol_hash(),
   "agent":"ChatGPT","original_instruction":"sandbox real cargo fmt under signed EG E3",
   "acceptance_criteria":["cargo result notarized"],
   "steps":[{"step_key":"01","title":"parent","acceptance_criteria":["parent criterion"],
             "required":True,"execution_required":False},
            {"step_key":"01.01","title":"cargo effect","preconditions":[HIGH_PRE],
             "acceptance_criteria":[H.CRIT],"required":True,"execution_required":True}]}
 registered=H.CLIENT.post("/v1/tasks/register",headers=H.HEAD,json=registration)
 assert registered.status_code==200,registered.text
 ch=registered.json()["contract_hash"];owner=Ed25519PrivateKey.generate();worker_key=Ed25519PrivateKey.generate()
 with tempfile.TemporaryDirectory() as tmp:
  directory=Path(tmp);ROOT=cargo_fixture(directory)
  journal=directory/"ledger";journal.mkdir(mode=0o700)
  build=directory/"build";build.mkdir(mode=0o700)
  key=directory/"worker.pem";sock=directory/"worker.sock";cfg=directory/"worker.json"
  key.write_bytes(worker_key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()));key.chmod(0o600)
  adapter="trusted-adapter-solana-cargo"
  cap=AdapterCapability(adapter_id=adapter,action_type="cargo_fmt_check",effect_class="E3",
    target_prefix=str(ROOT),maximum_payload_bytes=4096,isolated=True,
    public_key_b64=pub(worker_key),ci_only=False)
  capsha=hashlib.sha256(canonical(asdict(cap))).hexdigest()
  cfg.write_text(json.dumps({"adapter_id":adapter,"capability_sha256":capsha,"private_key":str(key),"socket":str(sock)}))
  child=subprocess.Popen([sys.executable,"-m","tools.cargo_liveness_daemon"],
             env={**os.environ,"CARGO_ADAPTER_CONFIG":str(cfg)},
             stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
  try:
   for _ in range(100):
    if sock.exists():break
    if child.poll() is not None:raise AssertionError(child.stderr.read().decode())
    time.sleep(.02)
   assert sock.exists()
   monkeypatch.setattr(gw,"HIGH_EFFECT_PRODUCTION_ENABLED",True)
   monkeypatch.setattr(gw,"HIGH_EFFECT_REQUIRE_RPC_LIVENESS",True)
   monkeypatch.setattr(gw,"HIGH_EFFECT_RPC_SOCKET",str(sock))
   monkeypatch.setattr(gw,"HIGH_EFFECT_RPC_WORKER_UID",os.getuid())
   monkeypatch.setattr(gw,"HIGH_EFFECT_CAPABILITIES_JSON",json.dumps([asdict(cap)]))
   monkeypatch.setattr(gw,"HITL_PUBLIC_KEY_B64",pub(owner))
   payload=canonical({"operation":"cargo_fmt_check","manifest":str(ROOT/"Cargo.toml")})
   action={"action_type":"cargo_fmt_check","target":str(ROOT/"Cargo.toml"),
           "effect_class":"E3","reversible":True,"real_world_effect":True,
           "payload_sha256":hashlib.sha256(payload).hexdigest(),"payload_bytes":len(payload),"proofs":[]}
   now=time.time()
   approval_body={"version":1,"task_id":task,"step_key":"01.01","gate_checkpoint_no":1,
                  "action_fingerprint":action_fingerprint(action),"adapter_id":adapter,
                  "decision":"APPROVED","issued_at":now-1,"expires_at":now+120,
                  "nonce":"sandbox-cargo-roundtrip-001"}
   approval={**approval_body,"signature_b64":base64.b64encode(owner.sign(canonical(approval_body))).decode()}
   pre=raw_eval(task,ch,0,step="01.01",claims=[high_pre_claim(high_pre_ref(task,0))],
                phase="PRE_EXECUTION",action=action,hitl_approval=approval)
   assert pre.status_code==200 and pre.json()["verdict"]=="READY_TO_EXECUTE",pre.text
   def get_task(t,suffix):
    response=H.CLIENT.get("/v1/tasks/"+t+suffix,headers=H.HEAD)
    assert response.status_code==200,response.text
    return response.json()
   worker=CargoWorker(root=ROOT,journal=journal,private=worker_key,adapter_id=adapter,
     hitl_public_key=pub(owner),fetch_state=lambda t:get_task(t,"/state"),
     fetch_detail=lambda t:get_task(t,""))
   effect_sock=directory/"effect.sock"
   config={"socket":str(effect_sock)}
   with patch("tools.production_cargo_rpc.configure",return_value=worker):
    with Server(config) as effect_server:
     effect_thread=threading.Thread(target=effect_server.serve_forever,daemon=True)
     effect_thread.start()
     try:
      ready=get_task(task,"/state")["pending_execution_gate"]
      with patch.dict(os.environ,toolchain_env(build)):
       result=dispatch(socket_path=str(effect_sock),task_id=task,step_key="01.01",
           action=action,approval=approval,ready_gate=ready,
           executor_public_key_b64=pub(worker_key),expected_worker_uid=os.getuid())
      assert result["status"]=="SIGNED_RECEIPT_VERIFIED_POST_REQUIRED"
      receipt=result["receipt"]
     finally:
      effect_server.shutdown()
      effect_thread.join(timeout=3)
   post_ref=step_ref(task,"POST_EXECUTION",pre.json()["gate_checkpoint_no"],step="01.01")
   post=raw_eval(task,ch,pre.json()["checkpoint_no"],step="01.01",
        claims=[claim(post_ref)],phase="POST_EXECUTION",action=action,execution_receipt=receipt)
   assert post.status_code==200 and post.json()["verdict"]=="VERIFIED_PASS",post.text
   parentpre,_=H.do_pre(task,ch,post.json()["checkpoint_no"],step="01",
                         criteria=[(0,"parent criterion")],stdout="PARENT=PASS",value="PARENT=PASS")
   taskref=H.task_ref(task,parentpre.json()["gate_checkpoint_no"],criterion="cargo result notarized")
   parentpost,_=H.do_post(task,ch,parentpre,step="01",
                         criteria=[(0,"parent criterion")],finalize=True,
                         task_claims=[H.task_claim(taskref,criterion="cargo result notarized")],
                         stdout="PARENT=PASS",value="PARENT=PASS")
   assert parentpost.status_code==200,parentpost.text
   assert parentpost.json()["contract_status"]=="SATISFIED",parentpost.text
   assert H.CLIENT.get("/v1/audit/verify",headers=H.HEAD).json()["status"]=="PASS"
  finally:child.terminate();child.wait(timeout=5)
