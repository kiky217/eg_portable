"""Sandbox canonical PRE integration for opt-in production gate with real signed RPC liveness."""
import base64,hashlib,json,os,subprocess,sys,tempfile,time
from pathlib import Path
from dataclasses import asdict
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat,PrivateFormat,NoEncryption
import harness as H
from harness import raw_eval,claim
from tools.high_effect_admission import AdapterCapability,action_fingerprint
from tools.signed_hitl_approval import canonical
from test_high_effect_gateway_integration import register_high_effect,high_pre_ref,high_pre_claim
from tools.high_effect_admission import action_fingerprint
from tools.adapter_liveness import ProbeDenied
from app import main as gw
def pub(k):return base64.b64encode(k.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
def test_ready_pre_requires_real_signed_liveness_and_scoped_hitl(monkeypatch):
 task,ch=register_high_effect()
 owner=Ed25519PrivateKey.generate();worker=Ed25519PrivateKey.generate()
 with tempfile.TemporaryDirectory() as tmp:
  p=Path(tmp);key=p/"worker.pem";cfg=p/"cfg.json";sock=p/"worker.sock"
  key.write_bytes(worker.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()));key.chmod(0o600)
  cap=AdapterCapability(adapter_id="trusted-adapter-real-cargo",action_type="cargo_test",effect_class="E3",
    target_prefix="/content/workspace/knid-solana",maximum_payload_bytes=4096,isolated=True,
    public_key_b64=pub(worker),ci_only=False)
  capsha=hashlib.sha256(canonical(asdict(cap))).hexdigest()
  cfg.write_text(json.dumps({"adapter_id":cap.adapter_id,"capability_sha256":capsha,"private_key":str(key),"socket":str(sock)}))
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
   action={"action_type":"cargo_test","target":"/content/workspace/knid-solana/Cargo.toml",
           "effect_class":"E3","reversible":True,"real_world_effect":True,
           "payload_sha256":"0"*64,"payload_bytes":10,"proofs":[]}
   now=time.time();gate_cp=1
   approval_body={"version":1,"task_id":task,"step_key":"01.01","gate_checkpoint_no":gate_cp,
                  "action_fingerprint":action_fingerprint(action),"adapter_id":cap.adapter_id,
                  "decision":"APPROVED","issued_at":now-1,"expires_at":now+120,
                  "nonce":"sandbox-live-pre-approval-00001"}
   approval={**approval_body,"signature_b64":base64.b64encode(owner.sign(canonical(approval_body))).decode()}
   ref=high_pre_ref(task,0)
   response=raw_eval(task,ch,0,step="01.01",claims=[high_pre_claim(ref)],
                     phase="PRE_EXECUTION",action=action,hitl_approval=approval)
   assert response.status_code==200,response.text
   body=response.json()
   assert body["verdict"]=="READY_TO_EXECUTE",body
   assert body["high_effect_liveness"]["status"]=="SIGNED_LIVENESS_ONLY_NOT_EXECUTION_ADMITTED"
  finally:
   child.terminate();child.wait(timeout=5)
