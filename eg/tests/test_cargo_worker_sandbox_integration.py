import base64,hashlib,json,os,tempfile,time,unittest
from datetime import datetime,timezone
from pathlib import Path
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from app.execution_receipts import verify
from tools.high_effect_admission import action_fingerprint
from tools.production_cargo_worker import CargoWorker,WorkerDenied
from tools.signed_hitl_approval import canonical
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
class CargoWorkerSandboxIntegration(unittest.TestCase):
 def test_authorized_sandbox_fmt_and_replay_without_repeat(self):
  with tempfile.TemporaryDirectory() as temp:
   ROOT=cargo_fixture(Path(temp))
   journal=Path(temp)/"journal";journal.mkdir(mode=0o700)
   output=Path(temp)/"target";output.mkdir(mode=0o700)
   now=time.time();created=datetime.now(timezone.utc).isoformat()
   task="task-knid-solana-sandbox";step="02.01";adapter="trusted-adapter-solana-cargo"
   data=canonical({"operation":"cargo_fmt_check","manifest":str(ROOT/"Cargo.toml")})
   action={"action_type":"cargo_fmt_check","effect_class":"E3","real_world_effect":True,
           "target":str(ROOT/"Cargo.toml"),"payload_sha256":hashlib.sha256(data).hexdigest(),
           "payload_bytes":len(data)}
   fp=action_fingerprint(action)
   gate={"verdict":"READY_TO_EXECUTE","pre_checkpoint_no":21,"action_fingerprint":fp,
         "hitl_approved":True,"created_at":created}
   owner=Ed25519PrivateKey.generate();worker_key=Ed25519PrivateKey.generate()
   signed_body={"version":1,"task_id":task,"step_key":step,"gate_checkpoint_no":21,
                "action_fingerprint":fp,"adapter_id":adapter,"decision":"APPROVED",
                "issued_at":now-1,"expires_at":now+100,"nonce":"sandbox-valid-approval-00001"}
   approval={**signed_body,"signature_b64":base64.b64encode(owner.sign(canonical(signed_body))).decode()}
   worker=CargoWorker(root=ROOT,journal=journal,private=worker_key,
                      adapter_id=adapter,hitl_public_key=pub(owner),
                      fetch_state=lambda t:{"current_step":step,"pending_execution_gate":gate},
                      fetch_detail=lambda t:{"task":{"contract_status":"OPEN"}})
   with patch.dict(os.environ,toolchain_env(output)):
    receipt=worker.execute(task_id=task,step_key=step,action=action,approval=approval)
    again=worker.execute(task_id=task,step_key=step,action=action,approval=approval)
   valid,reason=verify(receipt,public_b64=pub(worker_key),task_id=task,step_key=step,
                       gate_checkpoint_no=21,action_fingerprint=fp,
                       target=str(ROOT/"Cargo.toml"),gate_created_at=created)
   self.assertTrue(valid,reason)
   self.assertEqual(again,receipt)
   self.assertEqual(len(list(journal.glob("*.receipt.json"))),1)
   saved_file=next(journal.glob("*.receipt.json"))
   tampered=json.loads(saved_file.read_text());tampered["output_sha256"]="0"*64
   saved_file.write_text(json.dumps(tampered))
   with patch.dict(os.environ,toolchain_env(output)):
    with self.assertRaisesRegex(WorkerDenied,"REPLAY_RECEIPT_SIGNATURE_INVALID"):
     worker.execute(task_id=task,step_key=step,action=action,approval=approval)
if __name__=="__main__":unittest.main()
