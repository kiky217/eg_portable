import base64,hashlib,json,os,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat,PrivateFormat,NoEncryption
from tools.adapter_liveness import probe_unix,ProbeDenied
from tools.high_effect_admission import AdapterCapability
class SignedSeparateProcessTests(unittest.TestCase):
 def test_real_unix_socket_signed_challenge(self):
  with tempfile.TemporaryDirectory() as home:
   base=Path(home);cfg=base/"worker.json";keyfile=base/"key.pem";socket=base/"adapter.sock"
   k=Ed25519PrivateKey.generate()
   keyfile.write_bytes(k.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()));keyfile.chmod(0o600)
   pub=base64.b64encode(k.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
   cap=AdapterCapability(adapter_id="trusted-adapter-solana-cargo",
      action_type="cargo_test",effect_class="E3",target_prefix="/content/workspace/knid-solana",
      maximum_payload_bytes=4096,isolated=True,public_key_b64=pub,ci_only=False)
   from dataclasses import asdict
   cap_sha=hashlib.sha256(json.dumps(asdict(cap),sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
   cfg.write_text(json.dumps({"adapter_id":cap.adapter_id,"capability_sha256":cap_sha,
            "private_key":str(keyfile),"socket":str(socket)}))
   env={**os.environ,"CARGO_ADAPTER_CONFIG":str(cfg)}
   child=subprocess.Popen([sys.executable,"-m","tools.cargo_liveness_daemon"],
                          env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
   try:
    for _ in range(100):
     if socket.exists():break
     if child.poll() is not None:raise AssertionError(child.stderr.read().decode())
     time.sleep(0.02)
    assert socket.exists()
    scope=dict(adapter_id=cap.adapter_id,capability_sha256=cap_sha,public_key_b64=pub,
      task_id="task-knid-solana-sandbox",step_key="02.01",gate_checkpoint_no=11,
      action_fingerprint="a"*64,expected_worker_uid=os.getuid())
    result=probe_unix(str(socket),**scope)
    self.assertEqual(result["status"],"SIGNED_LIVENESS_ONLY_NOT_EXECUTION_ADMITTED")
    with self.assertRaises(ProbeDenied):
     probe_unix(str(socket),**{**scope,"capability_sha256":"0"*64})
   finally:
    child.terminate()
    child.wait(timeout=5)
if __name__=="__main__":unittest.main()
