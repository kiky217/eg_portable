import socket,tempfile,threading,json
from pathlib import Path
import pytest
from tools.production_cargo_dispatch import dispatch,DispatchDenied
def test_requires_canonical_pre():
 with pytest.raises(DispatchDenied,match="CANONICAL_PRE_REQUIRED"):
  dispatch(socket_path="/no/socket",task_id="x",step_key="02.01",action={},approval={},
           ready_gate={},executor_public_key_b64="bad",expected_worker_uid=1)
def test_rejects_non_socket():
 from tools.high_effect_admission import action_fingerprint
 with tempfile.TemporaryDirectory() as directory:
  p=Path(directory)/"file";p.touch()
  action={"action_type":"cargo_test","target":"/sandbox/Cargo.toml"}
  ready={"verdict":"READY_TO_EXECUTE","task_id":"x","step_key":"02.01",
         "action_fingerprint":action_fingerprint(action),"checkpoint_no":1}
  with pytest.raises(DispatchDenied,match="INVALID_SOCKET"):
   dispatch(socket_path=str(p),task_id="x",step_key="02.01",action=action,approval={},
            ready_gate=ready,executor_public_key_b64="bad",expected_worker_uid=1)
import json,os,socket,tempfile,threading
from pathlib import Path
from tools.high_effect_admission import action_fingerprint
def test_unix_worker_peer_uid_mismatch_denied(tmp_path):
 path=tmp_path/"effect.sock"
 ready={"verdict":"READY_TO_EXECUTE","task_id":"task-knid-solana-test","step_key":"02.01",
        "action_fingerprint":action_fingerprint({"action_type":"cargo_test","target":"/tmp/Cargo.toml"}),
        "checkpoint_no":1}
 with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
  server.bind(str(path));server.listen(1)
  def serve():
   connection,_=server.accept()
   with connection: connection.settimeout(1)
  thread=threading.Thread(target=serve,daemon=True);thread.start()
  try:
   with pytest.raises(DispatchDenied,match="WORKER_PEER_IDENTITY_MISMATCH"):
    dispatch(socket_path=str(path),task_id="task-knid-solana-test",step_key="02.01",
             action={"action_type":"cargo_test","target":"/tmp/Cargo.toml"},
             approval={},ready_gate=ready,executor_public_key_b64="invalid",
             expected_worker_uid=os.getuid()+1)
  finally:thread.join(timeout=2)
