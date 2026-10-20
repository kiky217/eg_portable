import socket,tempfile,threading,json
from pathlib import Path
import pytest
from tools.production_cargo_dispatch import dispatch,DispatchDenied
def test_requires_canonical_pre():
 with pytest.raises(DispatchDenied,match="CANONICAL_PRE_REQUIRED"):
  dispatch(socket_path="/no/socket",task_id="x",step_key="02.01",action={},approval={},
           ready_gate={},executor_public_key_b64="bad")
def test_rejects_non_socket():
 from tools.high_effect_admission import action_fingerprint
 with tempfile.TemporaryDirectory() as directory:
  p=Path(directory)/"file";p.touch()
  action={"action_type":"cargo_test","target":"/sandbox/Cargo.toml"}
  ready={"verdict":"READY_TO_EXECUTE","task_id":"x","step_key":"02.01",
         "action_fingerprint":action_fingerprint(action),"checkpoint_no":1}
  with pytest.raises(DispatchDenied,match="INVALID_SOCKET"):
   dispatch(socket_path=str(p),task_id="x",step_key="02.01",action=action,approval={},
            ready_gate=ready,executor_public_key_b64="bad")
