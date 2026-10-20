import json,os,socket,tempfile,threading
from pathlib import Path
from unittest.mock import patch
import pytest
from tools.production_cargo_rpc import Server,RpcDenied
def config(tmp):
 root=tmp/"source";root.mkdir()
 journal=tmp/"ledger";journal.mkdir(mode=0o700)
 signer=tmp/"signer";signer.write_text("TEST_ONLY");signer.chmod(0o600)
 token=tmp/"key";token.write_text("not-a-real-secret");token.chmod(0o600)
 return dict(socket=str(tmp/"effect.sock"),root=str(root),journal=str(journal),
             adapter_id="trusted-adapter-cargo",signer_file=str(signer),
             hitl_public_key="TEST_KEY",eg_endpoint="http://127.0.0.1:18765",
             eg_api_key_file=str(token))
def test_invalid_config_refuses_socket(tmp_path):
 cfg=config(tmp_path);cfg["eg_endpoint"]="https://untrusted.example"
 with pytest.raises(RpcDenied,match="EG_ENDPOINT_NOT_PINNED"):Server(cfg)
 assert not Path(cfg["socket"]).exists()
def test_rpc_denies_unknown_request_and_no_execute(tmp_path):
 cfg=config(tmp_path)
 class Mock:
  def execute(self,**kw):raise AssertionError("NEVER_EXECUTE")
 with patch("tools.production_cargo_rpc.configure",return_value=Mock()):
  with Server(cfg) as server:
   thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
   try:
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
     client.settimeout(3);client.connect(cfg["socket"])
     client.sendall(b'{"operation":"shell"}\n')
     output=client.recv(4096)
     assert json.loads(output)["status"]=="DENIED"
   finally:server.shutdown();thread.join(timeout=3)
def test_preexisting_socket_refused(tmp_path):
 cfg=config(tmp_path);Path(cfg["socket"]).touch()
 with patch("tools.production_cargo_rpc.configure",return_value=object()):
  with pytest.raises(RpcDenied,match="SOCKET_PREEXISTS"):Server(cfg)
