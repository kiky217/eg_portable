"""Isolated Cargo execution RPC. All execution requests require canonical EG PRE and signed HITL.
Worker API credential is only readable by the OS-isolated worker process."""
import base64,json,os,socketserver,stat
from pathlib import Path
from urllib.request import Request,urlopen
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from tools.production_cargo_worker import CargoWorker,WorkerDenied
class RpcDenied(RuntimeError):pass
def configure(config):
 required={"socket","root","journal","adapter_id","signer_file","hitl_public_key","eg_endpoint","eg_api_key_file"}
 if set(config)!=required:raise RpcDenied("INVALID_CONFIG")
 url=config["eg_endpoint"]
 if url!="http://127.0.0.1:18765":raise RpcDenied("EG_ENDPOINT_NOT_PINNED")
 def private_file(name):
  p=Path(config[name])
  if p.is_symlink() or not p.is_file():raise RpcDenied("INVALID_PRIVATE_FILE")
  info=p.stat()
  if info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)&0o077:
   raise RpcDenied("PRIVATE_FILE_OWNER_OR_MODE")
  return p
 signer=load_pem_private_key(private_file("signer_file").read_bytes(),password=None)
 api_key=private_file("eg_api_key_file").read_text().strip()
 if len(api_key)<24:raise RpcDenied("INVALID_API_KEY")
 def fetch(task,suffix):
  if not isinstance(task,str) or not task.startswith("task-knid-solana-") or "/" in task:
   raise RpcDenied("TASK_SCOPE")
  req=Request(url+"/v1/tasks/"+task+suffix,headers={"X-Evaluation-Key":api_key})
  with urlopen(req,timeout=5) as response:return json.load(response)
 worker=CargoWorker(root=config["root"],journal=config["journal"],private=signer,
                    adapter_id=config["adapter_id"],hitl_public_key=config["hitl_public_key"],
                    fetch_state=lambda task:fetch(task,"/state"),
                    fetch_detail=lambda task:fetch(task,""))
 return worker
class Handler(socketserver.StreamRequestHandler):
 def handle(self):
  try:
   raw=self.rfile.readline(16385)
   if not raw or len(raw)>16384:raise RpcDenied("REQUEST_SIZE")
   data=json.loads(raw)
   if not isinstance(data,dict) or set(data)!={"task_id","step_key","action","approval"}:
    raise RpcDenied("REQUEST_SCHEMA")
   result=self.server.worker.execute(**data)
   self.wfile.write(json.dumps({"status":"EXECUTED_POST_REQUIRED","receipt":result}).encode()+b"\n")
  except (RpcDenied,WorkerDenied,ValueError,TypeError,KeyError):
   self.wfile.write(b'{"status":"DENIED"}\n')
class Server(socketserver.ThreadingUnixStreamServer):
 daemon_threads=True
 def __init__(self,config):
  self.worker=configure(config)
  sock=Path(config["socket"])
  if sock.exists() or sock.is_symlink():raise RpcDenied("SOCKET_PREEXISTS")
  if sock.parent.stat().st_uid!=os.geteuid() or stat.S_IMODE(sock.parent.stat().st_mode)&0o077:
   raise RpcDenied("SOCKET_PARENT_UNSAFE")
  super().__init__(str(sock),Handler)
  os.chmod(sock,0o600)
if __name__=="__main__":
 config_path=Path(os.environ["CARGO_EXECUTION_CONFIG"])
 if config_path.is_symlink() or stat.S_IMODE(config_path.stat().st_mode)&0o077:
  raise RpcDenied("CONFIG_PERMISSIONS")
 config=json.loads(config_path.read_text())
 with Server(config) as server:server.serve_forever()
