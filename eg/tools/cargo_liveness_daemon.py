#!/usr/bin/env python3
"""Independent private UNIX-socket liveness worker; no effects are accepted here."""
import json,os,socketserver
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from tools.adapter_liveness import attest,ProbeDenied
class Handler(socketserver.StreamRequestHandler):
 def handle(self):
  try:
   raw=self.rfile.readline(8192)
   if not raw or len(raw)>=8192:raise ValueError("REQUEST_TOO_LARGE")
   req=json.loads(raw)
   if not isinstance(req,dict) or set(req)!={"operation","challenge"} or req["operation"]!="attest":
    raise ValueError("ONLY_SIGNED_LIVENESS_SUPPORTED")
   msg=attest(req["challenge"],adapter_id=self.server.adapter_id,capability_sha256=self.server.cap_hash,private_key=self.server.key)
   self.wfile.write(json.dumps(msg,separators=(",",":")).encode()+b"\n")
  except (ValueError,TypeError,ProbeDenied,json.JSONDecodeError):
   self.wfile.write(b'{"error":"DENIED"}\n')
class UnixServer(socketserver.ThreadingUnixStreamServer):
 daemon_threads=True
 def __init__(self,config):
  self.adapter_id=config["adapter_id"];self.cap_hash=config["capability_sha256"]
  self.key=load_pem_private_key(Path(config["private_key"]).read_bytes(),password=None)
  socket_file=Path(config["socket"])
  socket_file.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
  if socket_file.exists():raise RuntimeError("EXISTING_SOCKET_NO_UNLINK")
  super().__init__(str(socket_file),Handler)
  os.chmod(socket_file,0o600)
if __name__=="__main__":
 cfg=json.loads(Path(os.environ["CARGO_ADAPTER_CONFIG"]).read_text())
 server=UnixServer(cfg)
 try:server.serve_forever(poll_interval=0.1)
 finally:server.server_close()
