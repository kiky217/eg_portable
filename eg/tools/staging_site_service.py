"""Operator-owned persistent loopback staging site; execution remains EG-gated.

Only the separately provisioned E3 worker UID may call this service.
EG's original PRE, independent approval, signed receipt and POST live outside it.
"""
import base64
import hashlib
import json
import os
import socket
import socketserver
import stat
import struct
import threading
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from tools.operator_process_service import _private_file


class SiteDenied(ValueError): pass


def canon(value):
    return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


class Site:
    def __init__(self, config):
        self.lock=threading.Lock()
        folder=Path(config['state_dir'])
        if (folder.is_symlink() or not folder.is_dir() or
            folder.stat().st_uid!=os.geteuid() or stat.S_IMODE(folder.stat().st_mode)&0o077):
            raise SiteDenied('PRIVATE_SITE_STATE_REQUIRED')
        self.statefile=folder/'active.json'
        if self.statefile.exists():
            self.state=json.loads(self.statefile.read_bytes())
            for field in ('current','previous'):
                if not isinstance(self.state[field],str):raise SiteDenied('CORRUPT_SITE_STATE')
                self._decode(self.state[field])
        else:
            self.state={'current':'','previous':''}

    @staticmethod
    def _decode(value):
        content=base64.b64decode(value,validate=True)
        if len(content)>524288:raise SiteDenied('SITE_PAYLOAD_TOO_LARGE')
        return content

    def apply(self, doc):
        if not isinstance(doc,dict) or set(doc)!={'operation','content_b64','content_sha256'}:
            raise SiteDenied('INVALID_SITE_OPERATION')
        if doc['operation'] not in ('deploy','rollback'):
            raise SiteDenied('UNSUPPORTED_SITE_OPERATION')
        if doc['operation']=='deploy':
            raw=self._decode(doc['content_b64'])
            if not raw or not (raw.lstrip().startswith(b'<!doctype html>') or
                               raw.lstrip().startswith(b'<html')):
                raise SiteDenied('INVALID_SITE_DOCUMENT')
            if hashlib.sha256(raw).hexdigest()!=doc['content_sha256']:
                raise SiteDenied('SITE_DIGEST_MISMATCH')
        with self.lock:
            if doc['operation']=='deploy':
                if self.state['current']==doc['content_b64']:
                    raise SiteDenied('SITE_VERSION_ALREADY_ACTIVE')
                updated={'current':doc['content_b64'],'previous':self.state['current']}
            else:
                if doc['content_b64']!='' or not self.state['previous']:
                    raise SiteDenied('NO_PRIOR_SITE_VERSION')
                prior=self._decode(self.state['previous'])
                if hashlib.sha256(prior).hexdigest()!=doc['content_sha256']:
                    raise SiteDenied('ROLLBACK_DIGEST_MISMATCH')
                updated={'current':self.state['previous'],'previous':self.state['current']}
            temporary=self.statefile.with_suffix('.new')
            fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            try:
                with os.fdopen(fd,'wb') as file:
                    file.write(canon(updated));file.flush();os.fsync(file.fileno())
                os.replace(temporary,self.statefile)
                dirfd=os.open(self.statefile.parent,os.O_RDONLY|os.O_DIRECTORY)
                try:os.fsync(dirfd)
                finally:os.close(dirfd)
            finally:
                if temporary.exists():temporary.unlink()
            self.state=updated
        observed=self._decode(updated['current'])
        return {'status':'PASS','sha256':hashlib.sha256(observed).hexdigest(),
                'bytes':len(observed),'operation':doc['operation']}


def serve(config):
    if os.geteuid()==0:raise SiteDenied('SITE_MUST_RUN_NONROOT')
    site=Site(config)
    directory=Path(config['socket_path']).parent
    info=directory.stat()
    if (directory.is_symlink() or info.st_uid!=os.geteuid() or
        info.st_gid!=config['controller_gid'] or
        stat.S_IMODE(info.st_mode)!=0o2710 or Path(config['socket_path']).exists()):
        raise SiteDenied('INVALID_SITE_SOCKET_DIRECTORY')

    class Pages(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path!='/':self.send_error(404);return
            with site.lock:content=site._decode(site.state['current'])
            self.send_response(200 if content else 503)
            self.send_header('Content-Type','text/html; charset=utf-8')
            self.send_header('Content-Length',str(len(content)))
            self.end_headers();self.wfile.write(content)
        def log_message(self,*args):pass

    class Control(socketserver.StreamRequestHandler):
        def handle(self):
            try:
                self.request.settimeout(4)
                cred=self.request.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i'))
                if struct.unpack('3i',cred)[1]!=config['controller_uid']:
                    raise SiteDenied('UNAUTHORIZED_EXECUTOR_UID')
                raw=self.rfile.readline(524289)
                if len(raw)>524288 or not raw.endswith(b'\n'):
                    raise SiteDenied('INVALID_SITE_REQUEST_SIZE')
                result=site.apply(json.loads(raw))
            except Exception as exc:
                result={'status':'DENIED','reason':type(exc).__name__+':'+str(exc)}
            self.wfile.write(canon(result)+b'\n')

    class Unix(socketserver.ThreadingUnixStreamServer):daemon_threads=True
    with ThreadingHTTPServer(('127.0.0.1',config['http_port']),Pages) as http:
        threading.Thread(target=http.serve_forever,daemon=True).start()
        with Unix(config['socket_path'],Control) as control:
            os.chmod(config['socket_path'],0o660)
            control.serve_forever(poll_interval=.2)
        http.shutdown()


def client(socket_path, stdin):
    """Fixed operator E3 command, never an agent-selected shell invocation."""
    if not isinstance(socket_path,str) or not socket_path.startswith('/'):
        raise SiteDenied('INVALID_SITE_SOCKET')
    if len(stdin)>524000:raise SiteDenied('INVALID_SITE_REQUEST_SIZE')
    try:doc=json.loads(stdin)
    except (TypeError,ValueError) as exc:raise SiteDenied('INVALID_SITE_JSON') from exc
    if not isinstance(doc,dict) or set(doc)!={'operation','content_b64','content_sha256'}:
        raise SiteDenied('INVALID_SITE_OPERATION')
    if doc['operation'] not in ('deploy','rollback'):raise SiteDenied('INVALID_SITE_OPERATION')
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
        conn.settimeout(8);conn.connect(socket_path)
        conn.sendall(canon(doc)+b'\n')
        response=bytearray()
        while len(response)<=4096:
            part=conn.recv(4097-len(response))
            if not part:break
            response.extend(part)
            if b'\n' in part:break
    if not response.endswith(b'\n') or len(response)>4096:
        raise SiteDenied('INVALID_SITE_REPLY')
    result=json.loads(response)
    if result.get('status')!='PASS':raise SiteDenied('STAGING_OWNER_REJECTED_ACTION')
    if result.get('sha256')!=doc['content_sha256'] or result.get('operation')!=doc['operation']:
        raise SiteDenied('STAGING_OWNER_DIGEST_MISMATCH')
    return canon(result)


if __name__=='__main__':
    import sys
    if len(sys.argv)==3 and sys.argv[1]=='client':
        sys.stdout.buffer.write(client(sys.argv[2],sys.stdin.buffer.read(524001))+b'\n')
        raise SystemExit(0)
    if len(sys.argv)!=2:raise SystemExit('expected protected operator site config')
    config=json.loads(_private_file(Path(sys.argv[1])))
    if (set(config)!={'socket_path','state_dir','controller_uid','controller_gid','http_port'}
        or type(config['controller_uid']) is not int
        or type(config['controller_gid']) is not int
        or type(config['http_port']) is not int or not 1<=config['http_port']<=65535):
        raise SiteDenied('INVALID_OPERATOR_SITE_CONFIGURATION')
    serve(config)
