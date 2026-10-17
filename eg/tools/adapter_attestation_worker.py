"""Read-only independent Unix-socket attester, not an effect executor.

The private Ed25519 key and socket directory must be owned by the worker UID
and inaccessible to other users. An authenticated response proves key
possession only; it never grants EG PRE, effect dispatch, or POST VERIFIED.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import stat
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from tools.adapter_liveness import ProbeDenied,attest,canon


class WorkerSetupDenied(RuntimeError):
    pass


def _private_directory(path):
    if (path.is_symlink() or not path.is_dir() or
        path.stat().st_uid!=os.getuid() or
        stat.S_IMODE(path.stat().st_mode)&0o077):
        raise WorkerSetupDenied("WORKER_SOCKET_DIRECTORY_NOT_PRIVATE")


def _read_private_key(path):
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    except OSError as exc:
        raise WorkerSetupDenied("WORKER_PRIVATE_KEY_UNAVAILABLE") from exc
    try:
        info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid()
            or stat.S_IMODE(info.st_mode)&0o077 or info.st_nlink!=1):
            raise WorkerSetupDenied("WORKER_PRIVATE_KEY_INSECURE")
        with os.fdopen(fd,"rb",closefd=False) as stream:
            key=load_pem_private_key(stream.read(),password=None)
        if not isinstance(key,Ed25519PrivateKey):
            raise WorkerSetupDenied("WORKER_KEY_NOT_ED25519")
        return key
    finally:
        os.close(fd)


def serve(*,socket_path,private_key_path,adapter_id,capability_sha256,max_requests=0):
    """Run a strictly read-only attestation service in its own process/UID."""
    root=Path(socket_path).parent
    path=Path(socket_path)
    _private_directory(root)
    if path.exists() or path.is_symlink():
        raise WorkerSetupDenied("WORKER_SOCKET_ALREADY_EXISTS")
    if (not isinstance(adapter_id,str) or not adapter_id.startswith("trusted-adapter-")
        or not isinstance(capability_sha256,str) or len(capability_sha256)!=64
        or any(x not in "0123456789abcdef" for x in capability_sha256)
        or type(max_requests) is not int or max_requests<0):
        raise WorkerSetupDenied("WORKER_CAPABILITY_CONFIGURATION_INVALID")
    key=_read_private_key(Path(private_key_path))
    requests=0
    original_umask=os.umask(0o077)
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
            try:
                server.bind(str(path))
                os.chmod(path,0o600)
                inode=path.lstat().st_ino
                server.listen(8)
                while not max_requests or requests<max_requests:
                    with server.accept()[0] as peer:
                        requests+=1
                        peer.settimeout(3)
                        try:
                            with peer.makefile("rb") as stream:
                                raw=stream.readline(8193)
                            if not raw.endswith(b"\n") or len(raw)>8192:
                                raise ProbeDenied("WORKER_REQUEST_INVALID_SIZE")
                            request=json.loads(raw)
                            if (not isinstance(request,dict) or
                                set(request)!={"operation","challenge"} or
                                request["operation"]!="attest"):
                                raise ProbeDenied("WORKER_OPERATION_FORBIDDEN")
                            reply=attest(request["challenge"],adapter_id=adapter_id,
                                         capability_sha256=capability_sha256,private_key=key)
                        except (ProbeDenied,ValueError,TypeError,TimeoutError,OSError):
                            reply={"status":"DENIED"}
                        peer.sendall(canon(reply)+b"\n")
            finally:
                if path.exists() and not path.is_symlink() and path.lstat().st_ino==inode:
                    path.unlink()
    finally:
        os.umask(original_umask)


def main():
    parser=argparse.ArgumentParser(description="Read-only EG adapter key attester")
    parser.add_argument("--socket",required=True)
    parser.add_argument("--private-key",required=True)
    parser.add_argument("--adapter-id",required=True)
    parser.add_argument("--capability-sha256",required=True)
    parser.add_argument("--max-requests",type=int,default=0,help="test only; 0 serves continuously")
    a=parser.parse_args()
    serve(socket_path=a.socket,private_key_path=a.private_key,
          adapter_id=a.adapter_id,capability_sha256=a.capability_sha256,
          max_requests=a.max_requests)


if __name__=="__main__":
    main()
