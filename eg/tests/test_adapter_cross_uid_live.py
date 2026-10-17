"""True Linux OS-UID separation smoke for the read-only high-effect attester."""
import base64
import os
import shutil
import socket
import tempfile
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption,PublicFormat

from tools.adapter_attestation_worker import serve
from tools.adapter_liveness import probe_unix,canon

WORKER_UID=65101
CONTROLLER_UID=65102
ROGUE_UID=65103
SHARED_GID=65100
ADAPTER="trusted-adapter-e3-identity"
CAP="b"*64
ACTION="c"*64

pytestmark=pytest.mark.skipif(os.geteuid()!=0 or not hasattr(os,"fork"),
                             reason="needs isolated Linux root CI job")


def _child(uid,call):
    pid=os.fork()
    if pid==0:
        try:
            os.setgroups([SHARED_GID])
            os.setgid(SHARED_GID)
            os.setuid(uid)
            call()
        except BaseException:
            os._exit(9)
        os._exit(0)
    return pid


def _status(pid):
    got,raw=os.waitpid(pid,0)
    assert got==pid and os.WIFEXITED(raw)
    return os.WEXITSTATUS(raw)


def test_distinct_uid_controller_worker_live_attestation_and_denial():
    base=Path(tempfile.mkdtemp(prefix="eg-uid-"))
    try:
        base.chmod(0o755)  # group access only to the worker-owned inner dir
        wd=base/"worker";wd.mkdir()
        os.chown(wd,WORKER_UID,SHARED_GID)
        wd.chmod(0o2710)  # setgid, group traverse only, no group read/write
        private=Ed25519PrivateKey.generate()
        key=wd/"signing.pem"
        key.write_bytes(private.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
        os.chown(key,WORKER_UID,SHARED_GID)
        key.chmod(0o600)
        pub=base64.b64encode(private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
        sock=wd/"attester.sock"

        def work():
            serve(socket_path=sock,private_key_path=key,adapter_id=ADAPTER,
                  capability_sha256=CAP,controller_uid=CONTROLLER_UID,
                  controller_gid=SHARED_GID,max_requests=2)

        worker=_child(WORKER_UID,work)
        try:
            for _ in range(150):
                if sock.exists():break
                time.sleep(0.02)
            assert sock.exists(),"worker did not create its socket"
            assert sock.stat().st_uid==WORKER_UID
            assert sock.stat().st_gid==SHARED_GID
            assert sock.stat().st_mode&0o777==0o660

            def rogue_call():
                # Rogue member of shared group can connect, but SO_PEERCRED blocks it.
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
                    client.settimeout(3)
                    client.connect(str(sock))
                    client.sendall(canon({"operation":"attest","challenge":{}})+b"\n")
                    response=client.makefile("rb").readline(4096)
                assert response==b'{"status":"DENIED"}\n'
            assert _status(_child(ROGUE_UID,rogue_call))==0

            def controller_call():
                try: key.read_bytes()
                except PermissionError: pass
                else: raise AssertionError("controller read worker private key")
                result=probe_unix(sock,adapter_id=ADAPTER,
                      capability_sha256=CAP,public_key_b64=pub,
                      task_id="uid-isolation-test",step_key="01.01",
                      gate_checkpoint_no=1,action_fingerprint=ACTION,
                      expected_worker_uid=WORKER_UID)
                assert result["status"]=="SIGNED_LIVENESS_ONLY_NOT_EXECUTION_ADMITTED"
            assert _status(_child(CONTROLLER_UID,controller_call))==0
            assert _status(worker)==0
            assert not sock.exists()
        finally:
            if _status_if_alive(worker):
                os.kill(worker,9)
                os.waitpid(worker,0)
    finally:
        shutil.rmtree(base)


def _status_if_alive(pid):
    try:
        return os.waitpid(pid,os.WNOHANG)[0]==0
    except ChildProcessError:
        return False
