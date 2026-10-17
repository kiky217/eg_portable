"""Independent attestation-only worker entrypoint and fail-closed RPC tests."""
import base64
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption,PublicFormat

from tools.adapter_attestation_worker import WorkerSetupDenied,serve
from tools.adapter_liveness import canon,probe_unix

ADAPTER="trusted-adapter-e3-test"
CAP="f"*64
ACTION="e"*64


def _key(path):
    private=Ed25519PrivateKey.generate()
    path.write_bytes(private.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
    path.chmod(0o600)
    public=base64.b64encode(private.public_key().public_bytes(
        Encoding.Raw,PublicFormat.Raw)).decode()
    return public


def _args(tmp_path,permission=0o700):
    root=tmp_path/"private"
    root.mkdir(mode=permission)
    key=root/"worker.pem"
    public=_key(key)
    return root,key,public


def test_rejects_world_readable_private_key(tmp_path):
    root,key,_=_args(tmp_path)
    key.chmod(0o644)
    with pytest.raises(WorkerSetupDenied,match="KEY_INSECURE"):
        serve(socket_path=root/"service.sock",private_key_path=key,
              adapter_id=ADAPTER,capability_sha256=CAP,max_requests=1)
    assert not (root/"service.sock").exists()


def test_rejects_symlinked_private_key(tmp_path):
    root,key,_=_args(tmp_path)
    alias=root/"alias.pem"
    alias.symlink_to(key)
    with pytest.raises(WorkerSetupDenied,match="KEY_UNAVAILABLE"):
        serve(socket_path=root/"service.sock",private_key_path=alias,
              adapter_id=ADAPTER,capability_sha256=CAP,max_requests=1)


def test_rejects_shared_socket_directory(tmp_path):
    root,key,_=_args(tmp_path)
    root.chmod(0o755)
    with pytest.raises(WorkerSetupDenied,match="DIRECTORY_NOT_PRIVATE"):
        serve(socket_path=root/"service.sock",private_key_path=key,
              adapter_id=ADAPTER,capability_sha256=CAP,max_requests=1)


def test_read_only_attestation_worker_in_separate_process(tmp_path):
    root,key,pub=_args(tmp_path)
    sock=root/"service.sock"
    argv=[sys.executable,"-m","tools.adapter_attestation_worker","--socket",str(sock),
          "--private-key",str(key),"--adapter-id",ADAPTER,
          "--capability-sha256",CAP,"--max-requests","2"]
    env={**os.environ,"PYTHONPATH":str(Path(__file__).resolve().parents[1])}
    process=subprocess.Popen(argv,env=env)
    try:
        for _ in range(100):
            if sock.exists() or process.poll() is not None:
                break
            time.sleep(0.02)
        assert process.poll() is None,"attestation worker exited before probing"
        assert sock.stat().st_mode & 0o077==0
        # No shell, filesystem action, or execution RPC exists on this socket.
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as peer:
            peer.settimeout(3)
            peer.connect(str(sock))
            peer.sendall(canon({"operation":"execute","action":{"effect_class":"E5"}})+b"\n")
            denied=json.loads(peer.makefile("rb").readline())
        assert denied=={"status":"DENIED"}
        result=probe_unix(sock,adapter_id=ADAPTER,capability_sha256=CAP,
                          public_key_b64=pub,task_id="task-read-only",step_key="01.01",
                          gate_checkpoint_no=1,action_fingerprint=ACTION)
        assert result["status"]=="SIGNED_LIVENESS_ONLY_NOT_EXECUTION_ADMITTED"
        assert process.wait(timeout=5)==0
        assert not sock.exists()
        assert not list(root.glob("*.json"))
    finally:
        if process.poll() is None:
            process.kill();process.wait(timeout=5)
