"""#26: real UDS process and negative signed adapter liveness tests."""
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

from tools.adapter_liveness import ProbeDenied,attest,challenge,probe_unix,verify

ADAPTER="trusted-adapter-e3-probe"
CAP="a"*64
ACTION="b"*64


def new_challenge():
    return challenge(adapter_id=ADAPTER,capability_sha256=CAP,
                     task_id="task-test",step_key="01.01",
                     gate_checkpoint_no=7,action_fingerprint=ACTION)


def pub(key):
    return base64.b64encode(key.public_key().public_bytes(
        Encoding.Raw,PublicFormat.Raw)).decode()


def test_signed_nonce_scope_key_and_freshness_fail_closed():
    key=Ed25519PrivateKey.generate()
    msg=new_challenge()
    proof=attest(msg,adapter_id=ADAPTER,capability_sha256=CAP,private_key=key)
    assert verify(msg,proof,adapter_id=ADAPTER,capability_sha256=CAP,
                  public_key_b64=pub(key))
    with pytest.raises(ProbeDenied,match="SIGNATURE"):
        verify(msg,proof,adapter_id=ADAPTER,capability_sha256=CAP,
               public_key_b64=pub(Ed25519PrivateKey.generate()))
    with pytest.raises(ProbeDenied,match="SCOPE_OR_FRESHNESS"):
        verify(new_challenge(),proof,adapter_id=ADAPTER,
               capability_sha256=CAP,public_key_b64=pub(key))
    with pytest.raises(ProbeDenied,match="SCOPE_OR_FRESHNESS"):
        verify({**msg,"action_fingerprint":"c"*64},proof,adapter_id=ADAPTER,
               capability_sha256=CAP,public_key_b64=pub(key))
    with pytest.raises(ProbeDenied,match="SCOPE_OR_FRESHNESS"):
        verify(msg,proof,adapter_id=ADAPTER,capability_sha256=CAP,
               public_key_b64=pub(key),now_ns=msg["issued_ns"]+31_000_000_000)


def test_worker_rejects_wrong_capability_and_expired_challenge():
    key=Ed25519PrivateKey.generate()
    msg=new_challenge()
    with pytest.raises(ProbeDenied,match="SCOPE"):
        attest(msg,adapter_id=ADAPTER,capability_sha256="d"*64,private_key=key)
    with pytest.raises(ProbeDenied,match="SCOPE"):
        attest(msg,adapter_id=ADAPTER,capability_sha256=CAP,private_key=key,
               now_ns=msg["issued_ns"]+31_000_000_000)


def test_socket_offline_fails_closed(tmp_path):
    key=Ed25519PrivateKey.generate()
    with pytest.raises(ProbeDenied,match="UNAVAILABLE"):
        probe_unix(tmp_path/"absent.sock",adapter_id=ADAPTER,
                   capability_sha256=CAP,public_key_b64=pub(key),
                   task_id="task-test",step_key="01.01",
                   gate_checkpoint_no=7,action_fingerprint=ACTION)


def test_separately_running_unix_worker_proves_key_only(tmp_path):
    private=Ed25519PrivateKey.generate()
    private_path=tmp_path/"private.pem"
    private_path.write_bytes(private.private_bytes(
        Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
    private_path.chmod(0o600)
    sock_path=tmp_path/"attester.sock"
    worker_code="""
import json,os,socket,sys
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from tools.adapter_liveness import attest,canon
key=load_pem_private_key(Path(sys.argv[2]).read_bytes(),password=None)
with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
    s.bind(sys.argv[1]);os.chmod(sys.argv[1],0o600)
    s.listen(1)
    peer,_=s.accept()
    with peer:
        request=json.loads(peer.makefile("rb").readline(8192))
        reply=attest(request["challenge"],adapter_id=sys.argv[3],
                     capability_sha256=sys.argv[4],private_key=key)
        peer.sendall(canon(reply)+b"\\n")
"""
    env={**os.environ,"PYTHONPATH":str(Path(__file__).resolve().parents[1])}
    process=subprocess.Popen([sys.executable,"-c",worker_code,str(sock_path),
                              str(private_path),ADAPTER,CAP],env=env)
    try:
        for _ in range(100):
            if sock_path.exists():break
            if process.poll() is not None:break
            time.sleep(0.02)
        result=probe_unix(sock_path,adapter_id=ADAPTER,
                  capability_sha256=CAP,public_key_b64=pub(private),
                  task_id="task-test",step_key="01.01",gate_checkpoint_no=7,
                  action_fingerprint=ACTION)
        assert result["status"]=="SIGNED_LIVENESS_ONLY_NOT_EXECUTION_ADMITTED"
        assert process.wait(timeout=5)==0
        # The signature has not granted an action, PRE or worker receipt.
        assert not list(tmp_path.glob("*.json"))
    finally:
        if process.poll() is None:
            process.kill();process.wait(timeout=5)
