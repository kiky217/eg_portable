"""Operator-shared UDS must never let group membership bypass UID pin."""
import json,os,socket,stat,threading,time
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tools.trusted_generic_rpc import serve

@pytest.mark.skipif(os.getuid()==0,reason="Requires independent non-root worker context")
def test_group_sharing_never_bypasses_controller_uid(tmp_path):
    directory=tmp_path/"socket";directory.mkdir()
    directory.chmod(0o2710)
    sock=directory/"worker.sock"
    class Adapter:
        adapter_id="trusted-adapter-group-test"
        private=Ed25519PrivateKey.generate()
    adapter=Adapter()
    group=os.stat(directory).st_gid
    controller_uid=os.getuid()+1000
    captured=[]
    def worker():
        try:
            serve(socket_path=str(sock),adapter=adapter,
                  capability_sha256="a"*64,eg_url="http://127.0.0.1:9999",
                  eg_key="test",hitl_public_key_b64="fixture",
                  controller_uid=controller_uid,controller_group_gid=group,
                  max_requests=1)
        except Exception as exc:captured.append(exc)
    thread=threading.Thread(target=worker,daemon=True);thread.start()
    for _ in range(200):
        if sock.exists():break
        time.sleep(.01)
    assert sock.exists(),captured
    assert stat.S_IMODE(sock.stat().st_mode)==0o660
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as peer:
        peer.settimeout(5);peer.connect(str(sock))
        peer.sendall(b'{"operation":"attest","challenge":{}}\n')
        response=json.loads(peer.recv(4096))
    thread.join(timeout=5)
    assert not thread.is_alive() and not captured
    assert response["status"]=="DENIED"
    assert response["reason"]=="TrustedRpcDenied"
