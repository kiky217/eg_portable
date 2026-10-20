import base64,time
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from tools.operator_adapter_binding import verify_operator_binding,BindingDenied,canonical

def pub(key):
    return base64.b64encode(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()

def approval(operator,worker):
    now=int(time.time())
    data={"version":1,"adapter_id":"trusted-adapter-generic",
          "capability_sha256":"a"*64,"worker_uid":10001,
          "socket_path":"/var/run/eg-adapters/generic.sock",
          "worker_public_key_b64":pub(worker),"issued_at":now-1,"expires_at":now+100,
          "environment":"isolated-test","operator_nonce":"operator_nonce_123456"}
    return {**data,"signature_b64":base64.b64encode(operator.sign(canonical(data))).decode()}

def verify(doc,operator):
    return verify_operator_binding(doc,operator_public_key_b64=pub(operator),
              adapter_id="trusted-adapter-generic",capability_sha256="a"*64)

def test_independent_signature_binds_runtime_but_never_authorizes_effect():
    operator,worker=Ed25519PrivateKey.generate(),Ed25519PrivateKey.generate()
    result=verify(approval(operator,worker),operator)
    assert result["status"]=="SIGNED_CONFIGURATION_ONLY"
    assert not result["admission"]
    assert result["worker_uid"]==10001

def test_self_signing_denied():
    key=Ed25519PrivateKey.generate()
    with pytest.raises(BindingDenied,match="OPERATOR_CANNOT_BE_EXECUTOR"):
        verify(approval(key,key),key)

def test_mutated_identity_or_scope_denied():
    operator,worker=Ed25519PrivateKey.generate(),Ed25519PrivateKey.generate()
    original=approval(operator,worker)
    for key,bad in [("worker_uid",0),("socket_path","/var/run/../root/worker.sock"),
                    ("environment","production"),("adapter_id","trusted-adapter-impostor")]:
        with pytest.raises(BindingDenied):
            verify({**original,key:bad},operator)

def test_untrusted_operator_denied():
    operator,worker=Ed25519PrivateKey.generate(),Ed25519PrivateKey.generate()
    with pytest.raises(BindingDenied,match="SIGNATURE_INVALID"):
        verify(approval(operator,worker),Ed25519PrivateKey.generate())
