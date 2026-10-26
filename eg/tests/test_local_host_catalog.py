"""Explicit single-host installations retain signed binding and host peer checks."""
import base64,hashlib,json,os,time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
import pytest
from tools.operator_adapter_binding import verify_operator_binding,canonical,BindingDenied

def _pub(key):
    return base64.b64encode(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()

def test_explicit_single_host_accepts_uid_zero_but_not_by_default(monkeypatch):
    operator=Ed25519PrivateKey.generate();worker=Ed25519PrivateKey.generate()
    now=int(time.time())
    body={'version':1,'adapter_id':'trusted-adapter-generic-local',
          'capability_sha256':hashlib.sha256(b'typed').hexdigest(),'worker_uid':0,
          'socket_path':'/tmp/eg-local-test.sock','worker_public_key_b64':_pub(worker),
          'issued_at':now-1,'expires_at':now+60,'environment':'test',
          'operator_nonce':'replay-resistant-nonce-123456'}
    signature=base64.b64encode(operator.sign(canonical(body))).decode()
    signed={**body,'signature_b64':signature}
    kwargs=dict(operator_public_key_b64=_pub(operator),adapter_id=body['adapter_id'],
                capability_sha256=body['capability_sha256'])
    monkeypatch.delenv('EVALUATION_GATEWAY_LOCAL_HOST_MODE',raising=False)
    with pytest.raises(BindingDenied):verify_operator_binding(signed,**kwargs)
    monkeypatch.setenv('EVALUATION_GATEWAY_LOCAL_HOST_MODE','enabled')
    assert verify_operator_binding(signed,**kwargs)['worker_uid']==0
    modified={**signed,'worker_public_key_b64':_pub(Ed25519PrivateKey.generate())}
    with pytest.raises(BindingDenied):verify_operator_binding(modified,**kwargs)

def test_local_mode_requires_explicit_setting(monkeypatch):
    from tools import operator_process_service as service
    monkeypatch.setattr(service.os,'geteuid',lambda:0)
    monkeypatch.delenv('EVALUATION_GATEWAY_LOCAL_HOST_MODE',raising=False)
    with pytest.raises(service.ConfigurationDenied,match='WORKER_MUST_RUN_UNPRIVILEGED'):
        service.load_config(__import__('pathlib').Path('/nonexistent'))
