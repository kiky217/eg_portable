"""Operator binding renewal preserves the exact trusted capability and key."""
import base64,json,os,time
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,PublicFormat,NoEncryption
from tools.operator_adapter_binding import canonical
from tools.renew_operator_binding import renew,RenewalDenied
from tools.operator_runtime_registry import OperatorAdapterRegistry

def _pub(key):
    return base64.b64encode(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()

def _setup(tmp_path):
    op=Ed25519PrivateKey.generate();worker=Ed25519PrivateKey.generate()
    key=tmp_path/'operator.pem'
    key.write_bytes(op.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()));key.chmod(0o600)
    now=int(time.time())
    body={'version':1,'adapter_id':'trusted-adapter-readonly-renew',
          'capability_sha256':'a'*64,'worker_uid':os.getuid(),
          'socket_path':'/tmp/example-worker.sock','worker_public_key_b64':_pub(worker),
          'issued_at':now-60,'expires_at':now+30,'environment':'local',
          'operator_nonce':'original-unique-nonce-123456'}
    old={**body,'signature_b64':base64.b64encode(op.sign(canonical(body))).decode()}
    path=tmp_path/'binding.json';path.write_text(json.dumps(old));path.chmod(0o600)
    reg=tmp_path/'registry';reg.mkdir(mode=0o700)
    obj=OperatorAdapterRegistry(reg,_pub(op))
    # Existing historical active binding; renewal must not manufacture another adapter.
    with obj._connect() as db:
        db.execute('INSERT INTO adapters VALUES (?,?,?,?,?)',(
            body['adapter_id'],body['capability_sha256'],body['operator_nonce'],
            json.dumps(old,sort_keys=True,separators=(',',':')),'ACTIVE'))
    return op,key,path,reg,old

def test_renew_existing_scope_only(tmp_path,monkeypatch):
    op,key,path,reg,old=_setup(tmp_path)
    import tools.operator_runtime_registry as registry
    monkeypatch.setattr(registry,'probe_unix',lambda *args,**kwargs:{'status':'PASS'})
    monkeypatch.setenv('EVALUATION_GATEWAY_LOCAL_HOST_MODE','enabled')
    result=renew(binding_path=path,operator_key_path=key,registry_dir=reg,
                 operator_public_key_b64=_pub(op),ttl_seconds=1200)
    assert result['status']=='ACTIVE_CONFIG_ROTATED'
    assert result['execution_approved'] is False
    new=json.loads(path.read_text())
    for field in ('adapter_id','worker_uid','socket_path','worker_public_key_b64',
                  'capability_sha256','environment'):
        assert new[field]==old[field]
    assert new['operator_nonce']!=old['operator_nonce']
    assert OperatorAdapterRegistry(reg,_pub(op),read_only=True).resolve(new['adapter_id'])['status']=='CONFIGURED_LIVENESS_RECHECK_REQUIRED'

def test_wrong_operator_cannot_rotate(tmp_path,monkeypatch):
    op,key,path,reg,old=_setup(tmp_path)
    other=Ed25519PrivateKey.generate()
    with pytest.raises(RenewalDenied,match='OPERATOR_ROOT_MISMATCH'):
        renew(binding_path=path,operator_key_path=key,registry_dir=reg,
              operator_public_key_b64=_pub(other))
    assert json.loads(path.read_text())==old

def test_denied_activation_preserves_original_and_no_pending(tmp_path,monkeypatch):
    op,key,path,reg,old=_setup(tmp_path)
    import tools.operator_runtime_registry as registry
    monkeypatch.setenv('EVALUATION_GATEWAY_LOCAL_HOST_MODE','enabled')
    def deny(*args,**kwargs):raise registry.RegistryDenied('ADAPTER_ALREADY_BOUND_OR_REVOKED')
    monkeypatch.setattr(registry.OperatorAdapterRegistry,'activate',deny)
    with pytest.raises(registry.RegistryDenied,match='ADAPTER_ALREADY_BOUND_OR_REVOKED'):
        renew(binding_path=path,operator_key_path=key,registry_dir=reg,
              operator_public_key_b64=_pub(op))
    assert json.loads(path.read_text())==old
    assert not path.with_name(path.name+'.pending').exists()


def test_out_of_range_ttl_rejected(tmp_path):
    op,key,path,reg,old=_setup(tmp_path)
    with pytest.raises(RenewalDenied,match='INVALID_BINDING_TTL'):
        renew(binding_path=path,operator_key_path=key,registry_dir=reg,
              operator_public_key_b64=_pub(op),ttl_seconds=100000)
    assert json.loads(path.read_text())==old
