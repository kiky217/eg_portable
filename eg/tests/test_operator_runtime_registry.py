"""Persist independently approved adapter activation and signed revocation."""
import base64,json,time
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from tools.operator_adapter_binding import canonical
from tools.operator_runtime_registry import OperatorAdapterRegistry,RegistryDenied

def pub(k):
    return base64.b64encode(k.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()

def binding(operator,worker):
    now=int(time.time())
    doc={"version":1,"adapter_id":"trusted-adapter-scanner","capability_sha256":"a"*64,
         "worker_uid":65533,"socket_path":"/run/eg-scanner/worker.sock",
         "worker_public_key_b64":pub(worker),"issued_at":now-1,"expires_at":now+120,
         "environment":"test","operator_nonce":"operator_binding_nonce_123"}
    return {**doc,"signature_b64":base64.b64encode(operator.sign(canonical(doc))).decode()}

def revoke(operator,original):
    now=int(time.time())
    doc={"version":1,"adapter_id":original["adapter_id"],
         "capability_sha256":original["capability_sha256"],
         "binding_nonce":original["operator_nonce"],"decision":"REVOKED",
         "issued_at":now-1,"expires_at":now+60,"reason":"operator revoked adapter"}
    return {**doc,"signature_b64":base64.b64encode(operator.sign(canonical(doc))).decode()}

def test_operator_activate_resolve_revoke_restart_no_self_privilege(tmp_path):
    directory=tmp_path/"db";directory.mkdir(mode=0o700)
    operator=Ed25519PrivateKey.generate()
    worker=Ed25519PrivateKey.generate()
    record=binding(operator,worker)
    seen=[]
    def probe(path,**kwargs):
        seen.append((path,kwargs["expected_worker_uid"],kwargs["public_key_b64"]))
        return True
    registry=OperatorAdapterRegistry(directory,pub(operator))
    created=registry.activate(record,adapter_id=record["adapter_id"],
                              capability_sha256=record["capability_sha256"],probe=probe)
    assert created["status"]=="ACTIVE_CONFIG_ONLY" and not created["admission"]
    assert seen==[(record["socket_path"],65533,pub(worker))]
    again=OperatorAdapterRegistry(directory,pub(operator))
    assert again.resolve("trusted-adapter-scanner")["status"]=="CONFIGURED_LIVENESS_RECHECK_REQUIRED"
    assert again.activate(record,adapter_id=record["adapter_id"],
        capability_sha256=record["capability_sha256"],probe=probe)["status"]=="ALREADY_ACTIVE"
    result=again.revoke(revoke(operator,record),adapter_id=record["adapter_id"])
    assert result["status"]=="REVOKED_NO_NEW_ADMISSION"
    with pytest.raises(RegistryDenied,match="NOT_ACTIVE"):
        again.resolve(record["adapter_id"])
    with pytest.raises(RegistryDenied,match="ALREADY_BOUND_OR_REVOKED"):
        again.activate(record,adapter_id=record["adapter_id"],
            capability_sha256=record["capability_sha256"],probe=probe)

def test_wrong_signer_cannot_revoke(tmp_path):
    folder=tmp_path/"private";folder.mkdir(mode=0o700)
    owner=Ed25519PrivateKey.generate()
    other=Ed25519PrivateKey.generate()
    worker=Ed25519PrivateKey.generate()
    record=binding(owner,worker)
    reg=OperatorAdapterRegistry(folder,pub(owner))
    reg.activate(record,adapter_id=record["adapter_id"],
                 capability_sha256=record["capability_sha256"],probe=lambda *args,**kwargs:True)
    with pytest.raises(RegistryDenied,match="UNTRUSTED_OPERATOR_REVOCATION"):
        reg.revoke(revoke(other,record),adapter_id=record["adapter_id"])
    assert reg.resolve(record["adapter_id"])["status"]=="CONFIGURED_LIVENESS_RECHECK_REQUIRED"
