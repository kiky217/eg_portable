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

def test_operator_activate_resolve_revoke_restart_no_self_privilege(tmp_path,monkeypatch):
    directory=tmp_path/"db";directory.mkdir(mode=0o700)
    operator=Ed25519PrivateKey.generate()
    worker=Ed25519PrivateKey.generate()
    record=binding(operator,worker)
    seen=[]
    def probe(path,**kwargs):
        seen.append((path,kwargs["expected_worker_uid"],kwargs["public_key_b64"]))
        return True
    monkeypatch.setattr('tools.operator_runtime_registry.probe_unix',probe)
    registry=OperatorAdapterRegistry(directory,pub(operator))
    created=registry.activate(record,adapter_id=record["adapter_id"],
                              capability_sha256=record["capability_sha256"])
    assert created["status"]=="ACTIVE_CONFIG_ONLY" and not created["admission"]
    assert seen==[(record["socket_path"],65533,pub(worker))]
    again=OperatorAdapterRegistry(directory,pub(operator))
    assert again.resolve("trusted-adapter-scanner")["status"]=="CONFIGURED_LIVENESS_RECHECK_REQUIRED"
    assert again.activate(record,adapter_id=record["adapter_id"],
        capability_sha256=record["capability_sha256"])["status"]=="ALREADY_ACTIVE"
    result=again.revoke(revoke(operator,record),adapter_id=record["adapter_id"])
    assert result["status"]=="REVOKED_NO_NEW_ADMISSION"
    with pytest.raises(RegistryDenied,match="NOT_ACTIVE"):
        again.resolve(record["adapter_id"])
    with pytest.raises(RegistryDenied,match="ALREADY_BOUND_OR_REVOKED"):
        again.activate(record,adapter_id=record["adapter_id"],
            capability_sha256=record["capability_sha256"])

def test_wrong_signer_cannot_revoke(tmp_path,monkeypatch):
    folder=tmp_path/"private";folder.mkdir(mode=0o700)
    owner=Ed25519PrivateKey.generate()
    other=Ed25519PrivateKey.generate()
    worker=Ed25519PrivateKey.generate()
    record=binding(owner,worker)
    monkeypatch.setattr('tools.operator_runtime_registry.probe_unix',lambda *args,**kwargs:True)
    reg=OperatorAdapterRegistry(folder,pub(owner))
    reg.activate(record,adapter_id=record["adapter_id"],
                 capability_sha256=record["capability_sha256"])
    with pytest.raises(RegistryDenied,match="UNTRUSTED_OPERATOR_REVOCATION"):
        reg.revoke(revoke(other,record),adapter_id=record["adapter_id"])
    assert reg.resolve(record["adapter_id"])["status"]=="CONFIGURED_LIVENESS_RECHECK_REQUIRED"

def signed_replacement(operator, original, **changes):
    doc={k:v for k,v in original.items() if k!="signature_b64"}
    doc.update(changes)
    return {**doc,"signature_b64":base64.b64encode(operator.sign(canonical(doc))).decode()}


def test_operator_can_renew_active_binding_but_not_replay_or_resurrect(tmp_path,monkeypatch):
    folder=tmp_path/"operator";folder.mkdir(mode=0o700)
    operator=Ed25519PrivateKey.generate()
    worker1,worker2=Ed25519PrivateKey.generate(),Ed25519PrivateKey.generate()
    first=binding(operator,worker1)
    probes=[]
    monkeypatch.setattr("tools.operator_runtime_registry.probe_unix",
                        lambda *a,**kw: probes.append(kw["public_key_b64"]))
    reg=OperatorAdapterRegistry(folder,pub(operator))
    assert reg.activate(first,adapter_id=first["adapter_id"],
                        capability_sha256=first["capability_sha256"])["status"]=="ACTIVE_CONFIG_ONLY"
    # Simulates the old operator binding's expiry, without manipulating wall-clock.
    with pytest.raises(RegistryDenied,match="EXPIRED"):
        reg.resolve(first["adapter_id"],now=first["expires_at"]+1)
    second=signed_replacement(operator,first,
        operator_nonce="operator_binding_nonce_rotated_456",
        issued_at=first["issued_at"]+1,worker_public_key_b64=pub(worker2))
    result=reg.activate(second,adapter_id=second["adapter_id"],
                        capability_sha256=second["capability_sha256"])
    assert result["status"]=="ACTIVE_CONFIG_ROTATED" and result["admission"] is False
    assert reg.resolve(first["adapter_id"])["worker_public_key_b64"]==pub(worker2)
    assert probes==[pub(worker1),pub(worker2)]
    assert reg.activate(second,adapter_id=second["adapter_id"],
                        capability_sha256=second["capability_sha256"])["status"]=="ALREADY_ACTIVE"
    with pytest.raises(RegistryDenied,match="STALE_OPERATOR_BINDING"):
        reg.activate(first,adapter_id=first["adapter_id"],
                     capability_sha256=first["capability_sha256"])
    same_nonce=signed_replacement(operator,second,worker_uid=65532)
    with pytest.raises(RegistryDenied,match="OPERATOR_NONCE_REUSED"):
        reg.activate(same_nonce,adapter_id=first["adapter_id"],
                     capability_sha256=first["capability_sha256"])
    wrong_cap=signed_replacement(operator,second,
        operator_nonce="operator_binding_nonce_rotated_789",
        capability_sha256="b"*64,issued_at=second["issued_at"])
    with pytest.raises(RegistryDenied,match="ALREADY_BOUND_OR_REVOKED"):
        reg.activate(wrong_cap,adapter_id=first["adapter_id"],
                     capability_sha256="b"*64)
    reg.revoke(revoke(operator,second),adapter_id=second["adapter_id"])
    with pytest.raises(RegistryDenied,match="ALREADY_BOUND_OR_REVOKED"):
        reg.activate(second,adapter_id=second["adapter_id"],
                     capability_sha256=second["capability_sha256"])
    with pytest.raises(RegistryDenied,match="NOT_ACTIVE"):
        reg.resolve(second["adapter_id"])


def test_failed_renewal_probe_preserves_current_route(tmp_path,monkeypatch):
    folder=tmp_path/"operator";folder.mkdir(mode=0o700)
    operator=Ed25519PrivateKey.generate()
    worker=Ed25519PrivateKey.generate()
    first=binding(operator,worker)
    monkeypatch.setattr("tools.operator_runtime_registry.probe_unix",lambda *a,**kw: True)
    reg=OperatorAdapterRegistry(folder,pub(operator))
    reg.activate(first,adapter_id=first["adapter_id"],
                 capability_sha256=first["capability_sha256"])
    newer=signed_replacement(operator,first,
        operator_nonce="operator_binding_nonce_newworker_777",
        issued_at=first["issued_at"]+1)
    def unavailable(*args,**kwargs):
        raise RuntimeError("WORKER_OFFLINE")
    monkeypatch.setattr("tools.operator_runtime_registry.probe_unix",unavailable)
    with pytest.raises(RuntimeError,match="WORKER_OFFLINE"):
        reg.activate(newer,adapter_id=newer["adapter_id"],
                     capability_sha256=newer["capability_sha256"])
    assert reg.resolve(first["adapter_id"])["worker_public_key_b64"]==pub(worker)
