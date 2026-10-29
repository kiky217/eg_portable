"""Issue #61: matching typed capability never elevates an untrusted agent."""
import base64
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from harness import CLIENT, HEAD, gw

URL="/v1/agent/capability-match"

def test_canonical_operations_match_without_legacy_class_parameter(monkeypatch):
    monkeypatch.setattr(gw,"ADMISSION_MODE","enabled")
    for operation in ("read","write","replace"):
        response=CLIENT.get(URL,params={"action_type":operation,
                                        "target":"/workspace/example.txt"},headers=HEAD)
        assert response.status_code==200
        assert response.json()["admission"] is False
        assert response.json()["status"] in ("MATCHED_PRE_REQUIRED","CAPABILITY_UNPROVISIONED")
    unsupported=CLIENT.get(URL,params={"action_type":"service_control",
                                       "target":"/workspace/example.txt"},headers=HEAD)
    assert unsupported.status_code==422


def test_match_requires_authentication():
    assert CLIENT.get(URL,params={"effect_class":"governed_operation","action_type":"operate","target":"/scope/a"}).status_code==401

def test_match_respects_type_scope_and_admission(monkeypatch):
    key=Ed25519PrivateKey.generate()
    public=base64.b64encode(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
    record={"adapter_id":"trusted-adapter-test","action_type":"operate",
            "effect_class":"governed_operation","target_prefix":"/scope/",
            "maximum_payload_bytes":4096,"isolated":True,
            "public_key_b64":public,"version":1,"ci_only":False}
    monkeypatch.setattr(gw,"HIGH_EFFECT_CAPABILITIES_JSON",json.dumps([record]))
    monkeypatch.setattr(gw,"EXTERNAL_ADAPTER_MODE","enabled")
    params={"effect_class":"governed_operation","action_type":"operate","target":"/scope/work"}
    matched=CLIENT.get(URL,params=params,headers=HEAD).json()
    assert matched["status"]=="MATCHED_PRE_REQUIRED"
    assert not matched["admission"]
    assert matched["candidates"][0]["status"]=="LIVE_PRE_ATTESTATION_REQUIRED"
    denied=CLIENT.get(URL,params={**params,"target":"/scope-evil/work"},headers=HEAD).json()
    assert denied["status"]=="CAPABILITY_UNPROVISIONED"
    assert denied["next_action"]=="ONBOARD_INDEPENDENT_TRUSTED_ADAPTER"
    monkeypatch.setattr(gw,"ADMISSION_MODE","disabled")
    disabled=CLIENT.get(URL,params=params,headers=HEAD).json()
    assert disabled["status"]=="ADMISSION_DISABLED"
    assert not disabled["candidates"]

def test_bad_query_rejected():
    response=CLIENT.get(URL,params={"effect_class":"unsupported_scope","action_type":"operate","target":"/a"},headers=HEAD)
    assert response.status_code==422


def test_signed_operator_binding_discovery_is_read_only_and_actionable(monkeypatch,tmp_path):
    import hashlib
    import os
    import time
    from dataclasses import asdict
    from tools.high_effect_admission import AdapterCapability
    from tools.operator_runtime_registry import OperatorAdapterRegistry
    from tools.operator_adapter_binding import canonical
    from test_operator_runtime_registry import revoke
    operator,worker=Ed25519PrivateKey.generate(),Ed25519PrivateKey.generate()
    def pub(key):
        return base64.b64encode(key.public_key().public_bytes(
            Encoding.Raw,PublicFormat.Raw)).decode()
    spec={"adapter_id":"trusted-adapter-ready-demo","action_type":"scan",
          "effect_class":"governed_operation","target_prefix":"/sandbox/",
          "maximum_payload_bytes":512,"isolated":True,
          "public_key_b64":pub(worker),"version":1,"ci_only":False}
    cap=AdapterCapability(**spec)
    digest=hashlib.sha256(gw.canon(asdict(cap)).encode()).hexdigest()
    directory=tmp_path/"private";directory.mkdir(mode=0o700)
    monkeypatch.setattr(gw,"HIGH_EFFECT_CAPABILITIES_JSON",json.dumps([spec]))
    monkeypatch.setattr(gw,"EXTERNAL_ADAPTER_MODE","enabled")
    monkeypatch.setattr(gw,"EXTERNAL_REGISTRY_DIR",str(directory))
    monkeypatch.setattr(gw,"EXTERNAL_REGISTRY_KEY",pub(operator))
    params={"effect_class":"governed_operation","action_type":"scan","target":"/sandbox/a"}
    before=CLIENT.get(URL,params=params,headers=HEAD).json()
    assert before["status"]=="CAPABILITY_UNPROVISIONED"
    assert before["next_action"]=="RENEW_OR_ACTIVATE_OPERATOR_BINDING"
    assert before["candidates"][0]["status"]=="OPERATOR_BINDING_REQUIRED"
    assert not (directory/"adapter-activation.sqlite3").exists()
    now=int(time.time())
    document={"version":1,"adapter_id":cap.adapter_id,"capability_sha256":digest,
              "worker_uid":os.getuid()+12000,"socket_path":"/run/eg-demo/worker.sock",
              "worker_public_key_b64":pub(worker),"issued_at":now-1,
              "expires_at":now+120,"environment":"test",
              "operator_nonce":"operator-binding-signed-demo"}
    signed={**document,"signature_b64":
            base64.b64encode(operator.sign(canonical(document))).decode()}
    monkeypatch.setattr("tools.operator_runtime_registry.probe_unix",lambda *a,**kw: True)
    reg=OperatorAdapterRegistry(directory,pub(operator))
    reg.activate(signed,adapter_id=cap.adapter_id,capability_sha256=digest)
    db=directory/"adapter-activation.sqlite3"
    import sqlite3
    with sqlite3.connect(db) as connection:
        original_rows=connection.execute("SELECT * FROM adapters ORDER BY adapter_id").fetchall()
    ready=CLIENT.get(URL,params=params,headers=HEAD).json()
    assert ready["status"]=="MATCHED_PRE_REQUIRED"
    assert ready["candidates"][0]["status"]=="LIVE_PRE_ATTESTATION_REQUIRED"
    catalog=CLIENT.get("/v1/agent/capabilities",headers=HEAD).json()
    assert any(row.get("status")=="EXTERNAL_LIVE_PRE_ATTESTATION_REQUIRED"
               and row.get("adapter_id")==cap.adapter_id for row in catalog["capabilities"])
    with sqlite3.connect(db) as connection:
        assert connection.execute("SELECT * FROM adapters ORDER BY adapter_id").fetchall()==original_rows
    reg.revoke(revoke(operator,signed),adapter_id=cap.adapter_id)
    revoked=CLIENT.get(URL,params=params,headers=HEAD).json()
    assert revoked["candidates"][0]["status"]=="OPERATOR_BINDING_REQUIRED"


def test_missing_root_cannot_match_builtin_operations(monkeypatch, tmp_path):
    monkeypatch.setattr(gw, "ADMISSION_MODE", "enabled")
    monkeypatch.setattr(gw, "EXECUTOR_OUTPUT_ROOT", str(tmp_path / "missing"))
    for operation in ("read", "write", "replace"):
        result = CLIENT.get(URL, params={
            "action_type": operation, "target": str(tmp_path / "missing" / "example.txt")
        }, headers=HEAD).json()
        assert result["status"] == "CAPABILITY_UNPROVISIONED"
        assert result["admission"] is False


def test_existing_root_matches_replace_but_requires_real_pre(monkeypatch, tmp_path):
    monkeypatch.setattr(gw, "ADMISSION_MODE", "enabled")
    monkeypatch.setattr(gw, "EXECUTOR_OUTPUT_ROOT", str(tmp_path))
    result = CLIENT.get(URL, params={
        "action_type": "replace", "target": str(tmp_path / "existing.txt")
    }, headers=HEAD).json()
    assert result["status"] == "MATCHED_PRE_REQUIRED"
    assert result["admission"] is False
    assert result["candidates"][0]["status"] == "LIVE_PRE_REQUIRED"
