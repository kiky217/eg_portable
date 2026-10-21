"""Agent discovery must never silently elevate user-supplied capability claims."""
import json
from harness import CLIENT, HEAD
import app.main as gw


def test_auth_required():
    assert CLIENT.get("/v1/agent/capabilities").status_code == 401


def test_bundled_and_untrusted_catalog(monkeypatch):
    blob = json.dumps({"schema_version": 1, "capabilities": [
        {"id": "custom.compiler", "effect_class": "E2", "action_type": "compile", "adapter_id": "host.worker"}]})
    monkeypatch.setenv("EVALUATION_GATEWAY_AGENT_CATALOG_JSON", blob)
    response = CLIENT.get("/v1/agent/capabilities", headers=HEAD)
    assert response.status_code == 200
    data = response.json()
    assert data["catalog_valid"] is True
    assert data["admission_is_execution"] is False
    custom = next(x for x in data["capabilities"] if x["id"] == "custom.compiler")
    assert custom["status"] == "UNVERIFIED_NOT_AUTHORIZED"


def test_disabled_no_false_admission(monkeypatch):
    monkeypatch.setattr(gw, "ADMISSION_MODE", "disabled")
    data = CLIENT.get("/v1/agent/capabilities", headers=HEAD).json()
    assert data["next_action"] == "PROVISION_TRUSTED_EXECUTOR"
    assert all(x["status"] == "UNAVAILABLE" for x in data["capabilities"][:3])


def test_invalid_catalog_fails_closed(monkeypatch):
    monkeypatch.setenv("EVALUATION_GATEWAY_AGENT_CATALOG_JSON", "{not-json")
    data = CLIENT.get("/v1/agent/capabilities", headers=HEAD).json()
    assert data["catalog_valid"] is False
    assert {r["id"] for r in data["capabilities"]} == {"builtin.read", "builtin.write", "builtin.replace"}


def test_registered_external_adapter_discovered_but_not_self_admitted(monkeypatch):
    import base64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    private=Ed25519PrivateKey.generate()
    public=base64.b64encode(private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
    cap={"adapter_id":"trusted-adapter-independent-test","action_type":"scan_contract",
         "effect_class":"E3","target_prefix":"/isolated/contracts/",
         "maximum_payload_bytes":4096,"isolated":True,
         "public_key_b64":public,"version":1,"ci_only":False}
    monkeypatch.setattr(gw,"HIGH_EFFECT_CI_FIXTURE_ENABLED",False)
    monkeypatch.setattr(gw,"HIGH_EFFECT_CAPABILITIES_JSON",json.dumps([cap]))
    monkeypatch.setattr(gw,"EXTERNAL_ADAPTER_MODE","enabled")
    monkeypatch.setattr(gw,"ADMISSION_MODE","enabled")
    data=CLIENT.get("/v1/agent/capabilities",headers=HEAD).json()
    found=[r for r in data["capabilities"] if r["adapter_id"]==cap["adapter_id"]]
    assert len(found)==1
    assert found[0]["action_type"]=="scan_contract"
    assert found[0]["effect_class"]=="E3"
    assert found[0]["status"]=="EXTERNAL_LIVE_PRE_ATTESTATION_REQUIRED"
    assert not data["admission_is_execution"]
    monkeypatch.setattr(gw,"EXTERNAL_ADAPTER_MODE","disabled")
    inactive=CLIENT.get("/v1/agent/capabilities",headers=HEAD).json()
    assert not [r for r in inactive["capabilities"] if r["adapter_id"]==cap["adapter_id"]]
