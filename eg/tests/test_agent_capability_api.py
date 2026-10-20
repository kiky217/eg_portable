"""Agent discovery must never silently elevate user-supplied capability claims."""
import json
from tests.harness import CLIENT, HEAD
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
    assert all(x["status"] == "UNAVAILABLE" for x in data["capabilities"][:2])


def test_invalid_catalog_fails_closed(monkeypatch):
    monkeypatch.setenv("EVALUATION_GATEWAY_AGENT_CATALOG_JSON", "{not-json")
    data = CLIENT.get("/v1/agent/capabilities", headers=HEAD).json()
    assert data["catalog_valid"] is False
    assert len(data["capabilities"]) == 2
