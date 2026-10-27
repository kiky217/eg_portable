"""Agent readiness preflight is read-only, deterministic and never implies admission."""
import importlib.util
from pathlib import Path

_PATH = Path(__file__).resolve().parents[1] / "tools" / "agent_readiness.py"
_SPEC = importlib.util.spec_from_file_location("agent_readiness", _PATH)
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
diagnose = _MODULE.diagnose


def test_plain_cli_uses_operation_name_not_legacy_effect_code(monkeypatch, capsys):
    import json
    monkeypatch.setenv("EVALUATION_GATEWAY_ADMISSION_MODE", "enabled")
    monkeypatch.delenv("EVALUATION_GATEWAY_EXECUTOR_OUTPUT_ROOT", raising=False)
    monkeypatch.delenv("EVALUATION_GATEWAY_EXECUTOR_PUBLIC_KEY_B64", raising=False)
    assert _MODULE.main(["--action", "write", "--json"]) == 2
    data = json.loads(capsys.readouterr().out)
    assert data["operation"] == "write" and "effect" not in data
    assert "E2" not in json.dumps(data)


def test_disabled_rejects_even_with_key():
    report = diagnose("E2", "write", {
        "EVALUATION_GATEWAY_ADMISSION_MODE": "disabled",
        "EVALUATION_GATEWAY_EXECUTOR_PUBLIC_KEY_B64": "public-not-secret",
        "EVALUATION_GATEWAY_EXECUTOR_OUTPUT_ROOT": "/protected",
    })
    assert report["preflight"] == "NOT_ADMITTED"
    assert "ADMISSION_DISABLED_ALL_CONCRETE_ACTIONS_DENIED" in report["reasons"]
    assert not report["mutated"] and not report["live_verified"]


def test_enabled_not_equal_live_ready():
    report = diagnose("E2", "write", {
        "EVALUATION_GATEWAY_ADMISSION_MODE": "enabled",
        "EVALUATION_GATEWAY_EXECUTOR_PUBLIC_KEY_B64": "public-not-secret",
        "EVALUATION_GATEWAY_EXECUTOR_OUTPUT_ROOT": "/protected",
    })
    assert report["preflight"] == "REQUIRES_LIVE_VERIFICATION"
    assert report["live_verified"] is False


def test_unprovisioned_source_and_shell_and_github():
    env = {"EVALUATION_GATEWAY_ADMISSION_MODE": "enabled"}
    for effect, action in [("E2", "edit_rust"), ("E2", "cargo_build"),
                           ("E3", "service_control"), ("E5", "git_push")]:
        report = diagnose(effect, action, env)
        assert "CAPABILITY_NOT_DISCOVERED" in report["reasons"]
        assert report["preflight"] == "NOT_ADMITTED"


def test_invalid_mode_fails_closed():
    assert "INVALID_ADMISSION_MODE" in diagnose("E0", "read", {
        "EVALUATION_GATEWAY_ADMISSION_MODE": "maybe"
    })["reasons"]


def test_external_adapter_never_requires_unrelated_builtin_e2_key():
    from tools.capability_catalog import parse_catalog
    raw = '{"schema_version":1,"capabilities":[{"id":"build.worker","effect_class":"E3","action_type":"bounded_process_run","adapter_id":"trusted-adapter-build"}]}'
    report = diagnose("E3", "bounded_process_run",
                      {"EVALUATION_GATEWAY_ADMISSION_MODE": "enabled"},
                      parse_catalog(raw))
    assert "EXTERNAL_CAPABILITY_UNVERIFIED" in report["reasons"]
    assert "EXECUTOR_PUBLIC_KEY_NOT_CONFIGURED" not in report["reasons"]
    assert report["preflight"] == "NOT_ADMITTED"
    assert report["live_verified"] is False


def test_builtin_e2_still_requires_executor_signer():
    report = diagnose("E2", "write",
                      {"EVALUATION_GATEWAY_ADMISSION_MODE": "enabled",
                       "EVALUATION_GATEWAY_EXECUTOR_OUTPUT_ROOT": "/bounded"})
    assert "EXECUTOR_PUBLIC_KEY_NOT_CONFIGURED" in report["reasons"]
    assert report["preflight"] == "NOT_ADMITTED"


def test_valid_e3_only_runtime_without_unrelated_e2_signer(monkeypatch):
    import json, base64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    import harness as H
    gw = H.gw
    def fresh_root():
        raw = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return base64.b64encode(raw).decode()
    capability = {"adapter_id": "trusted-adapter-e3-only",
        "action_type": "bounded_process_run", "effect_class": "E3",
        "target_prefix": "/tasks/e3-only/", "maximum_payload_bytes": 4096,
        "isolated": True, "public_key_b64": fresh_root(), "ci_only": False}
    monkeypatch.setattr(gw, "EXTERNAL_ADAPTER_MODE", "enabled")
    monkeypatch.setattr(gw, "EXTERNAL_ADAPTER_SOCKET", "/tmp/eg-test-e3-only.sock")
    monkeypatch.setattr(gw, "EXTERNAL_ADAPTER_UID", 65533)
    monkeypatch.setattr(gw, "EXTERNAL_REGISTRY_DIR", "")
    monkeypatch.setattr(gw, "EXTERNAL_REGISTRY_KEY", "")
    monkeypatch.setattr(gw, "HIGH_EFFECT_CAPABILITIES_JSON", json.dumps([capability]))
    monkeypatch.setattr(gw, "HIGH_EFFECT_CI_FIXTURE_ENABLED", False)
    monkeypatch.setattr(gw, "HITL_PUBLIC_KEY_B64", fresh_root())
    monkeypatch.setattr(gw, "ADMISSION_MODE", "enabled")
    monkeypatch.setattr(gw, "EXECUTOR_PUBLIC_KEY_B64", "")
    monkeypatch.setattr(gw, "EXECUTOR_OUTPUT_ROOT", "")
    monkeypatch.setattr(gw.os, "geteuid", lambda: 65534)
    gw.require_config()
    from fastapi.testclient import TestClient
    response = TestClient(gw.app).get("/v1/agent/capabilities", headers=H.HEAD)
    assert response.status_code == 200
    available = [x for x in response.json()["capabilities"]
                 if x["adapter_id"] == capability["adapter_id"]]
    assert len(available) == 1
    assert all(x["status"] == "UNAVAILABLE" for x in response.json()["capabilities"][:3])
    assert response.json()["admission_mode"] == "enabled"
    # Enabling bundled E2 additionally needs its own separate public signing key.
    monkeypatch.setattr(gw, "EXECUTOR_OUTPUT_ROOT", str(H.WORKER_OUTPUT))
    import pytest
    with pytest.raises(RuntimeError, match="independent executor public key missing"):
        gw.require_config()
