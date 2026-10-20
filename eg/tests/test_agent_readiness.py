"""Agent readiness preflight is read-only, deterministic and never implies admission."""
import importlib.util
from pathlib import Path

_PATH = Path(__file__).resolve().parents[1] / "tools" / "agent_readiness.py"
_SPEC = importlib.util.spec_from_file_location("agent_readiness", _PATH)
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
diagnose = _MODULE.diagnose


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
