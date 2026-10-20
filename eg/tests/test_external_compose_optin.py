"""Compose external adapter is strictly opt-in, never quietly enabled."""
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]


def test_external_compose_separated_from_default():
    baseline=(ROOT/"docker-compose.yml").read_text()
    override=(ROOT/"docker-compose.external-adapter.yml").read_text()
    assert "EVALUATION_GATEWAY_EXTERNAL_ADAPTER_MODE" not in baseline
    assert "EVALUATION_GATEWAY_EXTERNAL_ADAPTER_MODE: enabled" in override
    for token in ("EVALUATION_GATEWAY_EXTERNAL_ADAPTER_UID:?",
                  "EVALUATION_GATEWAY_HIGH_EFFECT_CAPABILITIES_JSON:?",
                  "EVALUATION_GATEWAY_HITL_PUBLIC_KEY_B64:?",
                  "EVALUATION_GATEWAY_EXTERNAL_ADAPTER_SOCKET_DIR:?"):
        assert token in override
    for forbidden in ("docker.sock", "privileged: true", "cap_add:", "network_mode: host"):
        assert forbidden not in override
