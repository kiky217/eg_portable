"""Malformed operator-provisioned adapter config must fail before startup."""
import json
import pytest
from harness import gw


@pytest.mark.parametrize("catalog", [
    "{broken-json", "{}", "[]",
    json.dumps([{"adapter_id":"bad", "action_type":"execute"}]),
])
def test_external_registry_strict_diagnostics(monkeypatch, catalog):
    monkeypatch.setattr(gw, "HIGH_EFFECT_CAPABILITIES_JSON", catalog)
    with pytest.raises(RuntimeError, match="INVALID_HIGH_EFFECT_CAPABILITIES_CONFIGURATION"):
        gw.configured_high_effect_capabilities(allow_external=True, strict=True)
    assert gw.configured_high_effect_capabilities(allow_external=True) == []


def test_no_catalog_is_unprovisioned_not_parser_error(monkeypatch):
    monkeypatch.setattr(gw, "HIGH_EFFECT_CAPABILITIES_JSON", "")
    assert gw.configured_high_effect_capabilities(allow_external=True, strict=True) == []
