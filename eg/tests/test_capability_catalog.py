"""Capability catalog is generic and does not confer execution privileges."""
import json
import pytest
from tools.capability_catalog import parse_catalog, lookup, CatalogError

def _fixture(effect="E2", action="modify_file"):
    return json.dumps({"schema_version": 1, "capabilities": [
        {"id": "worker.operation", "effect_class": effect, "action_type": action,
         "adapter_id": "remote.worker"}]})

@pytest.mark.parametrize("effect,action", [
    ("E2", "modify_file"), ("E3", "service_restart"), ("E5", "external_publish")])
def test_generic_nonhardcoded(effect, action):
    match = lookup(parse_catalog(_fixture(effect, action)), effect, action)
    assert match[0]["trust"] == "UNVERIFIED"
    assert match[0]["admission"] == "NOT_AUTHORIZED"

def test_malformed_and_invalid_catalogs_fail_closed():
    for raw in ['{}', '[]', 'not json', _fixture("E9")]:
        with pytest.raises(CatalogError):
            parse_catalog(raw)

def test_duplicate_rejected():
    row = {"id": "a", "effect_class": "E2", "action_type": "write", "adapter_id": "a"}
    with pytest.raises(CatalogError):
        parse_catalog(json.dumps({"schema_version": 1, "capabilities": [row, row]}))

def test_no_false_match():
    assert not lookup(parse_catalog(_fixture()), "E2", "write")
