"""Read-only deployment inspection never mistakes a catalog listing for admission."""
import json,os
import pytest
from tools.inspect_live_capabilities import inspect,InspectionError,_read_private_env

def _state(tmp_path,contents):
    state=tmp_path/'state';state.mkdir()
    conf=state/'runtime.env';conf.write_text(contents);conf.chmod(0o600)
    return state

def test_rejects_untrusted_manifest_operator_key_before_network(tmp_path):
    state=_state(tmp_path,'EVALUATION_GATEWAY_API_KEY=local-test\n'
           'EVALUATION_GATEWAY_EXTERNAL_REGISTRY_OPERATOR_PUBLIC_KEY_B64=pinned\n')
    manifest=tmp_path/'manifest.json';manifest.write_text(json.dumps({
        'operator_public_key_b64':'untrusted','capabilities':[{'adapter_id':'trusted-adapter-a'}]}))
    with pytest.raises(InspectionError,match='UNTRUSTED_CATALOG_OPERATOR_ROOT'):
        inspect(state=state,manifest=manifest)

def test_private_config_only(tmp_path):
    state=_state(tmp_path,'EVALUATION_GATEWAY_API_KEY=local-test\n')
    config=state/'runtime.env';config.chmod(0o644)
    with pytest.raises(InspectionError,match='PRIVATE_RUNTIME_CONFIG_REQUIRED'):
        _read_private_env(config)

def test_no_duplicate_config_keys(tmp_path):
    state=_state(tmp_path,'EVALUATION_GATEWAY_API_KEY=x\nEVALUATION_GATEWAY_API_KEY=y\n')
    with pytest.raises(InspectionError,match='DUPLICATE_RUNTIME_CONFIG_KEY'):
        _read_private_env(state/'runtime.env')

def test_rejects_non_loopback_inspection_before_file_read(tmp_path):
    with pytest.raises(InspectionError,match='LOCAL_GATEWAY_URL_REQUIRED'):
        inspect(state=tmp_path/'missing',manifest=tmp_path/'missing',url='http://example.org:18766')
