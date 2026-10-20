import pytest
from tools.typed_capability_match import validate_typed_descriptor,match_typed_capability,TypedCapabilityDenied

CAP={"schema_version":2,"id":"scanner","adapter_id":"scanner-adapter",
"action_type":"scan_ca","effect_class":"E3","input_schema_id":"solana/scan-v1",
"output_schema_id":"solana/mints-v1","transport":"unix-rpc",
"target_prefix":"/tasks/scanner/","max_payload_bytes":4096}
REQ={"effect_class":"E3","action_type":"scan_ca",
"target":"/tasks/scanner/task-1","input_schema_id":"solana/scan-v1"}

def test_new_scanner_capability_matches_without_admission():
    result=match_typed_capability(CAP,REQ)
    assert result["matched"] and not result["admission"]
    assert result["status"]=="MATCHED_OPERATOR_ONBOARDING_REQUIRED"

@pytest.mark.parametrize("different",[
    {"input_schema_id":"solana/scan-v2"},
    {"effect_class":"E0"},
    {"target":"/tasks/scanner-other/task-1"},
    {"target":"/tasks/scanner/../admin"},
])
def test_mismatch_denied(different):
    r=match_typed_capability(CAP,{**REQ,**different})
    assert not r["matched"] and not r["admission"]

@pytest.mark.parametrize("bad",[
    {"schema_version":3},
    {"max_payload_bytes":True},
    {"max_payload_bytes":9999999},
    {"transport":"shell"},
    {"input_schema_id":"bad schema"},
    {"target_prefix":"/tasks/../admin"},
    {"unknown":"extra"},
])
def test_bad_metadata_fail_closed(bad):
    with pytest.raises(TypedCapabilityDenied):
        validate_typed_descriptor({**CAP,**bad})
