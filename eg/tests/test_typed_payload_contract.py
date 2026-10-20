import hashlib,json
import pytest
from tools.typed_payload_contract import (canonical,validate_document,
    match_typed_payload,TypedPayloadDenied)

CAP={"schema_version":2,"id":"scanner","adapter_id":"scanner-adapter",
"action_type":"scan_ca","effect_class":"E3","input_schema_id":"solana/scan-v1",
"output_schema_id":"solana/mints-v1","transport":"unix-rpc",
"target_prefix":"/tasks/scanner/","max_payload_bytes":4096}
REQUEST={"effect_class":"E3","action_type":"scan_ca","target":"/tasks/scanner/job-1",
         "input_schema_id":"solana/scan-v1"}
SCHEMA={"schema_version":1,"schema_id":"solana/scan-v1",
        "required":["wallet","rpc","limit"],"additional_properties":False,
        "properties":{"wallet":{"type":"string","minimum":32,"maximum":64},
          "rpc":{"type":"string","minimum":8,"maximum":256},
          "limit":{"type":"integer","minimum":1,"maximum":25}}}

def sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()

def test_solscan_bound_json_input_matches_without_admission():
    payload=canonical({"wallet":"1"*32,"rpc":"http://127.0.0.1:8899","limit":1})
    report=match_typed_payload(CAP,REQUEST,SCHEMA,payload,
                               expected_schema_sha256=sha(SCHEMA))
    assert report["status"]=="TYPED_INPUT_PRE_REQUIRED"
    assert not report["admission"]
    assert report["input"]["payload_sha256"]==hashlib.sha256(payload).hexdigest()

@pytest.mark.parametrize("payload",[
  b'{"wallet":"11111111111111111111111111111111","rpc":"http://127.0.0.1","limit":true}',
  b'{"wallet":"11111111111111111111111111111111","rpc":"http://127.0.0.1","limit":1,"secret":"x"}',
  b'{"wallet":"11111111111111111111111111111111","rpc":"http://127.0.0.1","limit":1,"limit":2}',
  b'{"wallet":"11111111111111111111111111111111","rpc":"http://127.0.0.1","limit":NaN}',
  b'[]',
])
def test_invalid_scanner_input_rejected(payload):
    with pytest.raises(TypedPayloadDenied):
        validate_document(SCHEMA,payload,expected_schema_sha256=sha(SCHEMA),
                          max_bytes=4096)

def test_schema_key_substitution_fail_closed():
    payload=canonical({"wallet":"1"*32,"rpc":"http://127.0.0.1:8899","limit":1})
    with pytest.raises(TypedPayloadDenied,match="UNPINNED_OR_OVERSIZE"):
        validate_document(SCHEMA,payload,expected_schema_sha256="0"*64,max_bytes=4096)

def test_output_schema_validates_scanner_result():
    schema={"schema_version":1,"schema_id":"solana/mints-v1",
       "required":["unique_mints"],"additional_properties":False,
       "properties":{"unique_mints":{"type":"array_string","minimum":0,"maximum":100}}}
    payload=canonical({"unique_mints":["So11111111111111111111111111111111111111112"]})
    result=validate_document(schema,payload,
                expected_schema_sha256=sha(schema),max_bytes=8192)
    assert result["status"]=="SCHEMA_VERIFIED_NOT_ADMITTED"
