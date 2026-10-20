"""Nested schema v2: generic GitHub E4 payload and scanner RPC data."""
import hashlib,json
import pytest
from tools.nested_json_schema import canon,validate_schema_v2,validate_document_v2,NestedSchemaDenied
from tools.typed_payload_contract import match_typed_payload

STR={"type":"string","minimum":1,"maximum":256}
SCHEMA={"schema_version":2,"schema_id":"github/effect-wire-v1",
        "document":{"type":"object","required":["version","operation","content_b64","commit_message"],
        "additional_properties":False,"properties":{
        "version":{"type":"integer","minimum":1,"maximum":1},
        "operation":{"type":"object","required":["repository","operation","branch","path","expected_blob_sha"],
            "additional_properties":False,"properties":{
                "repository":STR,"operation":STR,"branch":STR,
                "path":STR,"expected_blob_sha":{"type":"string","minimum":0,"maximum":40}}},
        "content_b64":{"type":"string","minimum":1,"maximum":524288},
        "commit_message":STR}}}
CAP={"schema_version":2,"id":"github-write","adapter_id":"trusted-adapter-github-e4",
    "action_type":"github_contents_write","effect_class":"E4",
    "input_schema_id":"github/effect-wire-v1","output_schema_id":"github/receipt-v1",
    "transport":"unix-rpc","target_prefix":"/github/example/project/src/",
    "max_payload_bytes":524288}
QUERY={"effect_class":"E4","action_type":"github_contents_write",
       "input_schema_id":"github/effect-wire-v1","target":"/github/example/project/src/example.json"}
INPUT={"version":1,"operation":{"repository":"example/project","operation":"create_file",
       "branch":"agent/test","path":"src/example.json","expected_blob_sha":""},
       "content_b64":"e30=","commit_message":"governed test"}

def test_nested_github_wire_matches_without_self_admission():
    data=canon(INPUT)
    sha=validate_schema_v2(SCHEMA)
    result=match_typed_payload(CAP,QUERY,SCHEMA,data,expected_schema_sha256=sha)
    assert result["status"]=="TYPED_INPUT_PRE_REQUIRED"
    assert not result["admission"]
    assert result["input"]["payload_sha256"]==hashlib.sha256(data).hexdigest()

@pytest.mark.parametrize("different",[
    {"operation":{"repository":"example/project","branch":"agent/test"}},
    {"operation":{**INPUT["operation"],"untrusted_shell":"bash"}},
    {"version":True},
    {"content_b64":""},
    {"unknown":"field"}
])
def test_bad_nested_effect_denied(different):
    payload=canon({**INPUT,**different})
    with pytest.raises(NestedSchemaDenied):
        validate_document_v2(SCHEMA,payload,
           expected_schema_sha256=validate_schema_v2(SCHEMA),max_bytes=524288)

def test_unpinned_nested_schema_or_duplicate_json_denied():
    value=canon(INPUT)
    with pytest.raises(NestedSchemaDenied,match="UNPINNED"):
        validate_document_v2(SCHEMA,value,expected_schema_sha256="0"*64,max_bytes=524288)
    with pytest.raises(NestedSchemaDenied,match="DUPLICATE"):
        validate_document_v2(SCHEMA,b'{"version":1,"version":1}',
             expected_schema_sha256=validate_schema_v2(SCHEMA),max_bytes=524288)

def test_recursive_schema_exhaustion_fail_closed():
    schema=json.loads(json.dumps(SCHEMA))
    for _ in range(7):
        schema["document"]={"type":"array","items":schema["document"],"minimum":0,"maximum":2}
    with pytest.raises(NestedSchemaDenied):
        validate_schema_v2(schema)
