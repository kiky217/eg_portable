"""Portable bounded typed JSON input/output validation for operator-pinned adapters.

A schema match is data validation only; original EG PRE, independently signed
HITL and separately provisioned worker remain required for all physical effects.
This intentionally supports a strict, small schema subset, not arbitrary JSON Schema.
"""
from __future__ import annotations
import hashlib,json
from tools.typed_capability_match import match_typed_capability

class TypedPayloadDenied(ValueError):pass
_FIELDS={"schema_version","schema_id","required","properties","additional_properties"}
_TYPES={"string","integer","boolean","array_string"}

def canonical(obj):
    return json.dumps(obj,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()

def validate_schema(schema):
    if (not isinstance(schema,dict) or set(schema)!=_FIELDS
        or type(schema["schema_version"]) is not int or schema["schema_version"]!=1
        or not isinstance(schema["schema_id"],str) or not 1<=len(schema["schema_id"])<=128
        or not isinstance(schema["required"],list)
        or not isinstance(schema["properties"],dict) or len(schema["properties"])>64
        or type(schema["additional_properties"]) is not bool
        or len(set(schema["required"]))!=len(schema["required"])):
        raise TypedPayloadDenied("INVALID_TYPED_SCHEMA")
    for key,spec in schema["properties"].items():
        if (not isinstance(key,str) or not 1<=len(key)<=128
            or not isinstance(spec,dict) or set(spec)!={"type","minimum","maximum"}
            or spec["type"] not in _TYPES
            or type(spec["minimum"]) is not int or type(spec["maximum"]) is not int
            or not 0<=spec["minimum"]<=spec["maximum"]<=524288):
            raise TypedPayloadDenied("INVALID_TYPED_PROPERTY")
    if any(not isinstance(key,str) or key not in schema["properties"]
           for key in schema["required"]):
        raise TypedPayloadDenied("INVALID_TYPED_REQUIRED")
    return hashlib.sha256(canonical(schema)).hexdigest()

def _no_duplicates(rows):
    obj={}
    for k,v in rows:
        if k in obj:raise TypedPayloadDenied("DUPLICATE_JSON_KEY")
        obj[k]=v
    return obj

def _invalid_constant(x):
    raise TypedPayloadDenied("NONFINITE_JSON_NUMBER")

def validate_document(schema,payload,*,expected_schema_sha256,max_bytes):
    digest=validate_schema(schema)
    if (not isinstance(expected_schema_sha256,str)
        or expected_schema_sha256!=digest or type(max_bytes) is not int
        or not 1<=max_bytes<=524288 or not isinstance(payload,bytes)
        or not 0<len(payload)<=max_bytes):
        raise TypedPayloadDenied("UNPINNED_OR_OVERSIZE_DOCUMENT")
    try:
        data=json.loads(payload.decode("utf-8"),object_pairs_hook=_no_duplicates,
                        parse_constant=_invalid_constant)
    except (UnicodeError,ValueError,OverflowError) as exc:
        raise TypedPayloadDenied("INVALID_TYPED_DOCUMENT") from exc
    if not isinstance(data,dict):
        raise TypedPayloadDenied("TYPED_OBJECT_REQUIRED")
    properties=schema["properties"]
    if (not set(schema["required"]).issubset(data)
        or not schema["additional_properties"] and not set(data).issubset(properties)):
        raise TypedPayloadDenied("TYPED_FIELD_SCOPE_DENIED")
    for key,value in data.items():
        if key not in properties:continue
        spec=properties[key];minimum=spec["minimum"];maximum=spec["maximum"]
        typ=spec["type"]
        if typ=="string":
            valid=isinstance(value,str) and minimum<=len(value)<=maximum
        elif typ=="integer":
            valid=type(value) is int and minimum<=value<=maximum
        elif typ=="boolean":
            valid=type(value) is bool
        else:
            valid=isinstance(value,list) and minimum<=len(value)<=maximum and all(
                  isinstance(x,str) and len(x)<=128 for x in value)
        if not valid:
            raise TypedPayloadDenied("TYPED_VALUE_DENIED:"+key)
    return {"status":"SCHEMA_VERIFIED_NOT_ADMITTED",
            "schema_id":schema["schema_id"],"payload_sha256":hashlib.sha256(payload).hexdigest(),
            "payload_bytes":len(payload),"value":data}

def match_typed_payload(descriptor,request,schema,payload,*,expected_schema_sha256):
    match=match_typed_capability(descriptor,request)
    if not match["matched"]:
        raise TypedPayloadDenied("CAPABILITY_OR_TARGET_NOT_MATCHED")
    if schema.get("schema_id")!=descriptor["input_schema_id"]:
        raise TypedPayloadDenied("INPUT_SCHEMA_ID_MISMATCH")
    result=validate_document(schema,payload,
           expected_schema_sha256=expected_schema_sha256,
           max_bytes=descriptor["max_payload_bytes"])
    return {"status":"TYPED_INPUT_PRE_REQUIRED","admission":False,
            "adapter_id":descriptor["adapter_id"],"input":result}
