"""Bounded portable nested JSON schema v2, independent of language/tools.

No dynamic expressions, remote $refs, pattern evaluation or schema execution.
Operator pins SHA256 of exact canonical schema before any trusted worker effect.
"""
from __future__ import annotations
import hashlib,json,re
class NestedSchemaDenied(ValueError):pass
_ID=re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
_TYPES={"string","integer","boolean","object","array"}
MAX_DEPTH=5
MAX_NODES=128
MAX_SCHEMA_BYTES=16384

def canon(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()

def _inspect(spec,depth,budget):
    if depth>MAX_DEPTH or not isinstance(spec,dict) or spec.get("type") not in _TYPES:
        raise NestedSchemaDenied("NESTED_SCHEMA_DEPTH_OR_TYPE")
    budget[0]+=1
    if budget[0]>MAX_NODES:raise NestedSchemaDenied("NESTED_SCHEMA_TOO_COMPLEX")
    kind=spec["type"]
    if kind in ("string","integer"):
        if (set(spec)!={"type","minimum","maximum"} or
            type(spec["minimum"]) is not int or type(spec["maximum"]) is not int or
            not 0<=spec["minimum"]<=spec["maximum"]<=524288):
            raise NestedSchemaDenied("INVALID_SCALAR_BOUNDS")
    elif kind=="boolean":
        if set(spec)!={"type"}:raise NestedSchemaDenied("INVALID_BOOLEAN_SCHEMA")
    elif kind=="object":
        if (set(spec)!={"type","properties","required","additional_properties"} or
            not isinstance(spec["properties"],dict) or len(spec["properties"])>64 or
            not isinstance(spec["required"],list) or
            not isinstance(spec["additional_properties"],bool) or
            any(not isinstance(k,str) or not 1<=len(k)<=128
                for k in spec["properties"]) or
            len(set(spec["required"]))!=len(spec["required"]) or
            any(not isinstance(k,str) or k not in spec["properties"] for k in spec["required"])):
            raise NestedSchemaDenied("INVALID_OBJECT_SCHEMA")
        for child in spec["properties"].values():_inspect(child,depth+1,budget)
    else:
        if (set(spec)!={"type","items","minimum","maximum"} or
            type(spec["minimum"]) is not int or type(spec["maximum"]) is not int or
            not 0<=spec["minimum"]<=spec["maximum"]<=10000):
            raise NestedSchemaDenied("INVALID_ARRAY_SCHEMA")
        _inspect(spec["items"],depth+1,budget)

def validate_schema_v2(schema):
    if (not isinstance(schema,dict) or
        set(schema)!={"schema_version","schema_id","document"} or
        type(schema["schema_version"]) is not int or schema["schema_version"]!=2 or
        not isinstance(schema["schema_id"],str) or not _ID.fullmatch(schema["schema_id"])):
        raise NestedSchemaDenied("INVALID_NESTED_SCHEMA_ENVELOPE")
    try:raw=canon(schema)
    except (ValueError,TypeError,RecursionError) as exc:
        raise NestedSchemaDenied("UNENCODABLE_NESTED_SCHEMA") from exc
    if len(raw)>MAX_SCHEMA_BYTES:raise NestedSchemaDenied("NESTED_SCHEMA_TOO_LARGE")
    _inspect(schema["document"],0,[0])
    if schema["document"]["type"]!="object":
        raise NestedSchemaDenied("OBJECT_DOCUMENT_REQUIRED")
    return hashlib.sha256(raw).hexdigest()

def _unique(pairs):
    output={}
    for k,v in pairs:
        if k in output:raise NestedSchemaDenied("DUPLICATE_JSON_FIELD")
        output[k]=v
    return output

def _nonfinite(_):
    raise NestedSchemaDenied("NONFINITE_JSON_VALUE")

def _check(spec,value,depth):
    if depth>MAX_DEPTH:raise NestedSchemaDenied("NESTED_DATA_DEPTH_EXCEEDED")
    kind=spec["type"]
    if kind=="boolean":valid=type(value) is bool
    elif kind=="string":valid=isinstance(value,str) and spec["minimum"]<=len(value)<=spec["maximum"]
    elif kind=="integer":valid=type(value) is int and spec["minimum"]<=value<=spec["maximum"]
    elif kind=="array":
        valid=isinstance(value,list) and spec["minimum"]<=len(value)<=spec["maximum"]
        if valid:
            for item in value:_check(spec["items"],item,depth+1)
    else:
        valid=isinstance(value,dict) and set(spec["required"]).issubset(value)
        if valid and not spec["additional_properties"]:
            valid=set(value).issubset(spec["properties"])
        if valid:
            for name,item in value.items():
                if name in spec["properties"]:_check(spec["properties"][name],item,depth+1)
    if not valid:raise NestedSchemaDenied("TYPED_NESTED_VALUE_DENIED")

def validate_document_v2(schema,raw,*,expected_schema_sha256,max_bytes):
    digest=validate_schema_v2(schema)
    if (not isinstance(raw,bytes) or not raw or
        type(max_bytes) is not int or not 1<=max_bytes<=524288 or len(raw)>max_bytes or
        expected_schema_sha256!=digest):
        raise NestedSchemaDenied("UNPINNED_OR_OVERSIZE_NESTED_DOCUMENT")
    try:value=json.loads(raw.decode("utf-8"),object_pairs_hook=_unique,parse_constant=_nonfinite)
    except (ValueError,TypeError,UnicodeError,OverflowError,RecursionError) as exc:
        raise NestedSchemaDenied("INVALID_NESTED_DOCUMENT") from exc
    _check(schema["document"],value,0)
    return {"status":"SCHEMA_VERIFIED_NOT_ADMITTED","schema_id":schema["schema_id"],
            "payload_sha256":hashlib.sha256(raw).hexdigest(),"payload_bytes":len(raw),
            "value":value}
