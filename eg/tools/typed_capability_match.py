"""Generic, read-only agent capability schema matching; never execution authority.

A typed descriptor is useful for discovery but does not grant trust, create a
worker, or replace canonical PRE and signed HITL.
"""
from __future__ import annotations
import re

_ALLOWED_EFFECT={"E0","E1","E2","E3","E4","E5"}
_NAME=re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_SCHEMA_ID=re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,127}$")
_TRANSPORTS={"unix-rpc","https-rpc"}
class TypedCapabilityDenied(ValueError):pass

def validate_typed_descriptor(value:dict)->dict:
    """Version-2 declarative metadata; independently provisioned runtime required."""
    expected={"schema_version","id","adapter_id","action_type","effect_class",
              "input_schema_id","output_schema_id","transport","target_prefix",
              "max_payload_bytes"}
    if not isinstance(value,dict) or set(value)!=expected or value.get("schema_version")!=2:
        raise TypedCapabilityDenied("INVALID_TYPED_CAPABILITY_SCHEMA")
    if any(not isinstance(value.get(f),str) or not _NAME.fullmatch(value[f])
           for f in ("id","adapter_id","action_type")):
        raise TypedCapabilityDenied("INVALID_CAPABILITY_IDENTITY")
    if (value["effect_class"] not in _ALLOWED_EFFECT or
        value["transport"] not in _TRANSPORTS or
        any(not isinstance(value.get(f),str) or not _SCHEMA_ID.fullmatch(value[f])
            for f in ("input_schema_id","output_schema_id")) or
        not isinstance(value["target_prefix"],str) or not value["target_prefix"].startswith("/")
        or any(x in ("","..",".") for x in value["target_prefix"].split("/")[1:-1]) or
        type(value["max_payload_bytes"]) is not int or
        not 1<=value["max_payload_bytes"]<=524288):
        raise TypedCapabilityDenied("INVALID_CAPABILITY_CONSTRAINTS")
    return dict(value)

def match_typed_capability(descriptor:dict,request:dict)->dict:
    cap=validate_typed_descriptor(descriptor)
    if (not isinstance(request,dict) or
        set(request)!={"effect_class","action_type","target","input_schema_id"}):
        raise TypedCapabilityDenied("INVALID_TYPED_CAPABILITY_QUERY")
    target=request.get("target")
    prefix=cap["target_prefix"].rstrip("/")
    matched=(request["effect_class"]==cap["effect_class"] and
             request["action_type"]==cap["action_type"] and
             request["input_schema_id"]==cap["input_schema_id"] and
             isinstance(target,str) and target.startswith(prefix+"/") and
             all(segment not in (".","..","") for segment in target[len(prefix)+1:].split("/")))
    return {"matched":matched,"admission":False,
            "status":"MATCHED_OPERATOR_ONBOARDING_REQUIRED" if matched else "NO_TYPED_SCOPE_MATCH",
            "adapter_id":cap["adapter_id"] if matched else None}
