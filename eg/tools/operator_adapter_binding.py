"""Verify an operator-issued immutable binding for a generic external adapter.

A valid signature authorizes an adapter *configuration*, not an EG effect:
runtime OS peer identity, liveness, canonical PRE and HITL remain mandatory.
"""
from __future__ import annotations
import base64, json, re, time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HEX64=re.compile(r"^[0-9a-f]{64}$")
FIELDS={"version","adapter_id","capability_sha256","worker_uid",
        "socket_path","worker_public_key_b64","issued_at","expires_at",
        "environment","operator_nonce"}
class BindingDenied(ValueError):pass

def canonical(obj):
    return json.dumps(obj,sort_keys=True,separators=(",",":"),
                      ensure_ascii=False).encode()

def verify_operator_binding(signed:dict,*,operator_public_key_b64:str,
                            adapter_id:str,capability_sha256:str,now=None)->dict:
    if not isinstance(signed,dict) or set(signed)!=FIELDS|{"signature_b64"}:
        raise BindingDenied("INVALID_OPERATOR_BINDING")
    body={k:signed[k] for k in FIELDS}
    instant=time.time() if now is None else now
    if (body["version"]!=1 or body["adapter_id"]!=adapter_id
        or body["capability_sha256"]!=capability_sha256
        or not isinstance(adapter_id,str) or not adapter_id.startswith("trusted-adapter-")
        or not isinstance(capability_sha256,str) or not HEX64.fullmatch(capability_sha256)
        or type(body["worker_uid"]) is not int or body["worker_uid"]<=0
        or not isinstance(body["socket_path"],str) or not body["socket_path"].startswith("/")
        or ".." in body["socket_path"].split("/") or len(body["socket_path"])>128
        or not isinstance(body["environment"],str) or not body["environment"]
        or len(body["environment"])>64
        or not isinstance(body["operator_nonce"],str)
        or not 16<=len(body["operator_nonce"])<=128
        or type(body["issued_at"]) not in (int,float)
        or type(body["expires_at"]) not in (int,float)
        or not body["issued_at"]<=instant<body["expires_at"]
        or body["expires_at"]-body["issued_at"]>86400):
        raise BindingDenied("OPERATOR_BINDING_EXPIRED_OR_OUT_OF_SCOPE")
    try:
        operator_key=base64.b64decode(operator_public_key_b64,validate=True)
        worker_key=base64.b64decode(body["worker_public_key_b64"],validate=True)
        signature=base64.b64decode(signed["signature_b64"],validate=True)
        if any(len(k)!=32 for k in (operator_key,worker_key)) or len(signature)!=64:
            raise ValueError("invalid key size")
        if operator_key==worker_key:
            raise BindingDenied("OPERATOR_CANNOT_BE_EXECUTOR")
        Ed25519PublicKey.from_public_bytes(operator_key).verify(signature,canonical(body))
    except BindingDenied:raise
    except Exception as exc:
        raise BindingDenied("OPERATOR_BINDING_SIGNATURE_INVALID") from exc
    return {"status":"SIGNED_CONFIGURATION_ONLY","admission":False,
            "adapter_id":adapter_id,"worker_uid":body["worker_uid"],
            "socket_path":body["socket_path"],"worker_public_key_b64":body["worker_public_key_b64"],
            "capability_sha256":capability_sha256,"environment":body["environment"],
            "expires_at":body["expires_at"],
            "next_action":"VERIFY_RUNTIME_PEERCRED_LIVENESS_AND_CANONICAL_PRE"}
