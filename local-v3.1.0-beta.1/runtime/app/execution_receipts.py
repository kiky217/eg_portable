"""EG independent trusted-executor receipts (protocol 4.0 candidate).

The EG notary validates claims; a DISTINCT executor trust root validates execution.
Only the isolated worker may sign receipts. A receipt is valid for exactly one
task/step/PRE gate/action and is produced AFTER the worker performs an effect.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import time
from datetime import datetime
from typing import Any
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FIELDS = {
    "version", "task_id", "step_key", "gate_checkpoint_no",
    "action_fingerprint", "executor_id", "target",
    "output_sha256", "output_bytes", "completed_ns", "nonce"
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
NONCE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
MAX_BYTES = 2_000_000_000


def canon(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def body(task_id: str, step_key: str, gate_checkpoint_no: int,
         action_fingerprint: str, executor_id: str, target: str,
         data: bytes, nonce: str, *, completed_ns: int | None = None) -> dict[str, Any]:
    return {
        "version": 1, "task_id": task_id, "step_key": step_key,
        "gate_checkpoint_no": gate_checkpoint_no, "action_fingerprint": action_fingerprint,
        "executor_id": executor_id, "target": target,
        "output_sha256": hashlib.sha256(data).hexdigest(), "output_bytes": len(data),
        "completed_ns": time.time_ns() if completed_ns is None else completed_ns,
        "nonce": nonce
    }


def sign(receipt_body: dict[str, Any], private) -> dict[str, Any]:
    if set(receipt_body) != FIELDS:
        raise ValueError("invalid receipt schema")
    return {**receipt_body, "signature_b64": base64.b64encode(private.sign(canon(receipt_body))).decode("ascii")}


def verify(receipt: Any, *, public_b64: str, task_id: str, step_key: str,
           gate_checkpoint_no: int, action_fingerprint: str, target: str,
           gate_created_at: str, time_now_ns: int | None = None,
           max_future_seconds: int = 30) -> tuple[bool, str]:
    if not isinstance(receipt, dict) or set(receipt) != FIELDS | {"signature_b64"}:
        return False, "EXECUTION_RECEIPT_MISSING_OR_INVALID_SCHEMA"
    value = {k: receipt[k] for k in FIELDS}
    if type(value["version"]) is not int or value["version"] != 1:
        return False, "EXECUTION_RECEIPT_VERSION_UNSUPPORTED"
    if (value["task_id"] != task_id or value["step_key"] != step_key
        or type(value["gate_checkpoint_no"]) is not int
        or value["gate_checkpoint_no"] != gate_checkpoint_no
        or value["action_fingerprint"] != action_fingerprint
        or value["target"] != target):
        return False, "EXECUTION_RECEIPT_GATE_OR_ACTION_MISMATCH"
    if (not isinstance(value["executor_id"], str)
        or not value["executor_id"].startswith("trusted-worker-")
        or not isinstance(value["nonce"], str) or not NONCE.fullmatch(value["nonce"])
        or not isinstance(value["output_sha256"], str)
        or not HEX64.fullmatch(value["output_sha256"])
        or type(value["output_bytes"]) is not int
        or not 0 < value["output_bytes"] <= MAX_BYTES
        or type(value["completed_ns"]) is not int):
        return False, "EXECUTION_RECEIPT_INVALID_FIELDS"
    try:
        gate_ns = int(datetime.fromisoformat(gate_created_at).timestamp() * 1_000_000_000)
    except (TypeError, ValueError, OverflowError):
        return False, "EXECUTION_RECEIPT_INVALID_GATE_TIME"
    if value["completed_ns"] < gate_ns:
        return False, "EXECUTION_RECEIPT_PREDATES_GATE"
    now = time.time_ns() if time_now_ns is None else time_now_ns
    if value["completed_ns"] > now + int(max_future_seconds*1_000_000_000):
        return False, "EXECUTION_RECEIPT_FUTURE_TIMESTAMP"
    try:
        raw_public=base64.b64decode(public_b64,validate=True)
        signature=base64.b64decode(receipt["signature_b64"],validate=True)
        if len(raw_public)!=32 or len(signature)!=64:
            return False, "EXECUTION_RECEIPT_INVALID_SIGNATURE_FORMAT"
        Ed25519PublicKey.from_public_bytes(raw_public).verify(signature,canon(value))
    except (ValueError, TypeError, KeyError, AttributeError):
        return False, "EXECUTION_RECEIPT_INVALID_SIGNATURE"
    except Exception as exc:
        if type(exc).__name__ == "InvalidSignature":
            return False, "EXECUTION_RECEIPT_INVALID_SIGNATURE"
        return False, "EXECUTION_RECEIPT_TRUST_ROOT_ERROR"
    return True, "EXECUTION_RECEIPT_VALID"
