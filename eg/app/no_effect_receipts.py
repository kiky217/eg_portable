"""Worker-authenticated NO_EFFECT proof bound to one PRE gate (not an execution receipt)."""
import base64
import json
import time
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FIELDS=("version","task_id","step_key","gate_checkpoint_no","action_fingerprint",
        "target","observed_ns","status","executor_id")

def _canon(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()

def sign_no_effect(private, *, task_id, step_key, gate_checkpoint_no,
                   action_fingerprint, target, executor_id):
    data=dict(version=1,task_id=task_id,step_key=step_key,
              gate_checkpoint_no=gate_checkpoint_no,
              action_fingerprint=action_fingerprint,target=target,
              observed_ns=time.time_ns(),status="NOT_EXECUTED",executor_id=executor_id)
    return {**data,"signature_b64":base64.b64encode(private.sign(_canon(data))).decode()}

def verify_no_effect(proof, *, public_b64, task_id, step_key,
                     gate_checkpoint_no, action_fingerprint, target, gate_created_at):
    if not isinstance(proof,dict) or set(proof)!=set(FIELDS)|{"signature_b64"}:
        return False
    if (type(proof["version"]) is not int or proof["version"]!=1 or
        proof["task_id"]!=task_id or proof["step_key"]!=step_key or
        type(proof["gate_checkpoint_no"]) is not int or
        proof["gate_checkpoint_no"]!=gate_checkpoint_no or
        proof["action_fingerprint"]!=action_fingerprint or proof["target"]!=target or
        proof["status"]!="NOT_EXECUTED" or
        not isinstance(proof["executor_id"],str) or
        not proof["executor_id"].startswith("trusted-worker-") or
        type(proof["observed_ns"]) is not int):
        return False
    try:
        start=int(datetime.fromisoformat(gate_created_at).timestamp()*1e9)
        now=time.time_ns()
        if proof["observed_ns"]<start or proof["observed_ns"]>now+30_000_000_000:
            return False
        key=base64.b64decode(public_b64,validate=True)
        signature=base64.b64decode(proof["signature_b64"],validate=True)
        if len(key)!=32 or len(signature)!=64:return False
        Ed25519PublicKey.from_public_bytes(key).verify(signature,
                 _canon({k:proof[k] for k in FIELDS}))
    except Exception:
        return False
    return True
