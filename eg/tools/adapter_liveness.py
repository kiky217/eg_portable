"""Read-only Ed25519 challenge/response for a separately running adapter.

This proves control of a pinned signing key at probe time; it is NOT effect
authorization, OS isolation attestation, or a production E3-E5 executor.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import socket
import stat
import struct
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DOMAIN="EG_ADAPTER_LIVENESS_V1"
MAX_AGE_NS=30_000_000_000
CHALLENGE_KEYS={"domain","adapter_id","capability_sha256","task_id","step_key",
                "gate_checkpoint_no","action_fingerprint","nonce","issued_ns"}
REPLY_KEYS={"domain","adapter_id","challenge_sha256","observed_ns"}


class ProbeDenied(RuntimeError):
    pass


def canon(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()


def _digest(value):
    return hashlib.sha256(canon(value)).hexdigest()


def challenge(*,adapter_id,capability_sha256,task_id,step_key,
              gate_checkpoint_no,action_fingerprint):
    if (not isinstance(adapter_id,str) or not adapter_id.startswith("trusted-adapter-")
        or not isinstance(task_id,str) or not task_id
        or not isinstance(step_key,str) or not step_key
        or type(gate_checkpoint_no) is not int or gate_checkpoint_no<1
        or not all(isinstance(x,str) and len(x)==64 and
                   all(ch in "0123456789abcdef" for ch in x)
                   for x in (capability_sha256,action_fingerprint))):
        raise ProbeDenied("INVALID_LIVENESS_SCOPE")
    return {"domain":DOMAIN,"adapter_id":adapter_id,
            "capability_sha256":capability_sha256,"task_id":task_id,
            "step_key":step_key,"gate_checkpoint_no":gate_checkpoint_no,
            "action_fingerprint":action_fingerprint,
            "nonce":secrets.token_hex(24),"issued_ns":time.time_ns()}


def _scope_ok(message):
    return (isinstance(message,dict) and set(message)==CHALLENGE_KEYS
            and message.get("domain")==DOMAIN
            and isinstance(message.get("adapter_id"),str)
            and isinstance(message.get("nonce"),str)
            and len(message["nonce"])==48
            and type(message.get("issued_ns")) is int
            and type(message.get("gate_checkpoint_no")) is int
            and message["gate_checkpoint_no"]>0
            and all(isinstance(message.get(k),str) and message[k]
                    for k in ("task_id","step_key"))
            and all(isinstance(message.get(k),str) and len(message[k])==64
                    and all(ch in "0123456789abcdef" for ch in message[k])
                    for k in ("capability_sha256","action_fingerprint")))


def attest(message,*,adapter_id,capability_sha256,private_key,now_ns=None):
    """Worker-side: sign only the scope independently configured for this worker."""
    now=time.time_ns() if now_ns is None else now_ns
    if (not _scope_ok(message) or message["adapter_id"]!=adapter_id
        or message["capability_sha256"]!=capability_sha256
        or not 0<=now-message["issued_ns"]<=MAX_AGE_NS):
        raise ProbeDenied("WORKER_LIVENESS_SCOPE_DENIED")
    reply={"domain":DOMAIN,"adapter_id":adapter_id,
           "challenge_sha256":_digest(message),"observed_ns":now}
    return {**reply,"signature_b64":base64.b64encode(private_key.sign(canon(reply))).decode()}


def verify(message,reply,*,adapter_id,capability_sha256,public_key_b64,now_ns=None):
    """Controller-side: bind one fresh nonce, gate and capability to pinned key."""
    now=time.time_ns() if now_ns is None else now_ns
    if (not _scope_ok(message) or message["adapter_id"]!=adapter_id
        or message["capability_sha256"]!=capability_sha256
        or not 0<=now-message["issued_ns"]<=MAX_AGE_NS
        or not isinstance(reply,dict)
        or set(reply)!=REPLY_KEYS|{"signature_b64"}
        or reply["domain"]!=DOMAIN or reply["adapter_id"]!=adapter_id
        or reply["challenge_sha256"]!=_digest(message)
        or type(reply["observed_ns"]) is not int
        or not message["issued_ns"]-MAX_AGE_NS<=reply["observed_ns"]<=now+MAX_AGE_NS):
        raise ProbeDenied("LIVENESS_PROOF_SCOPE_OR_FRESHNESS_DENIED")
    try:
        key=base64.b64decode(public_key_b64,validate=True)
        sig=base64.b64decode(reply["signature_b64"],validate=True)
        if len(key)!=32 or len(sig)!=64:
            raise ValueError("invalid Ed25519 key/signature size")
        Ed25519PublicKey.from_public_bytes(key).verify(
            sig,canon({k:reply[k] for k in REPLY_KEYS}))
    except (ValueError,TypeError,KeyError,AttributeError) as exc:
        raise ProbeDenied("LIVENESS_SIGNATURE_INVALID") from exc
    except Exception as exc:
        raise ProbeDenied("LIVENESS_SIGNATURE_INVALID") from exc
    return True


def probe_unix(path,*,adapter_id,capability_sha256,public_key_b64,
               task_id,step_key,gate_checkpoint_no,action_fingerprint,
               expected_worker_uid=None):
    """One bounded read-only UDS probe; optional OS UID pin prevents socket impersonation."""
    path=Path(path)
    try:
        if path.is_symlink() or not stat.S_ISSOCK(path.stat().st_mode):
            raise ProbeDenied("LIVENESS_SOCKET_INVALID")
        message=challenge(adapter_id=adapter_id,capability_sha256=capability_sha256,
                          task_id=task_id,step_key=step_key,
                          gate_checkpoint_no=gate_checkpoint_no,
                          action_fingerprint=action_fingerprint)
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as peer:
            peer.settimeout(3)
            peer.connect(str(path))
            if expected_worker_uid is not None:
                if type(expected_worker_uid) is not int or expected_worker_uid<0:
                    raise ProbeDenied("LIVENESS_WORKER_UID_INVALID")
                rawcred=peer.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,
                                        struct.calcsize("3i"))
                _,peer_uid,_=struct.unpack("3i",rawcred)
                if peer_uid!=expected_worker_uid:
                    raise ProbeDenied("LIVENESS_WORKER_UID_MISMATCH")
            peer.sendall(canon({"operation":"attest","challenge":message})+b"\n")
            data=bytearray()
            while b"\n" not in data:
                part=peer.recv(4096)
                if not part or len(data)+len(part)>8192:
                    raise ProbeDenied("LIVENESS_RESPONSE_MISSING_OR_TOO_LARGE")
                data.extend(part)
        reply=json.loads(data.split(b"\n",1)[0])
    except (OSError,ValueError,TypeError,json.JSONDecodeError) as exc:
        raise ProbeDenied("LIVENESS_WORKER_UNAVAILABLE") from exc
    verify(message,reply,adapter_id=adapter_id,
           capability_sha256=capability_sha256,public_key_b64=public_key_b64)
    return {"status":"SIGNED_LIVENESS_ONLY_NOT_EXECUTION_ADMITTED",
            "adapter_id":adapter_id,"challenge_sha256":_digest(message),
            "challenge":message,"signed_response":reply}
