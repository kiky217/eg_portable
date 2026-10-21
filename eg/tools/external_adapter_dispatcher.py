"""Generic authenticated E3-E5 RPC to an independently administered adapter.

No effect is implemented here: the separately provisioned worker checks the
original PRE, signed HITL and its own bounds, performs once, and signs receipt.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
import socket
import struct
from urllib.parse import urlsplit
from urllib.request import Request
from tools.no_redirect_http import urlopen
from app.execution_receipts import verify as verify_receipt
from app.no_effect_receipts import verify_no_effect
from tools.high_effect_admission import action_fingerprint
from tools.trusted_execution_worker import gate_allows_new_effect
from tools.signed_hitl_approval import verify_approval

class ExternalDispatchDenied(RuntimeError):
    pass


def _get(base, api_key, task_id, suffix):
    with urlopen(Request(f"{base}/v1/tasks/{task_id}{suffix}",
                         headers={"X-Evaluation-Key":api_key}), timeout=10) as response:
        return json.load(response)


def dispatch(*, request, eg_url, api_key, worker_socket, expected_worker_uid,
             adapter_id, pinned_public_key_b64, hitl_public_key_b64,
             operation: str = "execute"):
    if (not isinstance(request,dict) or
        set(request)!={"task_id","step_key","action","approval","data_b64"}):
        raise ExternalDispatchDenied("INVALID_EXTERNAL_DISPATCH_REQUEST")
    if operation not in ("execute","compensate","no_effect","recover_receipt"):
        raise ExternalDispatchDenied("UNSUPPORTED_EXTERNAL_RECOVERY_OPERATION")
    task=request["task_id"];step=request["step_key"];action=request["action"]
    if (not isinstance(task,str) or not 1<=len(task)<=127 or
        any(x in task for x in "/?#") or
        not isinstance(step,str) or not 1<=len(step)<=18 or
        not isinstance(action,dict) or not isinstance(request["approval"],dict) or
        action.get("effect_class") not in ("E3","E4","E5") or
        not isinstance(request["data_b64"],str)):
        raise ExternalDispatchDenied("INVALID_HIGH_EFFECT_ACTION")
    url=urlsplit(eg_url)
    if (url.scheme!="https" and not (url.scheme=="http" and
        url.hostname in ("127.0.0.1","localhost"))) or url.username or url.password:
        raise ExternalDispatchDenied("UNTRUSTED_GATEWAY_URL")
    if (not isinstance(expected_worker_uid,int) or expected_worker_uid<=0 or expected_worker_uid==os.getuid() or
        not isinstance(worker_socket,str) or not worker_socket.startswith("/") or
        not isinstance(adapter_id,str) or not adapter_id.startswith("trusted-adapter-")):
        raise ExternalDispatchDenied("INDEPENDENT_WORKER_NOT_CONFIGURED")
    try:
        data=base64.b64decode(request["data_b64"],validate=True)
    except (ValueError,TypeError) as exc:
        raise ExternalDispatchDenied("INVALID_EFFECT_PAYLOAD") from exc
    if (len(data)>524288 or
        (operation=="execute" and (not data or
         action.get("payload_sha256")!=hashlib.sha256(data).hexdigest() or
         action.get("payload_bytes")!=len(data))) or
        (operation!="execute" and data) or
        (operation=="compensate" and (action.get("effect_class")=="E5" or
         action.get("reversible") is not True))):
        raise ExternalDispatchDenied("EFFECT_PAYLOAD_NOT_BOUND")
    eg_url=eg_url.rstrip("/")
    state=_get(eg_url,api_key,task,"/state")
    detail=_get(eg_url,api_key,task,"")
    gate=state.get("pending_execution_gate")
    latest=state.get("latest_checkpoint")
    fp=action_fingerprint(action)
    pin=gate.get("high_effect_pin") if isinstance(gate,dict) else None
    if (state.get("status") not in (("IN_PROGRESS","RECOVERY_PENDING") if operation=="recover_receipt" else ("IN_PROGRESS",)) or
        state.get("current_step")!=step or
        detail.get("task",{}).get("contract_status")!="OPEN" or
        not isinstance(gate,dict) or not isinstance(latest,dict) or
        gate.get("action_fingerprint")!=fp or
        not gate.get("hitl_approved") or
        latest.get("checkpoint_no")!=gate.get("checkpoint_no") or
        latest.get("verdict")!="READY_TO_EXECUTE" or
        not isinstance(pin,dict) or
        pin.get("adapter_id")!=adapter_id or
        pin.get("public_key_b64")!=pinned_public_key_b64 or
        pin.get("action_fingerprint")!=fp or
        pin.get("approval_nonce")!=request["approval"].get("nonce")):
        raise ExternalDispatchDenied("CANONICAL_HIGH_EFFECT_PRE_NOT_ADMITTED")
    cp=gate["checkpoint_no"]
    row=next((c for c in detail.get("checkpoints",[]) if c.get("checkpoint_no")==cp),None)
    if (not row or row.get("verdict")!="READY_TO_EXECUTE" or
        (operation!="recover_receipt" and
         not gate_allows_new_effect(row.get("created_at","")))):
        raise ExternalDispatchDenied("ORIGINAL_PRE_GATE_INVALID")
    # A sealed receipt is historical evidence, not authority for a new effect.
    approval_time=(request["approval"].get("issued_at")
                   if operation=="recover_receipt" else None)
    verify_approval(request["approval"],hitl_public_key_b64,
                    task_id=task,step_key=step,gate_checkpoint_no=cp,
                    action_fingerprint=fp,adapter_id=adapter_id,now=approval_time)
    req={**request,"operation":operation}
    packet=json.dumps(req,sort_keys=True,separators=(",",":")).encode()+b"\n"
    if len(packet)>1_000_000:
        raise ExternalDispatchDenied("EFFECT_RPC_OVERSIZE")
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as peer:
        peer.settimeout(15)
        peer.connect(worker_socket)
        _,uid,_=struct.unpack("3i",peer.getsockopt(socket.SOL_SOCKET,
            socket.SO_PEERCRED,struct.calcsize("3i")))
        if uid!=expected_worker_uid:
            raise ExternalDispatchDenied("EXECUTOR_IDENTITY_MISMATCH")
        try:
            peer.sendall(packet)
            data_reply=bytearray()
            while b"\n" not in data_reply:
                chunk=peer.recv(65536)
                if not chunk or len(data_reply)+len(chunk)>1_000_000:
                    raise ExternalDispatchDenied("INCOMPLETE_EXECUTION_ACK_RECONCILE")
                data_reply.extend(chunk)
        except OSError as exc:
            raise ExternalDispatchDenied("WORKER_ACK_UNKNOWN_RECONCILE") from exc
    try:
        answer=json.loads(data_reply.split(b"\n",1)[0])
    except (ValueError,TypeError) as exc:
        raise ExternalDispatchDenied("INVALID_WORKER_RESPONSE_RECONCILE") from exc
    if not isinstance(answer,dict):
        raise ExternalDispatchDenied("INVALID_WORKER_RESPONSE_RECONCILE")
    if answer.get("status")!="PASS":
        raise ExternalDispatchDenied("WORKER_DENIED:"+str(answer.get("reason","unknown")))
    result=answer.get("result")
    if operation=="no_effect":
        proof=result.get("proof") if isinstance(result,dict) else None
        if (not verify_no_effect(proof,public_b64=pinned_public_key_b64,
            task_id=task,step_key=step,gate_checkpoint_no=cp,
            action_fingerprint=fp,target=action["target"],gate_created_at=row["created_at"])
            or proof.get("executor_id")!="trusted-worker-"+adapter_id):
            raise ExternalDispatchDenied("INDEPENDENT_NO_EFFECT_PROOF_INVALID")
        return {"status":"SIGNED_NO_EFFECT_RECONCILIATION_REQUIRED",
                "no_effect_proof":proof,"gate_checkpoint_no":cp}
    receipt=result.get("receipt") if isinstance(result,dict) else None
    valid,reason=verify_receipt(receipt,public_b64=pinned_public_key_b64,
        task_id=task,step_key=step,gate_checkpoint_no=cp,
        action_fingerprint=fp,target=action["target"],gate_created_at=row["created_at"])
    if (not valid or receipt.get("nonce")!=request["approval"]["nonce"] or
        receipt.get("executor_id")!="trusted-worker-"+adapter_id):
        raise ExternalDispatchDenied("INDEPENDENT_RECEIPT_INVALID:"+reason)
    return {"status":"RECEIPT_VERIFIED_POST_REQUIRED",
            "execution_receipt":receipt,"gate_checkpoint_no":cp}
