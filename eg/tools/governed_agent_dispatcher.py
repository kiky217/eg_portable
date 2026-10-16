#!/usr/bin/env python3
"""Strict agent entrypoint for the supported independently signed E0/E2 worker.

Not a general shell. Never executes an effect itself, never signs a receipt,
never calls POST and never declares a task VERIFIED. For other actions, require
a separately audited adapter; never route around EG or relabel effect classes.
"""
from __future__ import annotations
import json
import socket
from pathlib import Path
from urllib.request import Request, urlopen

from app.execution_receipts import verify
from tools.trusted_execution_worker import fingerprint, gate_allows_new_effect

class DispatchDenied(RuntimeError):
    pass

def _get(url: str, key: str, task: str, suffix: str) -> dict:
    with urlopen(Request(url.rstrip("/") + "/v1/tasks/" + task + suffix,
                         headers={"X-Evaluation-Key": key}), timeout=10) as response:
        return json.load(response)

def _admit(req: dict, state: dict, detail: dict) -> dict:
    """No worker RPC is permitted without a fresh, unchanged actionable PRE."""
    if not isinstance(req, dict) or set(req) != {"task_id", "step_key", "action", "data_b64"}:
        raise DispatchDenied("UNREGISTERED_OR_UNSUPPORTED_AGENT_OPERATION")
    action=req["action"]
    if not isinstance(action, dict) or not isinstance(req["task_id"],str) or not isinstance(req["step_key"],str):
        raise DispatchDenied("INVALID_AGENT_ACTION")
    klass=(action.get("action_type"),action.get("effect_class"),
           action.get("reversible"),action.get("real_world_effect"))
    if klass not in (("read","E0",False,False),("write","E2",True,False)):
        raise DispatchDenied("UNSUPPORTED_EXECUTOR_CAPABILITY")
    if state.get("status") in ("PAUSED","RECOVERY_PENDING"):
        raise DispatchDenied("AGENT_GATE_PAUSED_OR_RECOVERY")
    if state.get("current_step") != req["step_key"] or detail.get("task",{}).get("contract_status") != "OPEN":
        raise DispatchDenied("AGENT_STEP_NOT_ADMITTED")
    gate=state.get("pending_execution_gate")
    latest=state.get("latest_checkpoint")
    if not isinstance(gate,dict) or not isinstance(latest,dict) or latest.get("verdict")!="READY_TO_EXECUTE":
        raise DispatchDenied("EG_PRE_NOT_READY")
    if gate.get("action_fingerprint")!=fingerprint(action) or gate.get("pre_checkpoint_no")!=latest.get("checkpoint_no"):
        raise DispatchDenied("EG_GATE_OR_ACTION_MISMATCH")
    record=next((x for x in detail.get("checkpoints",[])
                 if x.get("checkpoint_no")==gate["pre_checkpoint_no"]),None)
    if not record or record.get("verdict")!="READY_TO_EXECUTE" or not gate_allows_new_effect(record["created_at"]):
        raise DispatchDenied("EG_GATE_EXPIRED_OR_INVALID")
    return record

def dispatch(request: dict, *, eg_url: str, api_key: str, worker_socket: str,
             executor_public_key_b64: str) -> dict:
    if not isinstance(request,dict) or set(request)!={"task_id","step_key","action","data_b64"}:
        raise DispatchDenied("INVALID_DISPATCH_REQUEST")
    task=request["task_id"]
    if not isinstance(task,str) or not task or len(task)>127 or any(x in task for x in "/?#"):
        raise DispatchDenied("INVALID_TASK_ID")
    state=_get(eg_url,api_key,task,"/state")
    detail=_get(eg_url,api_key,task,"")
    gate=_admit(request,state,detail)
    payload=(json.dumps(request,separators=(",",":"),sort_keys=True)+"\n").encode()
    if len(payload)>1024*1024:
        raise DispatchDenied("RPC_PAYLOAD_TOO_LARGE")
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
        sock.settimeout(15)
        sock.connect(str(Path(worker_socket)))
        sock.sendall(payload)
        chunks=[];total=0
        while True:
            part=sock.recv(65536)
            if not part:break
            total+=len(part)
            if total>1024*1024:raise DispatchDenied("WORKER_RESPONSE_TOO_LARGE")
            chunks.append(part)
            if b"\n" in part:break
    raw=b"".join(chunks)
    if not raw.endswith(b"\n"):
        raise DispatchDenied("INCOMPLETE_WORKER_RECEIPT")
    answer=json.loads(raw)
    if answer.get("status")!="PASS":
        raise DispatchDenied("WORKER_DENIED:"+str(answer.get("reason","unknown")))
    receipt=answer.get("receipt")
    valid,reason=verify(receipt,public_b64=executor_public_key_b64,
                        task_id=task,step_key=request["step_key"],
                        gate_checkpoint_no=gate["checkpoint_no"],
                        action_fingerprint=fingerprint(request["action"]),
                        target=request["action"]["target"],
                        gate_created_at=gate["created_at"])
    if not valid:raise DispatchDenied(reason)
    # The caller must submit fresh result evidence and this exact receipt to
    # the canonical EG POST gate; a successful dispatcher return is NOT VERIFIED.
    return {"status":"RECEIPT_VERIFIED_POST_REQUIRED","execution_receipt":receipt,
            "gate_checkpoint_no":gate["checkpoint_no"]}
