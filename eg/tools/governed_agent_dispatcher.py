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


def dispatch_disposable_ci(*, task_id: str, step_key: str, action: dict,
                           approval: dict, data: bytes, adapter,
                           eg_url: str, api_key: str, hitl_public_key_b64: str,
                           executor_public_key_b64: str,
                           operation: str = "execute", ci_only: bool = False) -> dict:
    """Repository CI-only E3-E5 adapter pathway, not a production transport.

    Production requires a separately administered authenticated executor
    RPC/trust domain. Arbitrary shell execution is never permitted here.
    """
    import hashlib
    from tools.disposable_effect_adapter import DisposableAdapter
    from tools.high_effect_admission import action_fingerprint
    from tools.signed_hitl_approval import verify_approval
    if not ci_only or type(adapter) is not DisposableAdapter:
        raise DispatchDenied("HIGH_EFFECT_PRODUCTION_TRANSPORT_NOT_PROVISIONED")
    if operation not in ("execute","compensate") or not isinstance(data,bytes):
        raise DispatchDenied("INVALID_HIGH_EFFECT_OPERATION")
    if not isinstance(action,dict) or action.get("effect_class") not in ("E3","E4","E5") or adapter.effect_class!=action["effect_class"]:
        raise DispatchDenied("HIGH_EFFECT_CLASS_MISMATCH")
    if operation=="compensate" and (adapter.effect_class=="E5" or data):
        raise DispatchDenied("HIGH_EFFECT_COMPENSATION_DENIED")
    if operation=="execute" and (not data or action.get("payload_sha256")!=hashlib.sha256(data).hexdigest()
                                or action.get("payload_bytes")!=len(data)):
        raise DispatchDenied("HIGH_EFFECT_PAYLOAD_NOT_BOUND")
    state=_get(eg_url,api_key,task_id,"/state")
    detail=_get(eg_url,api_key,task_id,"")
    gate=state.get("pending_execution_gate")
    latest=state.get("latest_checkpoint")
    fp=action_fingerprint(action)
    if (state.get("status")!="IN_PROGRESS" or state.get("current_step")!=step_key or
        detail.get("task",{}).get("contract_status")!="OPEN" or
        not isinstance(gate,dict) or not isinstance(latest,dict) or
        gate.get("task_id")!=task_id or gate.get("step_key")!=step_key or
        gate.get("verdict")!="READY_TO_EXECUTE" or not gate.get("hitl_approved") or
        gate.get("action_fingerprint")!=fp or
        latest.get("checkpoint_no")!=gate.get("checkpoint_no") or
        latest.get("verdict")!="READY_TO_EXECUTE"):
        raise DispatchDenied("HIGH_EFFECT_CANONICAL_PRE_DENIED")
    checkpoint=gate["checkpoint_no"]
    record=next((r for r in detail.get("checkpoints",[]) if r.get("checkpoint_no")==checkpoint),None)
    if not record or record.get("verdict")!="READY_TO_EXECUTE" or not gate_allows_new_effect(record["created_at"]):
        raise DispatchDenied("HIGH_EFFECT_PRE_LEASE_DENIED")
    verify_approval(approval,hitl_public_key_b64,task_id=task_id,step_key=step_key,
                    gate_checkpoint_no=checkpoint,action_fingerprint=fp,
                    adapter_id=adapter.adapter_id)
    args=dict(task_id=task_id,step_key=step_key,gate_checkpoint_no=checkpoint,
              gate_created_at=record["created_at"],action=action,approval=approval,
              hitl_public_key_b64=hitl_public_key_b64,ready_gate=gate)
    result=(adapter.execute(**args,data=data) if operation=="execute"
            else adapter.compensate(**args))
    receipt=result["receipt"]
    valid,reason=verify(receipt,public_b64=executor_public_key_b64,task_id=task_id,
                        step_key=step_key,gate_checkpoint_no=checkpoint,
                        action_fingerprint=fp,target=action["target"],
                        gate_created_at=record["created_at"])
    if not valid:
        raise DispatchDenied("HIGH_EFFECT_RECEIPT_INVALID:"+str(reason))
    return {"status":"RECEIPT_VERIFIED_POST_REQUIRED","execution_receipt":receipt,
            "gate_checkpoint_no":checkpoint}


def dispatch_action(request: dict, *, eg_url: str, api_key: str,
                    executor_public_key_b64: str, worker_socket: str | None = None,
                    ci_only: bool = False, disposable_adapter=None,
                    hitl_approval: dict | None = None,
                    hitl_public_key_b64: str | None = None,
                    operation: str = "execute") -> dict:
    """Single fail-closed agent-facing action contract for bounded E0-E5.

    E0/E2 use independently privileged Unix-socket worker. E3/E4/E5 route
    solely to explicitly supplied CI-only disposable adapter; there is no
    production high-effect executor transport or shell fallback yet.
    """
    import base64
    if not isinstance(request,dict) or set(request)!={"task_id","step_key","action","data_b64"}:
        raise DispatchDenied("INVALID_DISPATCH_REQUEST")
    action=request["action"]
    if not isinstance(action,dict) or not isinstance(request["data_b64"],str):
        raise DispatchDenied("INVALID_DISPATCH_ACTION")
    effect=action.get("effect_class")
    if effect in ("E3","E4","E5"):
        if not ci_only or disposable_adapter is None or not hitl_approval or not hitl_public_key_b64:
            raise DispatchDenied("HIGH_EFFECT_PRODUCTION_TRANSPORT_NOT_PROVISIONED")
        try:
            data=base64.b64decode(request["data_b64"],validate=True)
        except (ValueError,TypeError) as exc:
            raise DispatchDenied("INVALID_HIGH_EFFECT_BASE64_PAYLOAD") from exc
        return dispatch_disposable_ci(task_id=request["task_id"],step_key=request["step_key"],
                 action=action,data=data,approval=hitl_approval,adapter=disposable_adapter,
                 eg_url=eg_url,api_key=api_key,hitl_public_key_b64=hitl_public_key_b64,
                 executor_public_key_b64=executor_public_key_b64,operation=operation,ci_only=True)
    if operation!="execute" or ci_only or disposable_adapter is not None:
        raise DispatchDenied("UNSUPPORTED_EXECUTION_TRANSPORT")
    if not worker_socket:
        raise DispatchDenied("INDEPENDENT_E0_E2_WORKER_SOCKET_REQUIRED")
    return dispatch(request,eg_url=eg_url,api_key=api_key,
                    worker_socket=worker_socket,
                    executor_public_key_b64=executor_public_key_b64)
