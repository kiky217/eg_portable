"""CI-only out-of-process E3-E5 sandbox executor; no host service RPC.

The worker independently reads canonical EG PRE, verifies scoped signed HITL,
uses durable single-use effect journal, and returns a signed receipt. An agent
cannot supply its own READY gate, replace target scope, or submit shell.
"""
from __future__ import annotations

import argparse
import base64
import hmac
import json
import os
import socket
import stat
import struct
from pathlib import Path
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from urllib.request import Request,urlopen

from tools.adapter_attestation_worker import _read_private_key,_private_directory
from tools.adapter_liveness import canon
from tools.disposable_effect_adapter import DisposableAdapter,EffectDenied
from tools.high_effect_admission import action_fingerprint
from tools.trusted_execution_worker import gate_allows_new_effect


class RpcDenied(RuntimeError): pass


def _secret_file(path):
    path=Path(path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid()
            or stat.S_IMODE(info.st_mode)&0o077 or info.st_nlink!=1):
            raise RpcDenied("UNSAFE_WORKER_EG_CREDENTIAL")
        data=os.read(fd,4096)
        if not data or len(data)>2048:raise RpcDenied("INVALID_WORKER_EG_CREDENTIAL")
        return data.decode().strip()
    finally: os.close(fd)


def eg_get(url,key,task,suffix):
    if not isinstance(task,str) or not task or len(task)>127 or any(ch in task for ch in "/?#"):
        raise RpcDenied("INVALID_TASK_ID")
    request=Request(url.rstrip("/")+"/v1/tasks/"+task+suffix,
                    headers={"X-Evaluation-Key":key})
    with urlopen(request,timeout=4) as response:
        return json.load(response)


def execute_once(request,*,adapter,eg_url,eg_key,hitl_key):
    """No caller-supplied admission; worker fetches live task state itself."""
    if not isinstance(request,dict) or set(request)!={"task_id","step_key","action",
                                                       "approval","data_b64","operation"}:
        raise RpcDenied("UNSUPPORTED_RPC_SCHEMA")
    task,step=request["task_id"],request["step_key"]
    action,approval=request["action"],request["approval"]
    op=request["operation"]
    if (not isinstance(task,str) or not isinstance(step,str)
        or not isinstance(action,dict) or not isinstance(approval,dict)
        or not isinstance(request["data_b64"],str) or op not in ("execute","compensate","no_effect")):
        raise RpcDenied("INVALID_RPC_FIELDS")
    try: data=base64.b64decode(request["data_b64"],validate=True)
    except (TypeError,ValueError) as exc:raise RpcDenied("INVALID_PAYLOAD_ENCODING") from exc
    if (op!="execute" and data) or len(data)>524288:
        raise RpcDenied("INVALID_EFFECT_PAYLOAD")
    state=eg_get(eg_url,eg_key,task,"/state")
    detail=eg_get(eg_url,eg_key,task,"")
    gate=state.get("pending_execution_gate")
    latest=state.get("latest_checkpoint")
    fp=action_fingerprint(action)
    if (state.get("status")!="IN_PROGRESS" or state.get("current_step")!=step
        or detail.get("task",{}).get("contract_status")!="OPEN"
        or not isinstance(gate,dict) or not isinstance(latest,dict)
        or gate.get("task_id")!=task or gate.get("step_key")!=step
        or gate.get("verdict")!="READY_TO_EXECUTE" or not gate.get("hitl_approved")
        or gate.get("action_fingerprint")!=fp
        or gate.get("checkpoint_no")!=latest.get("checkpoint_no")
        or latest.get("verdict")!="READY_TO_EXECUTE"):
        raise RpcDenied("CANONICAL_EG_PRE_NOT_READY")
    # Never physically execute with a key different from the original
    # HMAC-audited PRE signer. A later POST rejection cannot undo an effect.
    pin=gate.get("high_effect_pin")
    worker_key=base64.b64encode(adapter.private.public_key().public_bytes(
        Encoding.Raw,PublicFormat.Raw)).decode()
    if (not isinstance(pin,dict) or
        set(pin)!={"adapter_id","public_key_b64","action_fingerprint","approval_nonce"} or
        not isinstance(pin["public_key_b64"],str) or
        not isinstance(pin["adapter_id"],str) or
        not isinstance(pin["approval_nonce"],str) or
        not hmac.compare_digest(pin["public_key_b64"],worker_key) or
        not hmac.compare_digest(pin["adapter_id"],adapter.adapter_id) or
        pin["action_fingerprint"]!=fp or
        pin["approval_nonce"]!=approval.get("nonce")):
        raise RpcDenied("ORIGINAL_PRE_EXECUTOR_IDENTITY_MISMATCH")
    cp=gate["checkpoint_no"]
    record=next((r for r in detail.get("checkpoints",[])
                 if r.get("checkpoint_no")==cp),None)
    if not record or not gate_allows_new_effect(record.get("created_at","")):
        raise RpcDenied("EG_PRE_LEASE_INVALID")
    args=dict(task_id=task,step_key=step,gate_checkpoint_no=cp,
              gate_created_at=record["created_at"],action=action,
              approval=approval,hitl_public_key_b64=hitl_key,ready_gate=gate)
    if op=="execute":return adapter.execute(**args,data=data)
    if op=="compensate":return adapter.compensate(**args)
    return {"status":"NOT_EXECUTED","proof":adapter.reconcile_no_effect(
                task_id=task,step_key=step,gate_checkpoint_no=cp,
                action=action,approval=approval,hitl_public_key_b64=hitl_key,
                ready_gate=gate)}


def serve(*,socket_path,output_root,ledger_root,private_key_path,eg_url,eg_api_key_file,
          adapter_id,effect_class,hitl_public_key_b64,controller_uid,max_requests=0):
    """GitHub CI/test sandbox ONLY; no production or host-service effects."""
    if not (eg_url.startswith("http://127.0.0.1:") or eg_url.startswith("https://")):
        raise RpcDenied("EG_URL_NOT_TRUSTED")
    path=Path(socket_path)
    _private_directory(path.parent)
    _private_directory(Path(output_root))
    _private_directory(Path(ledger_root))
    if path.exists() or path.is_symlink():raise RpcDenied("SOCKET_ALREADY_EXISTS")
    if type(controller_uid) is not int or controller_uid<0:raise RpcDenied("CONTROLLER_UID_INVALID")
    key=_read_private_key(private_key_path)
    eg_key=_secret_file(eg_api_key_file)
    adapter=DisposableAdapter(output_root,ledger_root,key,adapter_id,effect_class)
    old_umask=os.umask(0o077)
    count=0
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
            try:
                server.bind(str(path));os.chmod(path,0o600)
                inode=path.lstat().st_ino
                server.listen(8)
                while not max_requests or count<max_requests:
                    with server.accept()[0] as client:
                        count+=1
                        client.settimeout(6)
                        try:
                            cred=client.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,
                                                    struct.calcsize("3i"))
                            if struct.unpack("3i",cred)[1]!=controller_uid:
                                raise RpcDenied("UNTRUSTED_RPC_CALLER_UID")
                            with client.makefile("rb") as stream:
                                payload=stream.readline(1048577)
                            if not payload.endswith(b"\n") or len(payload)>1048576:
                                raise RpcDenied("RPC_PAYLOAD_TOO_LARGE")
                            result=execute_once(json.loads(payload),adapter=adapter,
                                                eg_url=eg_url,eg_key=eg_key,
                                                hitl_key=hitl_public_key_b64)
                            reply={"status":"PASS","result":result}
                        except Exception as exc:
                            reply={"status":"DENIED","reason":type(exc).__name__}
                        client.sendall(canon(reply)+b"\n")
            finally:
                if path.exists() and not path.is_symlink() and path.lstat().st_ino==inode:
                    path.unlink()
    finally:os.umask(old_umask)


def main():
    p=argparse.ArgumentParser(description="CI-only bounded independent effect worker")
    for field in ("socket","output-root","ledger-root","private-key",
                  "eg-url","eg-api-key-file","adapter-id","effect-class",
                  "hitl-public-key-b64"):
        p.add_argument("--"+field,required=True)
    p.add_argument("--controller-uid",type=int,required=True)
    p.add_argument("--max-requests",type=int,default=0)
    x=p.parse_args()
    serve(socket_path=x.socket,output_root=x.output_root,ledger_root=x.ledger_root,
          private_key_path=x.private_key,eg_url=x.eg_url,eg_api_key_file=x.eg_api_key_file,
          adapter_id=x.adapter_id,effect_class=x.effect_class,
          hitl_public_key_b64=x.hitl_public_key_b64,
          controller_uid=x.controller_uid,max_requests=x.max_requests)

if __name__=="__main__":main()
