"""Generic independently operated high-effect RPC host (E3-E5).

The host never provisions its own signer, approval or runtime identity.
The independent operator instantiates the adapter and starts this host as
a distinct non-root OS user; no untrusted dynamic class imports or shell.
"""
from __future__ import annotations
import base64,hashlib,hmac,json,os,socket,stat,struct
from pathlib import Path
from tools.private_unix_socket import private_socket_lease
from urllib.parse import urlsplit
from urllib.request import Request
from tools.no_redirect_http import urlopen
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from tools.high_effect_admission import action_fingerprint
from tools.signed_hitl_approval import verify_approval
from tools.trusted_execution_worker import gate_allows_new_effect
from tools.adapter_liveness import attest,canon
from app.execution_receipts import verify as verify_receipt

class TrustedRpcDenied(RuntimeError):pass

def _get(url,key,task,suffix):
    if not isinstance(task,str) or not task or len(task)>127 or any(x in task for x in "/?#"):
        raise TrustedRpcDenied("INVALID_TASK")
    req=Request(url.rstrip("/")+"/v1/tasks/"+task+suffix,
                headers={"X-Evaluation-Key":key})
    with urlopen(req,timeout=5) as response:
        return json.load(response)

def dispatch_once(request,*,adapter,eg_url,eg_key,hitl_public_key_b64):
    """Fetch original EG state before issuing a single physical effect."""
    if not isinstance(request,dict) or set(request)!={"task_id","step_key",
                          "action","approval","data_b64","operation"}:
        raise TrustedRpcDenied("INVALID_RPC_SCHEMA")
    task,step=request["task_id"],request["step_key"]
    action,approval=request["action"],request["approval"]
    if (request["operation"] not in ("execute","recover_receipt") or not isinstance(action,dict)
        or not isinstance(approval,dict) or not isinstance(step,str)
        or not 1<=len(step)<=18 or not isinstance(request["data_b64"],str)
        or action.get("effect_class") not in ("E3","E4","E5")):
        raise TrustedRpcDenied("INVALID_EFFECT_REQUEST")
    try:data=base64.b64decode(request["data_b64"],validate=True)
    except Exception as exc:raise TrustedRpcDenied("INVALID_EFFECT_BYTES") from exc
    if ((request["operation"]=="execute" and
         (not data or len(data)>524288 or action.get("payload_bytes")!=len(data) or
          action.get("payload_sha256")!=hashlib.sha256(data).hexdigest()))
        or (request["operation"]=="recover_receipt" and data)):
        raise TrustedRpcDenied("EFFECT_PAYLOAD_NOT_BOUND")
    state=_get(eg_url,eg_key,task,"/state")
    detail=_get(eg_url,eg_key,task,"")
    gate=state.get("pending_execution_gate")
    latest=state.get("latest_checkpoint")
    fp=action_fingerprint(action)
    if (state.get("status") not in (("IN_PROGRESS","RECOVERY_PENDING") if request["operation"]=="recover_receipt" else ("IN_PROGRESS",)) or state.get("current_step")!=step
        or detail.get("task",{}).get("contract_status")!="OPEN"
        or not isinstance(gate,dict) or not isinstance(latest,dict)
        or gate.get("task_id")!=task or gate.get("step_key")!=step
        or gate.get("verdict")!="READY_TO_EXECUTE" or not gate.get("hitl_approved")
        or gate.get("action_fingerprint")!=fp
        or gate.get("checkpoint_no")!=latest.get("checkpoint_no")
        or latest.get("verdict")!="READY_TO_EXECUTE"):
        raise TrustedRpcDenied("CANONICAL_PRE_NOT_READY")
    public=base64.b64encode(adapter.private.public_key().public_bytes(
         Encoding.Raw,PublicFormat.Raw)).decode()
    pin=gate.get("high_effect_pin")
    if (not isinstance(pin,dict)
        or set(pin)!={"adapter_id","public_key_b64","action_fingerprint","approval_nonce"}
        or not hmac.compare_digest(pin["adapter_id"],adapter.adapter_id)
        or not hmac.compare_digest(pin["public_key_b64"],public)
        or pin["action_fingerprint"]!=fp
        or pin["approval_nonce"]!=approval.get("nonce")):
        raise TrustedRpcDenied("PINNED_INDEPENDENT_WORKER_MISMATCH")
    cp=gate["checkpoint_no"]
    record=next((r for r in detail.get("checkpoints",[])
                 if r.get("checkpoint_no")==cp),None)
    if (not record or record.get("verdict")!="READY_TO_EXECUTE" or
        (request["operation"]=="execute" and
         not gate_allows_new_effect(record.get("created_at","")))):
        raise TrustedRpcDenied("PRE_LEASE_INVALID")
    # Recovery is read-only: verify the original signed approval's time window,
    # not the current time, then require the original durable sealed receipt.
    approval_time=(approval.get("issued_at") if request["operation"]=="recover_receipt"
                   else None)
    verify_approval(approval,hitl_public_key_b64,task_id=task,step_key=step,
                    gate_checkpoint_no=cp,action_fingerprint=fp,
                    adapter_id=adapter.adapter_id,now=approval_time)
    if request["operation"]=="recover_receipt":
        journal=getattr(adapter,"ledger",None)
        if journal is None or not hasattr(journal,"read_sealed_receipt"):
            raise TrustedRpcDenied("RECOVERY_JOURNAL_UNAVAILABLE")
        receipt=journal.read_sealed_receipt(approval["nonce"],task_id=task,
            step_key=step,gate_checkpoint_no=cp,action_fingerprint=fp,
            adapter_id=adapter.adapter_id)
        if receipt is None:
            raise TrustedRpcDenied("UNPROVEN_UNKNOWN_EFFECT_NO_REPLAY")
        valid,reason=verify_receipt(receipt,public_b64=public,task_id=task,
            step_key=step,gate_checkpoint_no=cp,action_fingerprint=fp,
            target=action["target"],gate_created_at=record["created_at"])
        if (not valid or receipt.get("nonce")!=approval["nonce"] or
            receipt.get("executor_id")!="trusted-worker-"+adapter.adapter_id):
            raise TrustedRpcDenied("RECOVERED_RECEIPT_INVALID:"+reason)
        return {"status":"RECOVERED_POST_REQUIRED","receipt":receipt}
    response=adapter.execute(task_id=task,step_key=step,action=action,
                    approval=approval,gate=gate,gate_created_at=record["created_at"],
                    stdin=data)
    if not isinstance(response,dict) or "receipt" not in response:
        raise TrustedRpcDenied("INDEPENDENT_RECEIPT_MISSING")
    return {"status":response.get("status"),"receipt":response["receipt"]}

def serve(*,socket_path,adapter,capability_sha256,eg_url,eg_key,
          hitl_public_key_b64,controller_uid,max_requests=0,controller_group_gid=None):
    """Called ONLY by separately provisioned, non-root operator worker."""
    loc=urlsplit(eg_url)
    if (os.getuid()<=0 or type(controller_uid) is not int or controller_uid<0
        or controller_uid==os.getuid()
        or not (loc.scheme=="https" or
             (loc.scheme=="http" and loc.hostname in ("localhost","127.0.0.1")))
        or loc.username or loc.password or loc.query or loc.fragment
        or not isinstance(eg_key,str) or not eg_key
        or not isinstance(capability_sha256,str) or len(capability_sha256)!=64
        or any(x not in "0123456789abcdef" for x in capability_sha256)):
        raise TrustedRpcDenied("INDEPENDENT_RUNTIME_NOT_PROVISIONED")
    path=Path(socket_path)
    if not path.is_absolute() or not path.parent.is_dir():
        raise TrustedRpcDenied("SOCKET_PATH_NOT_PRIVATE_OR_OCCUPIED")
    parent=path.parent.stat()
    if parent.st_uid!=os.getuid():
        raise TrustedRpcDenied("UNSAFE_WORKER_SOCKET_DIRECTORY")
    if controller_group_gid is None:
        if stat.S_IMODE(parent.st_mode)&0o077:
            raise TrustedRpcDenied("UNSAFE_WORKER_SOCKET_DIRECTORY")
    elif (type(controller_group_gid) is not int or controller_group_gid<=0
          or parent.st_gid!=controller_group_gid
          or not parent.st_mode & stat.S_ISGID
          or stat.S_IMODE(parent.st_mode)&0o067):
        # Group may traverse, never write. A pinned controller UID and SO_PEERCRED
        # still check every connection before any sensitive request is processed.
        raise TrustedRpcDenied("UNSAFE_SHARED_SOCKET_DIRECTORY")
    if not getattr(adapter,"adapter_id","").startswith("trusted-adapter-"):
        raise TrustedRpcDenied("INVALID_ADAPTER")
    old=os.umask(0o077)
    try:
        with private_socket_lease(path), socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
            server.bind(str(path))
            os.chmod(path,0o660 if controller_group_gid is not None else 0o600)
            inode=path.stat().st_ino
            try:
                server.listen(8)
                count=0
                while not max_requests or count<max_requests:
                    with server.accept()[0] as peer:
                        count+=1
                        peer.settimeout(6)
                        try:
                            creds=peer.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,
                                                 struct.calcsize("3i"))
                            if struct.unpack("3i",creds)[1]!=controller_uid:
                                raise TrustedRpcDenied("UNTRUSTED_RPC_CALLER_UID")
                            with peer.makefile("rb") as stream:
                                raw=stream.readline(1048577)
                            if not raw.endswith(b"\n") or len(raw)>1048576:
                                raise TrustedRpcDenied("RPC_REQUEST_OVERSIZE")
                            packet=json.loads(raw)
                            if packet.get("operation")=="attest":
                                if set(packet)!={"operation","challenge"}:
                                    raise TrustedRpcDenied("INVALID_ATTEST_REQUEST")
                                reply=attest(packet["challenge"],adapter_id=adapter.adapter_id,
                                              capability_sha256=capability_sha256,
                                              private_key=adapter.private)
                            else:
                                response=dispatch_once(packet,adapter=adapter,eg_url=eg_url,
                                        eg_key=eg_key,hitl_public_key_b64=hitl_public_key_b64)
                                reply={"status":"PASS","result":response}
                        except Exception as exc:
                            reply={"status":"DENIED","reason":type(exc).__name__}
                        peer.sendall(canon(reply)+b"\n")
            finally:
                if path.exists() and not path.is_symlink() and path.stat().st_ino==inode:
                    path.unlink()
    finally:os.umask(old)
