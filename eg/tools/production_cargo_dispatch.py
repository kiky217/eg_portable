"""Controller-side bounded execution RPC; NEVER constructs HITL authority.
Only uses a canonical PRE gate and independently checks the signed worker receipt."""
import json,socket,stat,struct
from pathlib import Path
from app.execution_receipts import verify as verify_receipt
from tools.high_effect_admission import action_fingerprint
class DispatchDenied(RuntimeError):pass
def dispatch(*,socket_path,task_id,step_key,action,approval,ready_gate,
             executor_public_key_b64,expected_worker_uid):
 if (not isinstance(ready_gate,dict) or ready_gate.get("verdict")!="READY_TO_EXECUTE"
     or ready_gate.get("task_id")!=task_id or ready_gate.get("step_key")!=step_key
     or ready_gate.get("action_fingerprint")!=action_fingerprint(action)):
  raise DispatchDenied("CANONICAL_PRE_REQUIRED")
 cp=ready_gate.get("checkpoint_no")
 if type(cp) is not int or cp<1:raise DispatchDenied("INVALID_PRE_CHECKPOINT")
 target=action.get("target")
 if not isinstance(target,str):raise DispatchDenied("INVALID_TARGET")
 if type(expected_worker_uid) is not int or expected_worker_uid<0:
  raise DispatchDenied("EXPECTED_WORKER_UID_REQUIRED")
 path=Path(socket_path)
 if path.is_symlink() or not stat.S_ISSOCK(path.stat().st_mode):
  raise DispatchDenied("INVALID_SOCKET")
 request={"task_id":task_id,"step_key":step_key,"action":action,"approval":approval}
 payload=json.dumps(request,sort_keys=True,separators=(",",":")).encode()
 if len(payload)>16300:raise DispatchDenied("REQUEST_OVERSIZE")
 try:
  with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
   conn.settimeout(5)
   conn.connect(str(path))
   if not hasattr(socket,"SO_PEERCRED"):
    raise DispatchDenied("SO_PEERCRED_UNAVAILABLE")
   pid,uid,gid=struct.unpack("3i",conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
   if uid!=expected_worker_uid or pid<=0:
    raise DispatchDenied("WORKER_PEER_IDENTITY_MISMATCH")
   conn.sendall(payload+b"\n")
   response=bytearray()
   while b"\n" not in response:
    fragment=conn.recv(4096)
    if not fragment or len(response)+len(fragment)>16384:
     raise DispatchDenied("MISSING_OR_OVERSIZE_RECEIPT")
    response.extend(fragment)
  result=json.loads(response.split(b"\n",1)[0])
 except (OSError,ValueError,TypeError) as exc:
  raise DispatchDenied("WORKER_TRANSPORT_UNAVAILABLE") from exc
 if result.get("status")!="EXECUTED_POST_REQUIRED" or not isinstance(result.get("receipt"),dict):
  raise DispatchDenied("WORKER_DID_NOT_EXECUTE")
 receipt=result["receipt"]
 ok,reason=verify_receipt(receipt,public_b64=executor_public_key_b64,task_id=task_id,
    step_key=step_key,gate_checkpoint_no=cp,action_fingerprint=action_fingerprint(action),
    target=target,gate_created_at=ready_gate.get("created_at"))
 if not ok:raise DispatchDenied(reason)
 return {"status":"SIGNED_RECEIPT_VERIFIED_POST_REQUIRED","receipt":receipt}
