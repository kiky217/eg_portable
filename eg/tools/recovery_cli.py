#!/usr/bin/env python3
"""Operator-only read-only recovery diagnosis for a pinned external EG adapter.

Never replays an effect, signs a receipt, modifies EG, or submits POST.
Run under the independently provisioned worker's private journal identity.
"""
from __future__ import annotations
import argparse,json,os,stat
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request,urlopen
from tools.durable_hitl_ledger import ApprovalLedger
from tools.recovery_inspector import inspect

class RecoveryCliDenied(RuntimeError):pass

def _private_file(path,*,max_bytes=131072):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        row=os.fstat(fd)
        if (not stat.S_ISREG(row.st_mode) or row.st_uid!=os.getuid()
            or stat.S_IMODE(row.st_mode)&0o077 or row.st_nlink!=1):
            raise RecoveryCliDenied("UNSAFE_PRIVATE_RECOVERY_INPUT")
        value=os.read(fd,max_bytes+1)
        if not value or len(value)>max_bytes:
            raise RecoveryCliDenied("INVALID_RECOVERY_INPUT_LENGTH")
        return value
    finally:os.close(fd)

def _get(base,key,task,suffix):
    request=Request(base.rstrip("/")+"/v1/tasks/"+task+suffix,
                    headers={"X-Evaluation-Key":key})
    with urlopen(request,timeout=6) as response:
        return json.load(response)

def inspect_live(*,eg_url,api_key_file,journal_dir,task_id,step_key,adapter_id,
                 approval_nonce,action_file):
    url=urlsplit(eg_url)
    if (url.username or url.password or url.query or url.fragment
        or not (url.scheme=="https" or
           (url.scheme=="http" and url.hostname in ("localhost","127.0.0.1")))
        or not isinstance(task_id,str) or not task_id or len(task_id)>127
        or any(x in task_id for x in "/?#")):
        raise RecoveryCliDenied("UNTRUSTED_CANONICAL_GATEWAY")
    key=_private_file(api_key_file,max_bytes=4096).decode("utf-8").strip()
    action=json.loads(_private_file(action_file))
    if not isinstance(action,dict):
        raise RecoveryCliDenied("INVALID_RECOVERY_ACTION")
    ledger=ApprovalLedger(journal_dir)
    state=_get(eg_url,key,task_id,"/state")
    detail=_get(eg_url,key,task_id,"")
    return inspect(task_id=task_id,step_key=step_key,action=action,
                   approval_nonce=approval_nonce,adapter_id=adapter_id,
                   eg_state=state,eg_detail=detail,ledger=ledger)

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("eg-url","api-key-file","journal-dir","task-id","step-key",
                 "adapter-id","approval-nonce","action-file"):
        p.add_argument("--"+name,required=True)
    a=p.parse_args(argv)
    try:
        report=inspect_live(eg_url=a.eg_url,api_key_file=a.api_key_file,
            journal_dir=a.journal_dir,task_id=a.task_id,step_key=a.step_key,
            adapter_id=a.adapter_id,approval_nonce=a.approval_nonce,
            action_file=a.action_file)
    except (OSError,ValueError,RecoveryCliDenied) as exc:
        p.error("recovery inspection denied: "+type(exc).__name__)
    print(json.dumps(report,sort_keys=True,separators=(",",":")))
    return 0 if report["status"] in ("VERIFIED_EFFECT","POST_VERIFIED") else 3

if __name__=="__main__":
    raise SystemExit(main())
