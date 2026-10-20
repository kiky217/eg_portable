"""Bounded GitHub Contents API primitive for a separately governed EG worker.

Does not authorize action, hold durable idempotency journal, or sign receipts.
Never infer a verified physical effect from the GitHub API acknowledgement.
"""
from __future__ import annotations
import base64,json,re
from urllib.parse import quote
from urllib.request import Request,urlopen
from tools.github_effect_scope import validate_operation

_SHA=re.compile(r"^[0-9a-f]{40}$")

class GitHubTransportDenied(RuntimeError):pass

def contents_put(operation:dict,policy:dict,content:bytes,*,token:str,
                 commit_message:str,opener=urlopen)->dict:
    op=validate_operation(operation,policy)
    if (not isinstance(content,bytes) or not content or len(content)>512*1024 or
        not isinstance(token,str) or not token.strip() or "\r" in token or "\n" in token or
        not isinstance(commit_message,str) or not 1<=len(commit_message)<=180 or
        any(c in commit_message for c in "\r\n")):
        raise GitHubTransportDenied("INVALID_GITHUB_WRITE_INPUT")
    url="https://api.github.com/repos/"+op["repository"]+"/contents/"+quote(op["path"],safe="/")
    payload={"message":commit_message,"content":base64.b64encode(content).decode(),
             "branch":op["branch"]}
    if op["operation"]=="update_file":payload["sha"]=op["expected_blob_sha"]
    req=Request(url,data=json.dumps(payload,separators=(",",":")).encode(),method="PUT",
        headers={"Authorization":"Bearer "+token,"Accept":"application/vnd.github+json",
                 "Content-Type":"application/json","X-GitHub-Api-Version":"2022-11-28"})
    try:
        with opener(req,timeout=15) as response:
            raw=response.read(131073)
        if len(raw)>131072:raise ValueError("oversized")
        result=json.loads(raw)
        commit=result.get("commit") if isinstance(result,dict) else None
        item=result.get("content") if isinstance(result,dict) else None
        sha=commit.get("sha") if isinstance(commit,dict) else None
        blob=item.get("sha") if isinstance(item,dict) else None
        if (not isinstance(sha,str) or not _SHA.fullmatch(sha) or
            not isinstance(blob,str) or not _SHA.fullmatch(blob) or
            item.get("path")!=op["path"]):
            raise ValueError("incomplete")
    except Exception as exc:
        raise GitHubTransportDenied("UNKNOWN_EFFECT_RECONCILIATION_REQUIRED") from exc
    return {"status":"GITHUB_ACK_RECONCILE_BEFORE_RECEIPT","commit_sha":sha,
            "blob_sha":blob,"repository":op["repository"],"path":op["path"],
            "branch":op["branch"]}
