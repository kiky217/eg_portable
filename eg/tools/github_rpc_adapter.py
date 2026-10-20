"""Operator-pinned GitHub E4 adapter through the generic independent RPC host.

No shell, dynamic API endpoint, agent-selected credential, or self-authorization.
Exact canonical wire bytes are included in the original signed EG PRE action.
"""
from __future__ import annotations
import base64,binascii,json
from tools.trusted_github_effect import TrustedGitHubEffect,GitHubWorkerDenied

class GithubRpcWireDenied(ValueError):pass

def wire_bytes(*,operation,content,commit_message):
    if not isinstance(content,bytes) or not content or len(content)>400000:
        raise GithubRpcWireDenied("INVALID_GITHUB_WIRE_CONTENT")
    packet={"version":1,"operation":operation,"content_b64":base64.b64encode(content).decode(),
            "commit_message":commit_message}
    raw=json.dumps(packet,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
    if len(raw)>524288:raise GithubRpcWireDenied("GITHUB_WIRE_OVERSIZE")
    return raw

def _unique_pairs(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise GithubRpcWireDenied("DUPLICATE_GITHUB_WIRE_FIELD")
        result[key]=value
    return result

class GitHubRpcAdapter:
    """Binds operator-controlled TrustedGitHubEffect to E3-E5 RPC protocol."""
    def __init__(self,worker:TrustedGitHubEffect):
        if not isinstance(worker,TrustedGitHubEffect):
            raise GithubRpcWireDenied("TRUSTED_WORKER_REQUIRED")
        self.worker=worker
        self.adapter_id=worker.adapter_id
        self.private=worker.private
        self.ledger=worker.ledger

    def execute(self,*,task_id,step_key,action,approval,gate,gate_created_at,stdin):
        if not isinstance(stdin,bytes) or not stdin or len(stdin)>524288:
            raise GithubRpcWireDenied("INVALID_GITHUB_RPC_BYTES")
        try:
            packet=json.loads(stdin.decode(),object_pairs_hook=_unique_pairs)
            if not isinstance(packet,dict) or set(packet)!={"version","operation","content_b64","commit_message"}:
                raise ValueError("schema")
            if type(packet["version"]) is not int or packet["version"]!=1:
                raise ValueError("version")
            if not isinstance(packet["content_b64"],str):
                raise ValueError("content")
            content=base64.b64decode(packet["content_b64"],validate=True)
            if stdin!=wire_bytes(operation=packet["operation"],content=content,
                                  commit_message=packet["commit_message"]):
                raise ValueError("noncanonical")
        except (ValueError,TypeError,UnicodeError,binascii.Error) as exc:
            raise GithubRpcWireDenied("UNTRUSTED_GITHUB_RPC_WIRE") from exc
        return self.worker.execute(task_id=task_id,step_key=step_key,action=action,
             approval=approval,gate=gate,gate_created_at=gate_created_at,
             operation=packet["operation"],content=content,
             commit_message=packet["commit_message"],wire_bytes=stdin)
