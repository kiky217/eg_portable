"""Read-only independent GitHub commit readback for a future trusted adapter.

Never signs an EG receipt or infers causality merely from matching content.
The independently governed executor must also prove original PRE, durable
intent, effect idempotency and separate signed HITL before any GitHub write.
"""
from __future__ import annotations
import base64
import hashlib
import json
from urllib.parse import quote
from urllib.request import Request, urlopen
from tools.github_effect_scope import validate_operation, GitHubScopeDenied

class GitHubReadbackDenied(RuntimeError):
    pass

def verify_commit_content(operation: dict, policy: dict, *, commit_sha: str,
                          expected_bytes: bytes, token: str, opener=urlopen) -> dict:
    """Exact immutable commit readback; not proof of when/who caused a write."""
    validated = validate_operation(operation, policy)
    if (not isinstance(commit_sha,str) or len(commit_sha)!=40 or
        any(x not in "0123456789abcdef" for x in commit_sha) or
        not isinstance(expected_bytes,bytes) or not expected_bytes or
        len(expected_bytes)>512*1024 or not isinstance(token,str) or not token):
        raise GitHubReadbackDenied("INVALID_IMMUTABLE_READBACK_INPUT")
    repo = validated["repository"]
    path = quote(validated["path"],safe="/")
    url = ("https://api.github.com/repos/"+repo+"/contents/"+path+
           "?ref="+commit_sha)
    request=Request(url,headers={"Authorization":"Bearer "+token,
                  "Accept":"application/vnd.github+json",
                  "X-GitHub-Api-Version":"2022-11-28"})
    try:
        with opener(request,timeout=10) as response:
            raw=response.read(1024*1024)
        payload=json.loads(raw)
        if (not isinstance(payload,dict) or payload.get("type")!="file" or
            payload.get("encoding")!="base64" or
            not isinstance(payload.get("content"),str) or
            payload.get("path")!=validated["path"]):
            raise ValueError("invalid GitHub response")
        observed=base64.b64decode(payload["content"],validate=False)
    except (OSError,ValueError,TypeError,KeyError) as exc:
        raise GitHubReadbackDenied("IMMUTABLE_READBACK_UNAVAILABLE") from exc
    if observed!=expected_bytes:
        raise GitHubReadbackDenied("IMMUTABLE_READBACK_MISMATCH")
    return {"status":"CONTENT_VERIFIED_NOT_EXECUTION_PROOF",
            "commit_sha":commit_sha,
            "blob_sha256":hashlib.sha256(observed).hexdigest(),
            "bytes":len(observed)}
