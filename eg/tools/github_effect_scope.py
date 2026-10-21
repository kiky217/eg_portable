"""Narrow immutable GitHub operation scope for an external trusted adapter.

This validates untrusted requests only. It NEVER authenticates, writes to
GitHub, signs a receipt, or substitutes for independent EG PRE/HITL.
"""
from __future__ import annotations
import re

_REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
_SHA = re.compile(r"^[a-f0-9]{40}$")
_ACTIONS = frozenset({"update_file","create_file"})

class GitHubScopeDenied(ValueError):
    pass

def validate_operation(request: dict, policy: dict) -> dict:
    """Return a copy of a fully scoped, version-pinned request or deny."""
    if not isinstance(request,dict) or not isinstance(policy,dict):
        raise GitHubScopeDenied("INVALID_GITHUB_SCOPE")
    if (set(policy)!={"repository","branch_prefix","path_prefix","actions"} or
        not isinstance(policy["repository"],str) or not _REPO.fullmatch(policy["repository"]) or
        not isinstance(policy["branch_prefix"],str) or not _REF.fullmatch(policy["branch_prefix"]) or
        not isinstance(policy["path_prefix"],str) or not policy["path_prefix"] or
        policy["path_prefix"].startswith("/") or
        any(p in (".","..","") for p in policy["path_prefix"].split("/")) or
        not isinstance(policy["actions"],list) or not policy["actions"] or
        any(not isinstance(x,str) or x not in _ACTIONS for x in policy["actions"])):
        raise GitHubScopeDenied("INVALID_GITHUB_SCOPE_POLICY")
    action=request.get("operation")
    expected={"repository","operation","branch","path","expected_blob_sha"}
    if (set(request)!=expected or action not in policy["actions"] or
        request.get("repository")!=policy["repository"] or
        not isinstance(request.get("branch"),str) or
        not _REF.fullmatch(request["branch"]) or
        not request["branch"].startswith(policy["branch_prefix"]) or
        any(x in ("", ".", "..") for x in request["branch"].split("/")) or
        ".." in request["branch"] or request["branch"].endswith(".") or
        any(x.startswith(".") or x.endswith(".lock")
            for x in request["branch"].split("/")) or
        request["branch"] in ("main","master") or
        not isinstance(request.get("path"),str) or
        any(x in ("",".","..") for x in request["path"].split("/")) or
        not request["path"].startswith(policy["path_prefix"]+"/") or
        not isinstance(request.get("expected_blob_sha"),str)):
        raise GitHubScopeDenied("GITHUB_EFFECT_SCOPE_DENIED")
    if action=="update_file":
        if not _SHA.fullmatch(request["expected_blob_sha"]):
            raise GitHubScopeDenied("GITHUB_EXPECTED_SHA_REQUIRED")
    elif request["expected_blob_sha"]!="":
        raise GitHubScopeDenied("GITHUB_NEW_EFFECT_MUST_NOT_HAVE_OLD_SHA")
    return dict(request)
