"""Optional independently operated GitHub PR create/merge E4 adapter.

No credentials, signatures, or operator grants originate in this module.
The generic RPC host authenticates peer UID and original EG PRE before entry.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from datetime import datetime
from urllib.request import Request

from tools.no_redirect_http import urlopen
from tools.durable_hitl_ledger import ApprovalLedger
from tools.high_effect_admission import action_fingerprint
from tools.signed_hitl_approval import verify_approval
from app.execution_receipts import body, sign
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

_SHA = re.compile(r"^[0-9a-f]{40}$")
_REPO = re.compile(r"^[a-zA-Z0-9_.-]{1,100}/[a-zA-Z0-9_.-]{1,100}$")
_BRANCH = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,199}$")
_ACTIONS = {"create_pull_request", "merge_pull_request"}


class GitHubPullRequestDenied(RuntimeError):
    pass


def _branch_valid(name):
    return (isinstance(name, str) and bool(_BRANCH.fullmatch(name))
            and ".." not in name and not name.endswith(".")
            and all(part and not part.startswith(".") and not part.endswith(".lock")
                    for part in name.split("/")))


def validate_pr_request(op, policy):
    if (not isinstance(policy, dict)
        or set(policy) != {"repository", "branch_prefix", "base_branches", "operations"}
        or not isinstance(policy["repository"], str)
        or not _REPO.fullmatch(policy["repository"])
        or any(p in (".", "..") for p in policy["repository"].split("/"))
        or not isinstance(policy["branch_prefix"], str)
        or not _BRANCH.fullmatch(policy["branch_prefix"])
        or not policy["branch_prefix"].endswith("/")
        or not isinstance(policy["base_branches"], list)
        or not policy["base_branches"]
        or any(not _branch_valid(v) for v in policy["base_branches"])
        or not isinstance(policy["operations"], list)
        or not policy["operations"]
        or any(not isinstance(a, str) or a not in _ACTIONS for a in policy["operations"])):
        raise GitHubPullRequestDenied("INVALID_OPERATOR_PR_POLICY_NO_EFFECT")
    if not isinstance(op, dict) or op.get("operation") not in policy["operations"]:
        raise GitHubPullRequestDenied("PR_SCOPE_DENIED_NO_EFFECT")
    if op.get("repository") != policy["repository"]:
        raise GitHubPullRequestDenied("PR_REPOSITORY_DENIED_NO_EFFECT")
    if op["operation"] == "create_pull_request":
        if (set(op) != {"operation", "repository", "base", "head", "title", "body"}
            or op["base"] not in policy["base_branches"]
            or not _branch_valid(op["head"])
            or not op["head"].startswith(policy["branch_prefix"])
            or not isinstance(op["title"], str) or not 1 <= len(op["title"]) <= 180
            or not isinstance(op["body"], str) or len(op["body"].encode()) > 8192):
            raise GitHubPullRequestDenied("PR_CREATE_SCOPE_DENIED_NO_EFFECT")
    else:
        if (set(op) != {"operation", "repository", "number", "expected_head_sha", "method"}
            or type(op["number"]) is not int or not 1 <= op["number"] <= 999999999
            or not isinstance(op["expected_head_sha"], str)
            or not _SHA.fullmatch(op["expected_head_sha"])
            or op["method"] not in ("merge", "squash", "rebase")):
            raise GitHubPullRequestDenied("PR_MERGE_SCOPE_DENIED_NO_EFFECT")
    return dict(op)


def _api(op, path, token, *, method="GET", payload=None, opener=urlopen):
    if (not isinstance(token, str) or not token or any(x in token for x in "\r\n")):
        raise GitHubPullRequestDenied("INVALID_WORKER_GITHUB_CREDENTIAL")
    url = "https://api.github.com/repos/" + op["repository"] + path
    req = Request(url, method=method,
        data=None if payload is None else json.dumps(payload, separators=(",", ":")).encode(),
        headers={"Authorization": "Bearer " + token,
                 "Accept": "application/vnd.github+json",
                 "Content-Type": "application/json", "X-GitHub-Api-Version": "2022-11-28"})
    try:
        with opener(req, timeout=15) as response:
            raw = response.read(131073)
        if len(raw) > 131072:
            raise ValueError("response too large")
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise ValueError("non-object response")
        return result
    except Exception as exc:
        raise GitHubPullRequestDenied("PR_API_UNKNOWN_RECONCILE_NO_REPLAY") from exc


def perform_pr_effect(op, *, token, opener=urlopen):
    if op["operation"] == "create_pull_request":
        response = _api(op, "/pulls", token, method="POST", opener=opener,
                        payload={k: op[k] for k in ("base", "head", "title", "body")})
        number = response.get("number")
        head = response.get("head")
        if (type(number) is not int or number < 1 or not isinstance(head, dict)
            or not isinstance(head.get("sha"), str) or not _SHA.fullmatch(head["sha"])):
            raise GitHubPullRequestDenied("PR_CREATE_ACK_UNKNOWN_NO_REPLAY")
        return {"number": number, "commit_sha": head["sha"]}
    result = _api(op, "/pulls/" + str(op["number"]) + "/merge", token,
                  method="PUT", opener=opener,
                  payload={"sha": op["expected_head_sha"], "merge_method": op["method"]})
    sha = result.get("sha")
    if result.get("merged") is not True or not isinstance(sha, str) or not _SHA.fullmatch(sha):
        raise GitHubPullRequestDenied("PR_MERGE_ACK_UNKNOWN_NO_REPLAY")
    return {"number": op["number"], "commit_sha": sha}


def verify_pr_effect(op, ack, *, token, policy, opener=urlopen):
    current = _api(op, "/pulls/" + str(ack["number"]), token, opener=opener)
    base, head = current.get("base"), current.get("head")
    if not isinstance(base, dict) or not isinstance(head, dict):
        raise GitHubPullRequestDenied("PR_READBACK_REPOSITORY_MISMATCH_NO_REPLAY")
    base_repo, head_repo = base.get("repo"), head.get("repo")
    if not isinstance(base_repo, dict) or not isinstance(head_repo, dict):
        raise GitHubPullRequestDenied("PR_READBACK_REPOSITORY_MISMATCH_NO_REPLAY")
    if (current.get("number") != ack["number"]
        or not isinstance(base, dict) or not isinstance(head, dict)
        or base_repo.get("full_name") != op["repository"]
        or head_repo.get("full_name") != op["repository"]):
        raise GitHubPullRequestDenied("PR_READBACK_REPOSITORY_MISMATCH_NO_REPLAY")
    if op["operation"] == "create_pull_request":
        valid = (current.get("state") == "open" and base.get("ref") == op["base"]
                 and head.get("ref") == op["head"] and head.get("sha") == ack["commit_sha"]
                 and current.get("title") == op["title"] and current.get("body") == op["body"])
    else:
        valid = (current.get("merged") is True
                 and current.get("merge_commit_sha") == ack["commit_sha"]
                 and head.get("sha") == op["expected_head_sha"]
                 and base.get("ref") in policy["base_branches"]
                 and _branch_valid(head.get("ref"))
                 and head.get("ref").startswith(policy["branch_prefix"]))
    if not valid:
        raise GitHubPullRequestDenied("PR_IMMUTABLE_READBACK_MISMATCH_NO_REPLAY")
    return {"number": ack["number"], "commit_sha": ack["commit_sha"]}


def preflight_merge_scope(op, policy, *, token, opener=urlopen):
    """Read-only live check BEFORE consuming HITL or merging a scoped PR."""
    if op["operation"] != "merge_pull_request":
        return
    current = _api(op, "/pulls/" + str(op["number"]), token, opener=opener)
    base, head = current.get("base"), current.get("head")
    if (not isinstance(base, dict) or not isinstance(head, dict)
        or not isinstance(base.get("repo"), dict)
        or not isinstance(head.get("repo"), dict)
        or base["repo"].get("full_name") != op["repository"]
        or head["repo"].get("full_name") != op["repository"]
        or base.get("ref") not in policy["base_branches"]
        or not _branch_valid(head.get("ref"))
        or not head["ref"].startswith(policy["branch_prefix"])
        or head.get("sha") != op["expected_head_sha"]
        or current.get("state") != "open" or current.get("merged") is True):
        raise GitHubPullRequestDenied("PR_OPERATOR_SCOPE_OR_SHA_NOT_MET_NO_EFFECT")


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise GitHubPullRequestDenied("DUPLICATE_PR_WIRE_FIELD")
        result[key] = value
    return result


class GitHubPullRequestAdapter:
    """Typed PR/merge worker compatible with the existing UID-pinned generic RPC host."""
    def __init__(self, *, journal_dir, private_key, adapter_id, hitl_public_key_b64,
                 policy, github_token, write=perform_pr_effect, readback=verify_pr_effect,
                 preflight=preflight_merge_scope):
        if not isinstance(adapter_id, str) or not adapter_id.startswith("trusted-adapter-"):
            raise GitHubPullRequestDenied("INVALID_ADAPTER_ID")
        self.ledger = ApprovalLedger(journal_dir)
        self.private = private_key
        self.adapter_id = adapter_id
        self.hitl_key = hitl_public_key_b64
        self.policy = policy
        self.token = github_token
        self.write = write
        self.readback = readback
        self.preflight = preflight

    def execute(self, *, task_id, step_key, action, approval, gate, gate_created_at, stdin):
        if not isinstance(stdin, bytes) or not 1 <= len(stdin) <= 524288:
            raise GitHubPullRequestDenied("INVALID_PR_PAYLOAD_NO_EFFECT")
        try:
            packet = json.loads(stdin.decode(), object_pairs_hook=_unique_pairs)
            if (not isinstance(packet, dict) or set(packet) != {"version", "operation"}
                or type(packet["version"]) is not int or packet["version"] != 1
                or stdin != json.dumps(packet, sort_keys=True, separators=(",", ":"),
                                        ensure_ascii=False).encode()):
                raise ValueError("noncanonical PR wire")
            op = validate_pr_request(packet["operation"], self.policy)
        except (ValueError, TypeError, UnicodeError, KeyError) as exc:
            raise GitHubPullRequestDenied("INVALID_PR_WIRE_NO_EFFECT") from exc
        target = ("/github/" + op["repository"] + "/pulls/head/" + op["head"]
                  if op["operation"] == "create_pull_request" else
                  "/github/" + op["repository"] + "/pulls/" + str(op["number"]))
        if (not isinstance(action, dict) or action.get("action_type") != "github_pull_request"
            or action.get("effect_class") != "E4" or action.get("real_world_effect") is not True
            or action.get("reversible") is not False or action.get("target") != target
            or action.get("payload_sha256") != hashlib.sha256(stdin).hexdigest()
            or action.get("payload_bytes") != len(stdin)):
            raise GitHubPullRequestDenied("PR_SIGNED_ACTION_MISMATCH_NO_EFFECT")
        if not isinstance(approval, dict):
            raise GitHubPullRequestDenied("PR_INDEPENDENT_HITL_REQUIRED")
        fp = action_fingerprint(action)
        public = base64.b64encode(self.private.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)).decode()
        pin = gate.get("high_effect_pin") if isinstance(gate, dict) else None
        cp = gate.get("checkpoint_no") if isinstance(gate, dict) else None
        if (not isinstance(gate, dict) or gate.get("task_id") != task_id
            or gate.get("step_key") != step_key or gate.get("verdict") != "READY_TO_EXECUTE"
            or gate.get("hitl_approved") is not True or gate.get("action_fingerprint") != fp
            or not isinstance(pin, dict) or pin.get("adapter_id") != self.adapter_id
            or pin.get("public_key_b64") != public or pin.get("approval_nonce") != approval.get("nonce")
            or type(cp) is not int or cp <= 0):
            raise GitHubPullRequestDenied("PR_CANONICAL_PRE_REQUIRED_NO_EFFECT")
        try:
            epoch = datetime.fromisoformat(gate_created_at).timestamp()
        except (TypeError, ValueError, OverflowError) as exc:
            raise GitHubPullRequestDenied("INVALID_PR_GATE_TIME_NO_EFFECT") from exc
        now = time.time()
        if not epoch - 30 <= now <= epoch + 300:
            raise GitHubPullRequestDenied("PR_PRE_EXPIRED_NO_EFFECT")
        verify_approval(approval, self.hitl_key, task_id=task_id, step_key=step_key,
                        gate_checkpoint_no=cp, action_fingerprint=fp,
                        adapter_id=self.adapter_id, now=now)
        scope = dict(task_id=task_id, step_key=step_key, gate_checkpoint_no=cp,
                     action_fingerprint=fp, adapter_id=self.adapter_id)
        nonce = approval["nonce"]
        if self.ledger.claim_status(nonce, **scope) is not None:
            raise GitHubPullRequestDenied("PR_EFFECT_UNKNOWN_NO_REPLAY")
        self.preflight(op, self.policy, token=self.token)
        self.ledger.consume(approval, self.hitl_key, now=now, **scope)
        try:
            ack = self.write(op, token=self.token)
            proof = self.readback(op, ack, token=self.token, policy=self.policy)
        except Exception as exc:
            raise GitHubPullRequestDenied("PR_EFFECT_UNKNOWN_RECONCILE_NO_REPLAY") from exc
        if (not isinstance(proof, dict) or proof.get("number") != ack["number"]
            or proof.get("commit_sha") != ack["commit_sha"]):
            raise GitHubPullRequestDenied("PR_READBACK_UNKNOWN_NO_REPLAY")
        output = json.dumps(proof, sort_keys=True, separators=(",", ":")).encode()
        receipt = sign(body(task_id, step_key, cp, fp, "trusted-worker-" + self.adapter_id,
                            target, output, nonce, completed_ns=max(time.time_ns(),
                            int(epoch * 1e9))), self.private)
        self.ledger.record_executed_effect(target + "@" + ack["commit_sha"],
            task_id=task_id, gate_checkpoint_no=cp, action_fingerprint=fp,
            adapter_id=self.adapter_id, digest=hashlib.sha256(output).hexdigest())
        return {"status": "EXECUTED_POST_NOT_VERIFIED",
                "receipt": self.ledger.seal_receipt(nonce, receipt, **scope)}
