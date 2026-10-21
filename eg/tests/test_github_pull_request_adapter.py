"""Local HTTP GitHub-emulator effects: distinct signed PRE, real API writes, no replay."""
import base64
import hashlib
import json
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from tools.no_redirect_http import urlopen
from tools.github_pull_request_adapter import (
    GitHubPullRequestAdapter, GitHubPullRequestDenied, validate_pr_request,
    preflight_merge_scope, perform_pr_effect, verify_pr_effect,
)
from tools.high_effect_admission import action_fingerprint
from tools.signed_hitl_approval import canonical
from app.execution_receipts import verify as verify_receipt

REPO = "example/project"
POL = {"repository": REPO, "branch_prefix": "agent/", "base_branches": ["develop"],
       "operations": ["create_pull_request", "merge_pull_request"]}
CREATE = {"operation": "create_pull_request", "repository": REPO,
          "head": "agent/fix-68", "base": "develop", "title": "Fix bug", "body": "Local verification"}
MERGE = {"operation": "merge_pull_request", "repository": REPO, "number": 17,
         "expected_head_sha": "a" * 40, "method": "merge"}


def pub(k):
    return base64.b64encode(k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


class LocalGitHub(BaseHTTPRequestHandler):
    state = {}

    def _json(self, code, value):
        body = json.dumps(value).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

    def _pr(self):
        st = self.state
        return {"number": 17, "state": "closed" if st["merged"] else "open",
                "merged": st["merged"], "merge_commit_sha": st["merge_sha"] or None,
                "title": CREATE["title"], "body": CREATE["body"],
                "base": {"ref": "develop", "repo": {"full_name": REPO}},
                "head": {"ref": "agent/fix-68", "sha": "a" * 40,
                         "repo": {"full_name": REPO}}}

    def _auth(self):
        assert self.headers.get("Authorization") == "Bearer ephemeral-ci-only"
        assert self.path.startswith("/repos/example/project/pulls")

    def do_GET(self):
        self._auth()
        self.state["reads"] += 1
        self._json(200, self._pr() if self.state["created"] else {})

    def do_POST(self):
        self._auth()
        inp = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        assert inp == {key: CREATE[key] for key in ("base", "head", "title", "body")}
        assert not self.state["created"]
        self.state["created"] = True
        self.state["writes"].append("create")
        self._json(201, self._pr())

    def do_PUT(self):
        self._auth()
        inp = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        assert inp == {"sha": "a" * 40, "merge_method": "merge"}
        assert self.state["created"] and not self.state["merged"]
        self.state["merged"] = True
        self.state["merge_sha"] = "b" * 40
        self.state["writes"].append("merge")
        self._json(200, {"merged": True, "sha": "b" * 40})


@pytest.fixture
def local_github():
    LocalGitHub.state = {"writes": [], "reads": 0, "created": False,
                         "merged": False, "merge_sha": ""}
    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalGitHub)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    def opener(request, *, timeout):
        url = request.full_url.replace("https://api.github.com", f"http://127.0.0.1:{server.server_port}")
        return urlopen(Request(url, data=request.data, method=request.get_method(),
                               headers=dict(request.header_items())), timeout=timeout)
    try:
        yield LocalGitHub.state, opener
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def signed_call(op, adapter, human, *, task_id):
    wire = json.dumps({"version": 1, "operation": op}, sort_keys=True,
                      separators=(",", ":"), ensure_ascii=False).encode()
    target = (f"/github/{REPO}/pulls/head/{op['head']}"
              if op["operation"] == "create_pull_request" else
              f"/github/{REPO}/pulls/{op['number']}")
    action = {"action_type": "github_pull_request", "effect_class": "E4",
              "real_world_effect": True, "reversible": False, "target": target,
              "payload_bytes": len(wire), "payload_sha256": hashlib.sha256(wire).hexdigest()}
    fp = action_fingerprint(action)
    cp = 1
    now = int(time.time())
    nonce = "nonce-independent-" + task_id + "-abc123456789"
    doc = {"version": 1, "task_id": task_id, "step_key": "01.01",
           "gate_checkpoint_no": cp, "action_fingerprint": fp,
           "adapter_id": adapter.adapter_id, "decision": "APPROVED",
           "issued_at": now - 1, "expires_at": now + 100, "nonce": nonce}
    approval = {**doc, "signature_b64": base64.b64encode(human.sign(canonical(doc))).decode()}
    gate = {"task_id": task_id, "step_key": "01.01", "verdict": "READY_TO_EXECUTE",
            "hitl_approved": True, "action_fingerprint": fp, "checkpoint_no": cp,
            "high_effect_pin": {"adapter_id": adapter.adapter_id,
                                "public_key_b64": pub(adapter.private),
                                "action_fingerprint": fp, "approval_nonce": nonce}}
    kw = dict(task_id=task_id, step_key="01.01", action=action, approval=approval,
              gate=gate, gate_created_at=datetime.now(timezone.utc).isoformat(), stdin=wire)
    return kw


def test_pr_create_and_merge_with_separate_signed_human_and_real_local_http(tmp_path, local_github):
    state, opener = local_github
    operator, human = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    def write(op, *, token):
        return perform_pr_effect(op, token=token, opener=opener)
    def readback(op, ack, *, token, policy):
        return verify_pr_effect(op, ack, policy=policy, token=token, opener=opener)
    def preflight(op, policy, *, token):
        return preflight_merge_scope(op, policy, token=token, opener=opener)
    journal = tmp_path / "journal"
    journal.mkdir(mode=0o700)
    worker = GitHubPullRequestAdapter(journal_dir=journal, private_key=operator,
        adapter_id="trusted-adapter-github-pr-local", hitl_public_key_b64=pub(human),
        policy=POL, github_token="ephemeral-ci-only", write=write,
        readback=readback, preflight=preflight)
    kw_create = signed_call(CREATE, worker, human, task_id="local-pr-1")
    out = worker.execute(**kw_create)
    assert out["status"] == "EXECUTED_POST_NOT_VERIFIED"
    valid, reason = verify_receipt(out["receipt"], public_b64=pub(operator),
        task_id="local-pr-1", step_key="01.01", gate_checkpoint_no=1,
        action_fingerprint=action_fingerprint(kw_create["action"]),
        target=kw_create["action"]["target"], gate_created_at=kw_create["gate_created_at"])
    assert valid, reason
    assert state["writes"] == ["create"]
    with pytest.raises(GitHubPullRequestDenied, match="NO_REPLAY"):
        worker.execute(**kw_create)
    wrong_sha = signed_call({**MERGE, "expected_head_sha": "c" * 40}, worker,
                            human, task_id="local-bad-head")
    with pytest.raises(GitHubPullRequestDenied, match="SHA_NOT_MET"):
        worker.execute(**wrong_sha)
    assert state["writes"] == ["create"]
    kw_merge = signed_call(MERGE, worker, human, task_id="local-merge-2")
    merged = worker.execute(**kw_merge)
    valid, reason = verify_receipt(merged["receipt"], public_b64=pub(operator),
        task_id="local-merge-2", step_key="01.01", gate_checkpoint_no=1,
        action_fingerprint=action_fingerprint(kw_merge["action"]),
        target=kw_merge["action"]["target"], gate_created_at=kw_merge["gate_created_at"])
    assert valid, reason
    with pytest.raises(GitHubPullRequestDenied, match="NO_REPLAY"):
        worker.execute(**kw_merge)
    assert state["writes"] == ["create", "merge"]
    assert state["reads"] >= 3


@pytest.mark.parametrize("operation_case", [
    {**MERGE, "number": True}, {**MERGE, "expected_head_sha": "bad"},
    {**CREATE, "head": "agent/../main"}, {**CREATE, "base": "main"},
    {**MERGE, "method": "reset"}, {**CREATE, "repository": "other/repo"},
])
def test_bounded_pr_scope_rejects_invalid_request(operation_case):
    with pytest.raises(GitHubPullRequestDenied):
        validate_pr_request(operation_case, POL)


def test_bad_human_approval_denied_before_local_http(tmp_path, local_github):
    state, _ = local_github
    operator, human = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    journal = tmp_path / "journal"
    journal.mkdir(mode=0o700)
    worker = GitHubPullRequestAdapter(journal_dir=journal,
        private_key=operator, adapter_id="trusted-adapter-pr-signer-test",
        hitl_public_key_b64=pub(human), policy=POL, github_token="ephemeral-ci-only")
    kw = signed_call(CREATE, worker, Ed25519PrivateKey.generate(), task_id="bad-signature")
    with pytest.raises(Exception):
        worker.execute(**kw)
    assert state["writes"] == []


def test_lost_ack_after_real_local_pr_create_never_replays(tmp_path, local_github):
    state, opener = local_github
    worker_key, human = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    journal = tmp_path / "journal"; journal.mkdir(mode=0o700)
    def write_then_lose_ack(op, *, token):
        perform_pr_effect(op, token=token, opener=opener)
        raise TimeoutError("ACK was lost after remote creation")
    worker = GitHubPullRequestAdapter(journal_dir=journal, private_key=worker_key,
        adapter_id="trusted-adapter-pr-lost-ack", hitl_public_key_b64=pub(human),
        policy=POL, github_token="ephemeral-ci-only", write=write_then_lose_ack)
    args = signed_call(CREATE, worker, human, task_id="local-lost-ack")
    with pytest.raises(GitHubPullRequestDenied, match="UNKNOWN_RECONCILE_NO_REPLAY"):
        worker.execute(**args)
    assert state["writes"] == ["create"]
    # Recreate the worker against the exact original durable journal.
    restarted = GitHubPullRequestAdapter(journal_dir=journal, private_key=worker_key,
        adapter_id=worker.adapter_id, hitl_public_key_b64=pub(human),
        policy=POL, github_token="ephemeral-ci-only", write=write_then_lose_ack)
    with pytest.raises(GitHubPullRequestDenied, match="NO_REPLAY"):
        restarted.execute(**args)
    assert state["writes"] == ["create"]
    assert restarted.ledger.read_sealed_receipt(args["approval"]["nonce"],
        task_id=args["task_id"], step_key=args["step_key"], gate_checkpoint_no=1,
        action_fingerprint=action_fingerprint(args["action"]),
        adapter_id=worker.adapter_id) is None
