"""Optional provider-neutral fixed-profile E3 process executor.

This module is not wired into the default portable runtime. A separately
governed operator must pin a signed profile manifest, independent executor
identity and gateway admission before any production invocation.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import resource
import re
import secrets
import signal
import stat
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from app.execution_receipts import body, sign
from tools.high_effect_admission import target_within_scope
from tools.signed_hitl_approval import verify_approval
from tools.trusted_execution_worker import api, store_exclusive, canon

POLICY_FIELDS = {"version", "adapter_id", "issued_at", "expires_at", "nonce", "profiles"}
PROFILE_FIELDS = {
    "profile_id", "target_prefix", "executable", "executable_sha256",
    "cwd", "fixed_args", "timeout_seconds", "max_output_bytes"
}


class ProcessDenied(RuntimeError):
    pass


def verify_profiles(signed: dict, trusted_operator_public_b64: str, *, now=None):
    """Verify once-provisioned, reusable profiles against an external trust root."""
    instant = time.time() if now is None else now
    if not isinstance(signed, dict) or set(signed) != POLICY_FIELDS | {"signature_b64"}:
        raise ProcessDenied("INVALID_GENERIC_PROFILE_ENVELOPE")
    policy = {k: signed[k] for k in POLICY_FIELDS}
    if (type(policy["version"]) is not int or policy["version"] != 1
        or not isinstance(policy["adapter_id"], str)
        or not policy["adapter_id"].startswith("trusted-adapter-")
        or type(policy["issued_at"]) not in (int, float)
        or type(policy["expires_at"]) not in (int, float)
        or not policy["issued_at"] <= instant < policy["expires_at"]
        or policy["expires_at"] - policy["issued_at"] > 86400
        or not isinstance(policy["nonce"], str)
        or len(policy["nonce"]) < 16
        or not isinstance(policy["profiles"], list)
        or not 1 <= len(policy["profiles"]) <= 32):
        raise ProcessDenied("EXPIRED_OR_INVALID_GENERIC_PROFILES")
    try:
        pub = base64.b64decode(trusted_operator_public_b64, validate=True)
        signature = base64.b64decode(signed["signature_b64"], validate=True)
        if len(pub) != 32 or len(signature) != 64:
            raise ValueError("invalid signature size")
        Ed25519PublicKey.from_public_bytes(pub).verify(signature, canon(policy))
    except Exception as exc:
        raise ProcessDenied("GENERIC_PROFILE_SIGNATURE_INVALID") from exc
    result = {}
    for item in policy["profiles"]:
        if not isinstance(item, dict) or set(item) != PROFILE_FIELDS:
            raise ProcessDenied("GENERIC_PROFILE_SCHEMA_DENIED")
        name = item["profile_id"]
        exe = item["executable"]
        cwd = item["cwd"]
        args = item["fixed_args"]
        if (not isinstance(name, str) or not name.isidentifier() or name in result
            or not isinstance(exe, str) or not exe.startswith("/")
            or not isinstance(cwd, str) or not cwd.startswith("/")
            or not isinstance(item["target_prefix"], str)
            or not item["target_prefix"].startswith("/")
            or ".." in Path(item["target_prefix"]).parts
            or not isinstance(args, list) or len(args) > 24
            or any(not isinstance(a, str) or len(a) > 256 or "\0" in a for a in args)
            or type(item["timeout_seconds"]) is not int
            or not 1 <= item["timeout_seconds"] <= 60
            or type(item["max_output_bytes"]) is not int
            or not 1 <= item["max_output_bytes"] <= 65536
            or not isinstance(item["executable_sha256"], str)
            or len(item["executable_sha256"]) != 64):
            raise ProcessDenied("GENERIC_PROFILE_OUT_OF_BOUNDS")
        executable, directory = Path(exe), Path(cwd)
        try:
            info = executable.lstat()
            dstat = directory.lstat()
            if (not stat.S_ISREG(info.st_mode) or not (info.st_mode & 0o111)
                or info.st_uid != 0 or info.st_mode & 0o022
                or not stat.S_ISDIR(dstat.st_mode) or dstat.st_uid != os.geteuid()
                or stat.S_IMODE(dstat.st_mode) & 0o077
                or executable.resolve(strict=True) != executable
                or directory.resolve(strict=True) != directory):
                raise ProcessDenied("GENERIC_PROFILE_UNSAFE_EXECUTABLE_OR_CWD")
            if hashlib.sha256(executable.read_bytes()).hexdigest() != item["executable_sha256"]:
                raise ProcessDenied("GENERIC_PROFILE_EXECUTABLE_DRIFT")
        except (OSError, ValueError) as exc:
            raise ProcessDenied("GENERIC_PROFILE_UNVERIFIED_TARGET") from exc
        result[name] = dict(item)
    return policy["adapter_id"], result


class GenericProcessExecutor:
    """One independently administered worker reused across unrelated EG tasks."""

    def __init__(self, *, policy, trusted_operator_public_b64, hitl_public_b64,
                 worker_key, eg_url, eg_api_key, journal_root):
        if os.geteuid() == 0:
            raise ProcessDenied("GENERIC_PROCESS_WORKER_MUST_BE_NONROOT")
        self.adapter_id, self.profiles = verify_profiles(policy, trusted_operator_public_b64)
        self._signed_profiles = policy
        self._operator_public = trusted_operator_public_b64
        if not hitl_public_b64 or not eg_api_key or not eg_url.startswith("http://127.0.0.1:"):
            raise ProcessDenied("TRUSTED_CONFIG_REQUIRED")
        self.hitl_public_b64 = hitl_public_b64
        self.worker_key = worker_key
        self.eg_url = eg_url
        self.eg_api_key = eg_api_key
        self.journal = Path(journal_root)
        info = self.journal.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
            or self.journal.is_symlink()):
            raise ProcessDenied("PRIVATE_WORKER_JOURNAL_REQUIRED")

    def run_once(self, *, task_id, step_key, action, profile_id,
                 signed_hitl, gate_checkpoint_no):
        if (not isinstance(task_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", task_id)
            or not isinstance(step_key, str)
            or not re.fullmatch(r"[0-9]{2}(?:\.[0-9]{2}){0,5}", step_key)
            or type(gate_checkpoint_no) is not int or gate_checkpoint_no < 1):
            raise ProcessDenied("INVALID_TASK_SCOPE")
        # The operator-approved catalog has its own short expiration; an
        # already-running worker never extends that trust implicitly.
        adapter_id, current = verify_profiles(
            self._signed_profiles, self._operator_public)
        if adapter_id != self.adapter_id or current != self.profiles:
            raise ProcessDenied("GENERIC_PROFILE_ROTATION_OR_TRUST_DRIFT")
        profile = current.get(profile_id)
        if not profile:
            raise ProcessDenied("UNTRUSTED_PROCESS_PROFILE")
        if (not isinstance(action, dict)
            or action.get("action_type") != "bounded_process_run"
            or action.get("effect_class") != "E3"
            or action.get("real_world_effect") is not True
            or not target_within_scope(action.get("target"), profile["target_prefix"])):
            raise ProcessDenied("ACTION_NOT_WITHIN_GENERIC_CAPABILITY")
        payload = canon({"profile_id": profile_id})
        if (action.get("payload_sha256") != hashlib.sha256(payload).hexdigest()
            or action.get("payload_bytes") != len(payload)):
            raise ProcessDenied("PROCESS_PROFILE_PAYLOAD_NOT_PREBOUND")
        from tools.trusted_execution_worker import fingerprint
        fp = fingerprint(action)
        verify_approval(signed_hitl, self.hitl_public_b64, task_id=task_id,
                        step_key=step_key, gate_checkpoint_no=gate_checkpoint_no,
                        action_fingerprint=fp, adapter_id=self.adapter_id)
        state, detail = api(self.eg_url, self.eg_api_key, task_id)
        gate = state.get("pending_execution_gate")
        original = next(
            (item for item in detail.get("checkpoints", [])
             if item.get("checkpoint_no") == gate_checkpoint_no),
            None)
        pin = (original or {}).get("high_effect_pin") or {}
        if (not isinstance(gate, dict)
            or gate.get("pre_checkpoint_no") != gate_checkpoint_no
            or gate.get("action_fingerprint") != fp
            or state.get("current_step") != step_key
            or state.get("latest_checkpoint", {}).get("checkpoint_no") != gate_checkpoint_no
            or state["latest_checkpoint"].get("verdict") != "READY_TO_EXECUTE"
            or (original or {}).get("verdict") != "READY_TO_EXECUTE"
            or pin.get("adapter_id") != self.adapter_id
            or pin.get("action_fingerprint") != fp
            or pin.get("public_key_b64") != base64.b64encode(
                self.worker_key.public_key().public_bytes(
                    Encoding.Raw, PublicFormat.Raw)).decode()
            or pin.get("approval_nonce") != signed_hitl["nonce"]
            or state.get("status") in {"PAUSED", "RECOVERY_PENDING"}):
            raise ProcessDenied("ORIGINAL_SIGNED_PRE_REQUIRED")
        stamp = datetime.fromisoformat(original["created_at"]).timestamp()
        if not 0 <= time.time() - stamp <= 300:
            raise ProcessDenied("PROCESS_PRE_EXECUTION_LEASE_EXPIRED")
        exe = Path(profile["executable"])
        info = exe.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o022 or exe.is_symlink()
            or hashlib.sha256(exe.read_bytes()).hexdigest() != profile["executable_sha256"]):
            raise ProcessDenied("EXECUTABLE_CHANGED_SINCE_OPERATOR_APPROVAL")
        intent = self.journal / (task_id + "-" + step_key + ".json")
        if intent.exists() or intent.is_symlink():
            # At-most-once: do not blindly retry a process after an uncertain crash.
            raise ProcessDenied("EXISTING_PROCESS_INTENT_RECONCILIATION_REQUIRED")
        store_exclusive(intent, canon({"state": "INTENT_DURABLE",
            "task_id": task_id, "step_key": step_key,
            "gate_checkpoint_no": gate_checkpoint_no,
            "action_fingerprint": fp, "profile_id": profile_id}))
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            def limit_child():
                maximum = profile["max_output_bytes"]
                resource.setrlimit(resource.RLIMIT_FSIZE, (maximum, maximum))
                resource.setrlimit(resource.RLIMIT_CPU, (
                    profile["timeout_seconds"] + 1, profile["timeout_seconds"] + 1))
            child = subprocess.Popen(
                [profile["executable"], *profile["fixed_args"]],
                stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                cwd=profile["cwd"], env={"PATH": "/usr/bin:/bin", "LANG": "C"},
                shell=False, close_fds=True, start_new_session=True,
                preexec_fn=limit_child)
            try:
                returncode = child.wait(timeout=profile["timeout_seconds"])
            except subprocess.TimeoutExpired as exc:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
                raise ProcessDenied("BOUNDED_PROCESS_TIMEOUT_AMBIGUOUS_EFFECT") from exc
            stdout.seek(0); stderr.seek(0)
            raw = stdout.read(profile["max_output_bytes"] + 1)
            err = stderr.read(profile["max_output_bytes"] + 1)
        if returncode != 0 or len(raw) + len(err) > profile["max_output_bytes"]:
            raise ProcessDenied("PROCESS_FAILED_OR_OUTPUT_LIMIT_EXCEEDED")
        evidence = canon({"exit_code": returncode,
                          "stdout_sha256": hashlib.sha256(raw).hexdigest(),
                          "stderr_sha256": hashlib.sha256(err).hexdigest()})
        from app.execution_receipts import body as receipt_body, sign as receipt_sign
        receipt = receipt_sign(
            receipt_body(task_id, step_key, gate_checkpoint_no, fp,
                         "trusted-worker-" + self.adapter_id, action["target"],
                         evidence, secrets.token_urlsafe(24)),
            self.worker_key)
        # Receipt is only execution evidence. Canonical POST remains mandatory.
        sealed = intent.with_suffix(".sealed")
        store_exclusive(sealed, canon({"state": "RECEIPT_SEALED", "receipt": receipt}))
        os.replace(sealed, intent)
        dfd = os.open(self.journal, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
        try: os.fsync(dfd)
        finally: os.close(dfd)
        return receipt
