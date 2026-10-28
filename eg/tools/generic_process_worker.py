"""Operator-profiled bounded process worker for independently gated EG actions.

A configured executable and fixed arguments are not caller-selected commands.
This worker does not create signing keys, approve itself or override PRE/HITL.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import resource
import socket
import socketserver
import stat
import subprocess
import threading

from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PublicFormat
from tools.private_unix_socket import private_socket_lease
from tools.trusted_execution_worker import api, canon, store_exclusive, store_replace, gate_allows_new_effect
from app.execution_receipts import body, sign


class ProcessDenied(RuntimeError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


class GenericProcessWorker:
    def __init__(self, config):
        self.profile = config["profile"]
        self.journal = Path(config["journal_root"]).resolve(strict=True)
        if self.journal.stat().st_mode & 0o077:
            raise ProcessDenied("JOURNAL_NOT_PRIVATE")
        key_path = Path(config["private_key"])
        key_info = key_path.lstat()
        if (not stat.S_ISREG(key_info.st_mode) or key_info.st_uid != os.geteuid()
            or stat.S_IMODE(key_info.st_mode) & 0o077):
            raise ProcessDenied("SIGNING_KEY_NOT_PRIVATE")
        self.private = load_pem_private_key(key_path.read_bytes(), password=None)
        self.public = base64.b64encode(self.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
        self.url = config["eg_url"].rstrip("/")
        self.key = config["eg_api_key"]
        self.lock = threading.RLock()
        p = self.profile
        if (p["effect_class"] not in ("E3", "E4", "E5")
            or p["action_type"] != "bounded_process_run"
            or not p["adapter_id"].startswith("trusted-adapter-")
            or not p["target"].startswith("/")
            or not isinstance(p["fixed_args"], list)
            or any(not isinstance(arg, str) or len(arg) > 1024 for arg in p["fixed_args"])
            or type(p["timeout_seconds"]) is not int or not 1 <= p["timeout_seconds"] <= 30
            or type(p["max_output_bytes"]) is not int or not 1 <= p["max_output_bytes"] <= 65536):
            raise ProcessDenied("INVALID_GENERIC_PROFILE")
        raw_cwd = Path(p["cwd"])
        if raw_cwd.is_symlink():
            raise ProcessDenied("SYMLINK_CWD")
        self.cwd = raw_cwd.resolve(strict=True)
        self.executable = Path(p["executable"])
        if (not self.executable.is_absolute() or self.executable.is_symlink()
            or not self.executable.is_file() or not os.access(self.executable, os.X_OK)
            or not self.cwd.is_dir() or self.cwd.stat().st_uid != os.geteuid()
            or stat.S_IMODE(self.cwd.stat().st_mode) & 0o077):
            raise ProcessDenied("UNSAFE_EXECUTABLE_OR_CWD")
        if not re.fullmatch("[0-9a-f]{64}", p["executable_sha256"]):
            raise ProcessDenied("EXECUTABLE_DIGEST_REQUIRED")

    def run(self, request):
        with self.lock:
            return self._run(request)

    def _run(self, request):
        if not isinstance(request, dict) or set(request) != {"task_id", "step_key", "action", "data_b64"}:
            raise ProcessDenied("INVALID_REQUEST")
        task, step, action = request["task_id"], request["step_key"], request["action"]
        if (not isinstance(task, str) or not re.fullmatch("[A-Za-z0-9_.-]{1,127}", task)
            or not isinstance(step, str) or not re.fullmatch("[A-Za-z0-9_.-]{1,18}", step)
            or not isinstance(action, dict) or not isinstance(request["data_b64"], str)):
            raise ProcessDenied("INVALID_REQUEST_FIELDS")
        payload = base64.b64decode(request["data_b64"], validate=True)
        p = self.profile
        if (len(payload) > 512 * 1024 or not payload
            or action.get("action_type") != p["action_type"]
            or action.get("effect_class") != p["effect_class"]
            or action.get("target") != p["target"]
            or action.get("payload_sha256") != digest(payload)
            or action.get("payload_bytes") != len(payload)):
            raise ProcessDenied("PROFILE_OR_PAYLOAD_MISMATCH")
        fingerprint = digest(canon(action))
        state, detail = api(self.url, self.key, task)
        gate = state.get("pending_execution_gate")
        if (state.get("current_step") != step or state.get("status") != "IN_PROGRESS"
            or detail["task"]["contract_status"] != "OPEN" or not gate
            or gate["action_fingerprint"] != fingerprint):
            raise ProcessDenied("EG_PRE_NOT_READY")
        pre = next((x for x in detail["checkpoints"]
                    if x["checkpoint_no"] == gate["pre_checkpoint_no"]), None)
        pin = gate.get("high_effect_pin")
        if (not pre or pre["verdict"] != "READY_TO_EXECUTE"
            or not gate_allows_new_effect(pre["created_at"])
            or not pin or pin.get("adapter_id") != p["adapter_id"]
            or pin.get("public_key_b64") != self.public
            or pin.get("action_fingerprint") != fingerprint):
            raise ProcessDenied("SIGNED_HITL_OR_WORKER_PIN_MISSING")
        intent = self.journal / (task + "-" + step + ".json")
        if intent.exists():
            prior = json.loads(intent.read_text())
            if prior.get("fingerprint") != fingerprint or prior.get("gate") != gate["pre_checkpoint_no"]:
                raise ProcessDenied("JOURNAL_MISMATCH")
            if prior["stage"] == "SEALED":
                return prior["receipt"]
            raise ProcessDenied("UNKNOWN_EFFECT_DO_NOT_REPLAY")
        fd = os.open(self.executable, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise ProcessDenied("EXECUTABLE_CHANGED")
            with os.fdopen(os.dup(fd), "rb") as f:
                if digest(f.read()) != p["executable_sha256"]:
                    raise ProcessDenied("EXECUTABLE_CHANGED")
            store_exclusive(intent, canon({"stage": "INTENT", "fingerprint": fingerprint,
                                           "gate": gate["pre_checkpoint_no"]}))
            def limits():
                resource.setrlimit(resource.RLIMIT_CPU, (p["timeout_seconds"], p["timeout_seconds"] + 1))
                resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
                resource.setrlimit(resource.RLIMIT_FSIZE, (p["max_output_bytes"], p["max_output_bytes"]))
            output = self.journal / (task + "-" + step + ".out")
            output_fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(output_fd, "wb") as out:
                proc = subprocess.Popen(["/proc/self/fd/" + str(fd), *p["fixed_args"]],
                    stdin=subprocess.PIPE, stdout=out, stderr=subprocess.STDOUT,
                    cwd=self.cwd, env={"PATH": "/usr/bin:/bin", "LANG": "C"},
                    pass_fds=(fd,), preexec_fn=limits, start_new_session=True)
                try:
                    proc.communicate(input=payload, timeout=p["timeout_seconds"] + 2)
                except subprocess.TimeoutExpired as exc:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.communicate()
                    raise ProcessDenied("PROCESS_TIMEOUT_UNKNOWN_EFFECT") from exc
                out.flush()
                os.fsync(out.fileno())
            if proc.returncode != 0:
                raise ProcessDenied("PROCESS_EXIT_NONZERO")
            data = output.read_bytes()
            if not 0 < len(data) <= p["max_output_bytes"]:
                raise ProcessDenied("INVALID_PROCESS_OUTPUT")
            receipt = sign(body(task, step, gate["pre_checkpoint_no"], fingerprint,
                                "trusted-worker-" + p["adapter_id"], p["target"],
                                data, base64.urlsafe_b64encode(os.urandom(24)).decode()), self.private)
            store_replace(intent, canon({"stage": "SEALED", "fingerprint": fingerprint,
                                        "gate": gate["pre_checkpoint_no"], "receipt": receipt}))
            return receipt
        finally:
            os.close(fd)

def serve(config):
    """One reusable Unix-socket worker for one operator-approved capability."""
    worker = GenericProcessWorker(config)
    path = Path(config["socket_path"])
    p = worker.profile
    required_uid = config.get("controller_uid")
    if required_uid is not None and (type(required_uid) is not int or required_uid < 0):
        raise ProcessDenied("INVALID_CONTROLLER_UID")

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            try:
                if required_uid is not None:
                    raw = self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                    import struct
                    if struct.unpack("3i", raw)[1] != required_uid:
                        raise ProcessDenied("UNAUTHORIZED_CONTROLLER")
                raw = self.rfile.readline(1024 * 1024 + 1)
                if len(raw) > 1024 * 1024 or not raw.endswith(b"\n"):
                    raise ProcessDenied("INVALID_RPC_SIZE")
                request = json.loads(raw)
                if request.get("operation") == "attest":
                    from tools.adapter_liveness import attest
                    response = attest(request["challenge"], adapter_id=p["adapter_id"],
                        capability_sha256=p["capability_sha256"], private_key=worker.private)
                elif request.get("operation") == "execute":
                    response = {"status": "PASS", "receipt": worker.run(
                        {k: request[k] for k in ("task_id", "step_key", "action", "data_b64")})}
                else:
                    raise ProcessDenied("INVALID_OPERATION")
            except Exception as exc:
                response = {"status": "DENIED", "reason": type(exc).__name__ + ":" + str(exc)}
            self.wfile.write(canon(response) + b"\n")

    class Server(socketserver.ThreadingUnixStreamServer):
        daemon_threads = True

    with private_socket_lease(path), Server(str(path), Handler) as server:
        os.chmod(path, 0o600 if required_uid is None else 0o660)
        server.serve_forever(poll_interval=.2)


if __name__ == "__main__":
    import sys
    path = Path(sys.argv[1]) if len(sys.argv) == 2 else None
    if path is None or path.is_symlink() or path.stat().st_mode & 0o077:
        raise SystemExit("PROTECTED_CONFIG_REQUIRED")
    serve(json.loads(path.read_text()))
