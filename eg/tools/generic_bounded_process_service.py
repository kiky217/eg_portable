"""Opt-in provider-neutral E3 process RPC service.

This server is NOT started by the default EG installer. Host operator must
independently provision keys, signed profiles, per-effect signed HITL and EG
PRE before high-effect admission can succeed. No project-specific adapter.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import socketserver
import stat
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, load_pem_private_key
)

from tools.adapter_liveness import DOMAIN, attest
from tools.generic_bounded_process_adapter import GenericProcessExecutor, ProcessDenied
from tools.private_unix_socket import private_socket_lease
from tools.trusted_execution_worker import canon

MAX_RPC_BYTES = 65536


def serve(config):
    if os.geteuid() == 0:
        raise ProcessDenied("NONROOT_WORKER_REQUIRED")
    trusted_operator_key = config["operator_public_key_b64"]
    worker_key_path = Path(config["worker_private_key"])
    stat_info = worker_key_path.lstat()
    if (not stat.S_ISREG(stat_info.st_mode)
        or stat_info.st_uid != os.geteuid()
        or stat.S_IMODE(stat_info.st_mode) & 0o077):
        raise ProcessDenied("INDEPENDENT_WORKER_KEY_REQUIRED")
    private = load_pem_private_key(worker_key_path.read_bytes(), password=None)
    public = base64.b64encode(
        private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    if public != config["worker_public_key_b64"] or public == trusted_operator_key:
        raise ProcessDenied("SEPARATE_PINNED_SIGNING_ROOTS_REQUIRED")
    runner = GenericProcessExecutor(
        policy=config["signed_process_profiles"],
        trusted_operator_public_b64=trusted_operator_key,
        hitl_public_b64=config["hitl_public_key_b64"],
        worker_key=private, eg_url=config["eg_url"],
        eg_api_key=config["eg_api_key"],
        journal_root=config["journal_root"])
    sock = Path(config["socket_path"])
    info = sock.parent.lstat()
    uid, gid = config["controller_uid"], config["controller_gid"]
    if (type(uid) is not int or uid < 1 or uid == os.geteuid()
        or type(gid) is not int or gid < 1
        or not sock.is_absolute() or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid() or info.st_gid != gid
        or not info.st_mode & stat.S_ISGID
        or stat.S_IMODE(info.st_mode) & 0o027):
        raise ProcessDenied("INDEPENDENT_PRIVATE_RPC_DIRECTORY_REQUIRED")
    capability = config["capability"]
    if not isinstance(capability, dict) or capability.get("adapter_id") != runner.adapter_id:
        raise ProcessDenied("CAPABILITY_PIN_REQUIRED")
    fingerprint = hashlib.sha256(canon(capability)).hexdigest()

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            try:
                peer = self.request.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
                if struct.unpack("3i", peer)[1] != uid:
                    raise ProcessDenied("UNTRUSTED_CONTROLLER_PEER_UID")
                data = self.rfile.readline(MAX_RPC_BYTES + 1)
                if len(data) > MAX_RPC_BYTES or not data.endswith(b"\n"):
                    raise ProcessDenied("RPC_OVERSIZE_OR_INCOMPLETE")
                request = json.loads(data)
                if (isinstance(request, dict) and
                    request.get("domain") == DOMAIN):
                    result = attest(request, adapter_id=runner.adapter_id,
                                    capability_sha256=fingerprint, private_key=private)
                    answer = result  # exact liveness wire schema; no extra status field
                elif isinstance(request, dict) and request.get("operation") == "bounded_process_run":
                    if set(request) != {
                        "operation", "task_id", "step_key", "action", "profile_id",
                        "signed_hitl", "gate_checkpoint_no"
                    }:
                        raise ProcessDenied("UNSUPPORTED_GENERIC_RPC_SHAPE")
                    receipt = runner.run_once(
                        task_id=request["task_id"], step_key=request["step_key"],
                        action=request["action"], profile_id=request["profile_id"],
                        signed_hitl=request["signed_hitl"],
                        gate_checkpoint_no=request["gate_checkpoint_no"])
                    answer = {"status": "PASS", "receipt": receipt}
                else:
                    raise ProcessDenied("UNKNOWN_GENERIC_RPC_OPERATION")
            except Exception as exc:
                answer = {"status": "DENIED",
                          "reason": type(exc).__name__ + ":" + str(exc)}
            self.wfile.write(canon(answer) + b"\n")

    class Server(socketserver.UnixStreamServer):
        allow_reuse_address = False

    with private_socket_lease(sock), Server(str(sock), Handler) as server:
        os.chmod(sock, 0o660)
        server.serve_forever(poll_interval=0.2)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Expected protected operator-provisioned JSON config path")
    cfg = Path(sys.argv[1])
    info = cfg.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077):
        raise SystemExit("INVALID_PRIVATE_PROCESS_WORKER_CONFIG")
    serve(json.loads(cfg.read_text()))
