"""Real Unix-socket adapter attestation; never self-authorizes an effect."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

from tools.adapter_liveness import probe_unix
from test_generic_process_worker import setup as worker_setup  # fixture


def test_generic_adapter_live_socket_attests_only(worker_setup, tmp_path):
    worker, profile, _state, _detail, request, _payload, journal = worker_setup
    sock_dir = tmp_path / "socket"
    sock_dir.mkdir(mode=0o700)
    path = sock_dir / "worker.sock"
    config = tmp_path / "worker.json"
    config.write_text(json.dumps({
        "profile": profile,
        "journal_root": str(journal),
        "private_key": str(tmp_path / "executor.pem"),
        "eg_url": "http://127.0.0.1:18790",
        "eg_api_key": "fixture-only",
        "socket_path": str(path),
    }))
    config.chmod(0o600)
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])}
    service = subprocess.Popen([sys.executable, "-m", "tools.generic_process_worker",
                                str(config)], env=env, stdout=subprocess.DEVNULL,
                               stderr=subprocess.PIPE)
    try:
        for _ in range(100):
            if service.poll() is not None:
                raise AssertionError("worker refused to start")
            if path.is_socket():
                break
            time.sleep(.02)
        assert path.is_socket()
        proof = probe_unix(path, adapter_id=profile["adapter_id"],
                           capability_sha256=profile["capability_sha256"],
                           public_key_b64=worker.public, task_id="fixture-task",
                           step_key="01.01", gate_checkpoint_no=1,
                           action_fingerprint="a"*64, expected_worker_uid=os.geteuid())
        assert proof["status"] == "SIGNED_LIVENESS_ONLY_NOT_EXECUTION_ADMITTED"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(3)
            client.connect(str(path))
            client.sendall((json.dumps({"operation": "execute", **request})+"\n").encode())
            response = json.loads(client.makefile("rb").readline())
        assert response["status"] == "DENIED"
        assert not list(journal.iterdir())
    finally:
        service.terminate()
        service.wait(timeout=5)
