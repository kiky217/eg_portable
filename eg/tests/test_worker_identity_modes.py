"""The generic file worker supports root and non-root without self-admission."""
import pytest
from tools import trusted_execution_worker as worker


@pytest.mark.parametrize("uid", [0, 10001])
def test_worker_startup_accepts_either_host_identity(monkeypatch, tmp_path, uid):
    """Stop at worker initialization: no keys, socket, or effects are created."""
    monkeypatch.setattr(worker.os, "geteuid", lambda: uid)

    def reached_worker(*args, **kwargs):
        raise RuntimeError("WORKER_INITIALIZATION_REACHED")

    monkeypatch.setattr(worker, "TrustedWriter", reached_worker)
    with pytest.raises(RuntimeError, match="WORKER_INITIALIZATION_REACHED"):
        worker.serve({
            "output_root": str(tmp_path), "journal_root": str(tmp_path),
            "private_key": str(tmp_path / "unused.pem"),
            "eg_url": "http://127.0.0.1:18766", "eg_api_key": "unused",
            "executor_id": "trusted-worker-generic-mode-check",
            "socket_path": str(tmp_path / "worker.sock"),
        })
