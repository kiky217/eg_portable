"""Production GitHub worker must only start with independently protected files."""
import json,os
import pytest
from tools.github_worker_service import load_worker,WorkerConfigurationDenied

def test_nonroot_worker_rejects_injected_untrusted_operator_config(tmp_path,monkeypatch):
    real_uid=os.getuid()
    monkeypatch.setattr("tools.github_worker_service.os.getuid",lambda:real_uid if real_uid else 10001)
    file=tmp_path/"operator.json"
    file.write_text("{}")
    file.chmod(0o600)
    with pytest.raises(WorkerConfigurationDenied,match="INVALID_OPERATOR_CONFIG|UNSAFE_PRIVATE_WORKER_FILE"):
        load_worker(str(file))

def test_protected_worker_config_rejects_world_readability(tmp_path,monkeypatch):
    real_uid=os.getuid()
    if real_uid==0:
        pytest.skip("root cannot instantiate independent worker")
    file=tmp_path/"operator.json"
    file.write_text("{}")
    file.chmod(0o644)
    with pytest.raises(WorkerConfigurationDenied,match="UNSAFE_PRIVATE_WORKER_FILE"):
        load_worker(str(file))

def test_root_can_never_start_production_worker(tmp_path,monkeypatch):
    monkeypatch.setattr("tools.github_worker_service.os.getuid",lambda:0)
    with pytest.raises(WorkerConfigurationDenied,match="INDEPENDENT_NONROOT_WORKER_REQUIRED"):
        load_worker(str(tmp_path/"nonexistent"))
