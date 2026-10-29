"""Real source-file write is gated, independent, receipt-backed, and verified."""
import base64
import subprocess
import sys
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
import pytest
import harness as H
from harness import CLIENT, HEAD, register, do_pre, do_post, bounded_write_action
from tools import trusted_execution_worker as worker


@pytest.mark.parametrize("nested",[False,True])
def test_source_creation_scanner_e2e(tmp_path, monkeypatch,nested):
    output = tmp_path / "outputs"; output.mkdir(mode=0o700)
    journal = tmp_path / "journal"; journal.mkdir(mode=0o700)
    monkeypatch.setattr(H.gw, "EXECUTOR_OUTPUT_ROOT", str(output))
    monkeypatch.setenv("EVALUATION_GATEWAY_EXECUTOR_ALLOWED_SUFFIXES", ".txt,.json,.py")
    task, contract = register(physical=True)
    if nested:
        sub=output / "project"; sub.mkdir(mode=0o700)
        package=sub / "src"; package.mkdir(mode=0o700)
        source=package / "scanner.py"
    else:
        source = output / "scanner.py"
    payload = b"def scan_contract(value):\n    return value.upper()\n"
    action = bounded_write_action(task, 0, target=str(source), payload=payload)
    key = tmp_path / "signer.pem"
    key.write_bytes(H.EXEC_PRIV.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    key.chmod(0o600)
    def live_state(_url, _key, which):
        assert which == task
        return (CLIENT.get(f"/v1/tasks/{which}/state", headers=HEAD).json(),
                CLIENT.get(f"/v1/tasks/{which}", headers=HEAD).json())
    monkeypatch.setattr(worker, "api", live_state)
    signer = worker.TrustedWriter(output, journal, key, "http://127.0.0.1:1",
                                  "fixture", "trusted-worker-source-fixture",
                                  allowed_suffixes=[".txt",".json",".py"])
    req = {"task_id": task, "step_key": "01.01", "action": action,
           "data_b64": base64.b64encode(payload).decode()}
    with pytest.raises(worker.WorkerDenied):
        signer.execute(req)
    assert not source.exists()
    pre, _ = do_pre(task, contract, 0, action=action)
    assert pre.status_code == 200 and pre.json()["verdict"] == "READY_TO_EXECUTE"
    receipt = signer.execute(req)
    assert source.read_bytes() == payload
    check = subprocess.run([sys.executable, "-B", "-c",
        'import importlib.util,sys; p=sys.argv[1];s=importlib.util.spec_from_file_location("scanner",p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);assert m.scan_contract("ca") == "CA"',
        str(source)], capture_output=True, text=True, timeout=10)
    assert check.returncode == 0, check.stderr
    original_inode = source.stat().st_ino
    assert signer.execute(req) == receipt
    post, _ = do_post(task, contract, pre, action=action, execution_receipt=receipt)
    assert post.status_code == 200 and post.json()["step_verified"]
    assert CLIENT.get("/v1/audit/verify", headers=HEAD).json()["status"] == "PASS"
    with pytest.raises(worker.WorkerDenied, match="EG_PRE_NOT_READY"):
        signer.execute(req)
    assert source.stat().st_ino == original_inode
