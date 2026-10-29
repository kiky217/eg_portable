"""Generic bounded process runner: distinct classes, live PRE, pin and no replay."""
import base64
import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from tools import generic_process_worker as gp


@pytest.fixture
def setup(tmp_path, monkeypatch):
    executable = Path("/usr/bin/cat")
    if not executable.is_file():
        pytest.skip("requires standard POSIX cat")
    journal = tmp_path / "journal"
    cwd = tmp_path / "tasks"
    journal.mkdir(mode=0o700)
    cwd.mkdir(mode=0o700)
    key = Ed25519PrivateKey.generate()
    pem = tmp_path / "executor.pem"
    pem.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    pem.chmod(0o600)
    profile = {
        "adapter_id": "trusted-adapter-generic-process",
        "action_type": "bounded_process_run",
        "effect_class": "governed_operation",
        "target": "/tasks/build",
        "executable": str(executable),
        "executable_sha256": gp.digest(executable.read_bytes()),
        "fixed_args": [],
        "cwd": str(cwd),
        "timeout_seconds": 5,
        "max_output_bytes": 4096,
        "capability_sha256": "f"*64,
    }
    worker = gp.GenericProcessWorker({
        "profile": profile, "journal_root": str(journal), "private_key": str(pem),
        "eg_url": "http://127.0.0.1:18790", "eg_api_key": "fixture-only",
    })
    payload = b"GENERIC_WORKER=PASS\n"
    action = {
        "action_type": "bounded_process_run", "effect_class": "governed_operation",
        "target": "/tasks/build", "payload_sha256": gp.digest(payload),
        "payload_bytes": len(payload), "reversible": False,
        "real_world_effect": True, "proofs": [],
    }
    cp = 1
    gate = {
        "pre_checkpoint_no": cp,
        "action_fingerprint": gp.digest(gp.canon(action)),
        "high_effect_pin": {
            "adapter_id": profile["adapter_id"], "public_key_b64": worker.public,
            "action_fingerprint": gp.digest(gp.canon(action)),
        },
    }
    state = {"current_step": "01.01", "status": "IN_PROGRESS",
             "pending_execution_gate": gate}
    details = {"task": {"contract_status": "OPEN"}, "checkpoints": [{
        "checkpoint_no": cp, "verdict": "READY_TO_EXECUTE",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }]}
    monkeypatch.setattr(gp, "api", lambda *_: (state, details))
    request = {"task_id": "test-generic-process-001", "step_key": "01.01",
               "action": action, "data_b64": base64.b64encode(payload).decode()}
    return worker, profile, state, details, request, payload, journal


@pytest.mark.parametrize("effect", ["governed_operation", "external_change", "publication"])
def test_process_profile_signed_receipt_and_no_replay(setup, effect):
    worker, profile, state, details, req, data, journal = setup
    profile["effect_class"] = effect
    req["action"]["effect_class"] = effect
    state["pending_execution_gate"]["action_fingerprint"] = gp.digest(gp.canon(req["action"]))
    state["pending_execution_gate"]["high_effect_pin"]["action_fingerprint"] = gp.digest(gp.canon(req["action"]))
    signed = worker.run(req)
    assert signed["output_sha256"] == hashlib.sha256(data).hexdigest()
    assert signed["executor_id"] == "trusted-worker-" + profile["adapter_id"]
    assert signed["gate_checkpoint_no"] == 1
    first = list(journal.glob("*.out"))
    assert len(first) == 1
    initial = first[0].stat().st_mtime_ns
    assert worker.run(req) == signed
    assert first[0].stat().st_mtime_ns == initial


def test_missing_pinned_worker_denies_before_effect(setup):
    worker, profile, state, details, req, data, journal = setup
    del state["pending_execution_gate"]["high_effect_pin"]
    with pytest.raises(gp.ProcessDenied, match="SIGNED_HITL_OR_WORKER_PIN"):
        worker.run(req)
    assert not list(journal.iterdir())


def test_changed_input_denied_before_effect(setup):
    worker, profile, state, details, req, data, journal = setup
    req["data_b64"] = base64.b64encode(b"changed").decode()
    with pytest.raises(gp.ProcessDenied, match="PROFILE_OR_PAYLOAD"):
        worker.run(req)
    assert not list(journal.iterdir())


def test_wrong_executable_hash_denies_before_effect(setup):
    worker, profile, state, details, req, data, journal = setup
    profile["executable_sha256"] = "0" * 64
    with pytest.raises(gp.ProcessDenied, match="EXECUTABLE_CHANGED"):
        worker.run(req)
    assert not list(journal.iterdir())


def test_unapproved_action_denies_before_effect(setup):
    worker, profile, state, details, req, data, journal = setup
    req["action"]["target"] = "/tasks/unapproved"
    with pytest.raises(gp.ProcessDenied, match="PROFILE_OR_PAYLOAD"):
        worker.run(req)
    assert not list(journal.iterdir())
