"""One generic process profile reused across independent task IDs.

All operator/HITL/worker keys here are disposable CI keys; never production.
"""
import base64
import hashlib
import os
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.execution_receipts import verify
from tools.generic_bounded_process_adapter import (
    GenericProcessExecutor, ProcessDenied, verify_profiles
)
from tools.trusted_execution_worker import canon, fingerprint


def public_b64(private):
    return base64.b64encode(
        private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()


def prepare(tmp_path):
    own = tmp_path / "private"
    own.mkdir(mode=0o700)
    assert own.stat().st_uid == os.geteuid()
    content = own / "fixture.txt"
    content.write_text("fixed original command output\n")
    exe = Path("/usr/bin/cat")
    operator, hitl, worker = (
        Ed25519PrivateKey.generate() for _ in range(3)
    )
    stamp = time.time()
    policy = {
        "version": 1, "adapter_id": "trusted-adapter-generic-process",
        "issued_at": stamp - 5, "expires_at": stamp + 600,
        "nonce": "operator-profile-v1-test-1234",
        "profiles": [{
            "profile_id": "readonly_cat", "target_prefix": "/tasks/",
            "executable": str(exe),
            "executable_sha256": hashlib.sha256(exe.read_bytes()).hexdigest(),
            "cwd": str(own), "fixed_args": [str(content)],
            "timeout_seconds": 5, "max_output_bytes": 4096
        }]
    }
    signed = {**policy, "signature_b64":
        base64.b64encode(operator.sign(canon(policy))).decode()}
    return signed, operator, hitl, worker, own, content


def approval(task, action, hitl, gate_cp=3):
    fingerprint_value = fingerprint(action)
    issued = time.time() - 1
    form = {
        "version": 1, "task_id": task, "step_key": "01.01",
        "gate_checkpoint_no": gate_cp,
        "action_fingerprint": fingerprint_value,
        "adapter_id": "trusted-adapter-generic-process",
        "decision": "APPROVED", "issued_at": issued,
        "expires_at": issued + 120,
        "nonce": "distinct-hitl-nonce-per-gate-" + task
    }
    return {**form, "signature_b64":
        base64.b64encode(hitl.sign(canon(form))).decode()}


def action_for(target):
    payload = canon({"profile_id": "readonly_cat"})
    return {
        "action_type": "bounded_process_run", "effect_class": "E3",
        "target": target, "payload_bytes": len(payload),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "real_world_effect": True, "reversible": False,
        "proofs": []
    }


def test_profile_requires_real_operator_signature_and_exact_binary(tmp_path):
    signed, operator, hitl, worker, own, content = prepare(tmp_path)
    adapter, profiles = verify_profiles(signed, public_b64(operator))
    assert adapter == "trusted-adapter-generic-process"
    assert profiles["readonly_cat"]["fixed_args"] == [str(content)]
    bad = dict(signed)
    bad["expires_at"] += 60
    with pytest.raises(ProcessDenied, match="SIGNATURE"):
        verify_profiles(bad, public_b64(operator))
    with pytest.raises(ProcessDenied, match="SIGNATURE"):
        verify_profiles(signed, public_b64(hitl))
    changed = dict(signed)
    changed["profiles"] = [dict(signed["profiles"][0])]
    changed["profiles"][0]["executable_sha256"] = "0" * 64
    changed_body = {k: changed[k] for k in signed if k != "signature_b64"}
    changed["signature_b64"] = base64.b64encode(
        operator.sign(canon(changed_body))).decode()
    with pytest.raises(ProcessDenied, match="DRIFT"):
        verify_profiles(changed, public_b64(operator))
    with pytest.raises(ProcessDenied, match="EXPIRED"):
        verify_profiles(signed, public_b64(operator), now=time.time() + 1000)


def test_root_may_not_provision_an_independent_worker(tmp_path):
    if os.geteuid() != 0:
        pytest.skip("positive nonroot worker enforced in next test")
    signed, operator, hitl, worker, own, _ = prepare(tmp_path)
    with pytest.raises(ProcessDenied, match="NONROOT"):
        GenericProcessExecutor(
            policy=signed, trusted_operator_public_b64=public_b64(operator),
            hitl_public_b64=public_b64(hitl),
            worker_key=worker, eg_url="http://127.0.0.1:18766",
            eg_api_key="test", journal_root=own
        )


@pytest.mark.skipif(os.geteuid() == 0, reason="nonroot execution is mandatory")
def test_same_independent_worker_proves_two_different_task_receipts(tmp_path, monkeypatch):
    signed, operator, hitl, worker, own, _ = prepare(tmp_path)
    journal = own / "journal"
    journal.mkdir(mode=0o700)
    runner = GenericProcessExecutor(
        policy=signed, trusted_operator_public_b64=public_b64(operator),
        hitl_public_b64=public_b64(hitl), worker_key=worker,
        eg_url="http://127.0.0.1:18766", eg_api_key="test-gate-key",
        journal_root=journal
    )
    tasks = ["task-compiler", "task-document-check"]
    proofs = []
    for task in tasks:
        action = action_for("/tasks/" + task)
        signed_hitl = approval(task, action, hitl)
        created_at = (datetime.now(timezone.utc) -
                      timedelta(seconds=2)).isoformat()
        def read_gate(url, key, task_id):
            assert task_id == task
            return ({
                "current_step": "01.01", "status": "RUNNING",
                "latest_checkpoint": {
                    "checkpoint_no": 3, "verdict": "READY_TO_EXECUTE"
                },
                "pending_execution_gate": {
                    "pre_checkpoint_no": 3,
                    "action_fingerprint": fingerprint(action)
                }
            }, {
                "checkpoints": [{
                    "checkpoint_no": 3, "created_at": created_at,
                    "verdict": "READY_TO_EXECUTE",
                    "high_effect_pin": {
                        "adapter_id": "trusted-adapter-generic-process",
                        "public_key_b64": public_b64(worker),
                        "approval_nonce": signed_hitl["nonce"],
                        "action_fingerprint": fingerprint(action)
                    }
                }]
            })
        monkeypatch.setattr(
            "tools.generic_bounded_process_adapter.api", read_gate)
        receipt = runner.run_once(
            task_id=task, step_key="01.01", action=action,
            profile_id="readonly_cat", signed_hitl=signed_hitl,
            gate_checkpoint_no=3
        )
        ok, reason = verify(receipt, public_b64=public_b64(worker),
            task_id=task, step_key="01.01", gate_checkpoint_no=3,
            action_fingerprint=fingerprint(action), target=action["target"],
            gate_created_at=created_at)
        assert ok, reason
        proofs.append(receipt)
        with pytest.raises(ProcessDenied, match="RECONCILIATION_REQUIRED"):
            runner.run_once(
                task_id=task, step_key="01.01", action=action,
                profile_id="readonly_cat", signed_hitl=signed_hitl,
                gate_checkpoint_no=3
            )
    assert proofs[0]["action_fingerprint"] != proofs[1]["action_fingerprint"]
    assert proofs[0]["executor_id"] == proofs[1]["executor_id"]
    assert len(list(journal.glob("*.json"))) == 2
    assert all(p["output_bytes"] > 0 for p in proofs)


@pytest.mark.skipif(os.geteuid() == 0, reason="nonroot execution is mandatory")
def test_no_valid_gate_or_hitl_means_no_process_effect(tmp_path, monkeypatch):
    signed, operator, hitl, worker, own, _ = prepare(tmp_path)
    journal = own / "journal"
    journal.mkdir(mode=0o700)
    runner = GenericProcessExecutor(
        policy=signed, trusted_operator_public_b64=public_b64(operator),
        hitl_public_b64=public_b64(hitl), worker_key=worker,
        eg_url="http://127.0.0.1:18766", eg_api_key="test",
        journal_root=journal
    )
    action = action_for("/tasks/subject")
    a = approval("task-denied", action, hitl)
    monkeypatch.setattr("tools.generic_bounded_process_adapter.api",
        lambda *_: ({}, {"checkpoints": []}))
    with pytest.raises(ProcessDenied, match="SIGNED_PRE_REQUIRED"):
        runner.run_once(task_id="task-denied", step_key="01.01",
            action=action, profile_id="readonly_cat",
            signed_hitl=a, gate_checkpoint_no=3)
    with pytest.raises(Exception, match="HITL_INVALID_SIGNATURE"):
        runner.run_once(task_id="task-denied", step_key="01.01",
            action=action, profile_id="readonly_cat",
            signed_hitl={**a, "signature_b64": base64.b64encode(b"x"*64).decode()},
            gate_checkpoint_no=3)
    assert not list(journal.iterdir())

def test_generic_process_signer_is_compatible_with_existing_liveness_protocol():
    from tools.adapter_liveness import challenge, attest, verify
    worker = Ed25519PrivateKey.generate()
    task = "task-fixture-A"
    cap_sha = "a" * 64
    fp = "b" * 64
    scope = challenge(
        adapter_id="trusted-adapter-generic-process",
        capability_sha256=cap_sha,
        task_id=task, step_key="01.01",
        gate_checkpoint_no=3, action_fingerprint=fp
    )
    reply = attest(scope, adapter_id="trusted-adapter-generic-process",
                   capability_sha256=cap_sha, private_key=worker)
    assert verify(scope, reply,
                  adapter_id="trusted-adapter-generic-process",
                  capability_sha256=cap_sha,
                  public_key_b64=public_b64(worker))
    assert "status" not in reply, "liveness response must have exact schema"
    with pytest.raises(Exception):
        verify(scope, reply,
               adapter_id="trusted-adapter-generic-process",
               capability_sha256="c" * 64,
               public_key_b64=public_b64(worker))
