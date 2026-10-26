"""Three unrelated generic high-effect adapter classes with distinct approval roots.

Uses canonical EG PRE and real signed operator registry documents. The
separate-process full execution/receipt/POST tests live in
test_process_external_e2e.py; this adds the missing three-key acceptance.
"""
import json
import os
import time
from dataclasses import asdict

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.operator_runtime_registry import OperatorAdapterRegistry
from tools.high_effect_admission import AdapterCapability
from test_high_effect_gateway_integration import (
    gw, H, register_high_effect, high_pre_ref, high_pre_claim, signed, pub,
)
from test_external_registry_live_pre import binding


def test_three_independently_approved_generic_classes_reach_original_pre(monkeypatch, tmp_path):
    directory = tmp_path / "operator"
    directory.mkdir(mode=0o700)
    operator = Ed25519PrivateKey.generate()
    classes = ("E3", "E4", "E5")
    workers = [Ed25519PrivateKey.generate() for _ in classes]
    signers = [Ed25519PrivateKey.generate() for _ in classes]
    caps = [
        AdapterCapability(
            adapter_id="trusted-adapter-generic-" + effect.lower(),
            action_type="bounded_process_run",
            effect_class=effect,
            target_prefix="/tasks/generic/",
            maximum_payload_bytes=4096,
            isolated=True,
            public_key_b64=pub(worker),
            ci_only=False,
        )
        for effect, worker in zip(classes, workers)
    ]
    keys = {cap.adapter_id: pub(signer) for cap, signer in zip(caps, signers)}
    registry = OperatorAdapterRegistry(directory, pub(operator))
    attestations = []
    monkeypatch.setattr(
        "tools.operator_runtime_registry.probe_unix",
        lambda path, **kwargs: attestations.append((path, kwargs["expected_worker_uid"])),
    )
    for idx, cap in enumerate(caps):
        signed_binding = binding(operator, workers[idx], cap, 65101 + idx, int(time.time()))
        assert registry.activate(
            signed_binding, adapter_id=cap.adapter_id,
            capability_sha256=signed_binding["capability_sha256"],
        )["status"] == "ACTIVE_CONFIG_ONLY"

    monkeypatch.setattr(gw, "HIGH_EFFECT_CI_FIXTURE_ENABLED", False)
    monkeypatch.setattr(gw, "HIGH_EFFECT_CAPABILITIES_JSON",
                        json.dumps([asdict(cap) for cap in caps]))
    monkeypatch.setattr(gw, "EXTERNAL_ADAPTER_MODE", "enabled")
    monkeypatch.setattr(gw, "EXTERNAL_REGISTRY_DIR", str(directory))
    monkeypatch.setattr(gw, "EXTERNAL_REGISTRY_KEY", pub(operator))
    monkeypatch.setattr(gw, "EXTERNAL_ADAPTER_SOCKET", "")
    monkeypatch.setattr(gw, "EXTERNAL_ADAPTER_UID", -1)
    monkeypatch.setattr(gw, "HITL_PUBLIC_KEY_B64", "")
    monkeypatch.setattr(gw, "HIGH_EFFECT_HITL_KEYS_JSON", json.dumps(keys))
    probes = []
    monkeypatch.setattr(
        gw, "probe_unix",
        lambda path, **kwargs: probes.append((path, kwargs["expected_worker_uid"],
                                               kwargs["public_key_b64"])),
    )
    assert gw.high_effect_hitl_keys(strict=True) == keys
    for idx, cap in enumerate(caps):
        task, contract = register_high_effect()
        payload = b"{}"
        import hashlib
        action = {
            "action_type": "bounded_process_run",
            "effect_class": cap.effect_class,
            "target": "/tasks/generic/job",
            "reversible": cap.effect_class != "E5",
            "real_world_effect": True,
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "payload_bytes": len(payload),
            "proofs": [],
        }
        approval = signed(signers[idx], task, action, cap.adapter_id, 1, time.time())
        response = H.raw_eval(
            task, contract, 0, claims=[high_pre_claim(high_pre_ref(task, 0))],
            action=action, hitl_approval=approval,
        )
        assert response.status_code == 200, response.text
        assert response.json()["verdict"] == "READY_TO_EXECUTE", response.text
        assert response.json()["high_effect_pin"]["public_key_b64"] == pub(workers[idx])
        assert probes[-1] == (
            "/run/" + cap.adapter_id + "/worker.sock", 65101 + idx, pub(workers[idx])
        )
        assert gw.hitl_key_for(cap) == keys[cap.adapter_id]
    assert len(probes) == len(attestations) == 3

    # A valid signature from a different authorized adapter is not transferable.
    task, contract = register_high_effect()
    cap = caps[0]
    action = {
        "action_type": "bounded_process_run",
        "effect_class": cap.effect_class,
        "target": "/tasks/generic/job",
        "reversible": True,
        "real_world_effect": True,
        "payload_sha256": __import__("hashlib").sha256(b"{}").hexdigest(),
        "payload_bytes": 2,
        "proofs": [],
    }
    wrong = signed(signers[1], task, action, cap.adapter_id, 1, time.time())
    rejected = H.raw_eval(
        task, contract, 0, claims=[high_pre_claim(high_pre_ref(task, 0))],
        action=action, hitl_approval=wrong,
    )
    assert rejected.status_code != 200 or rejected.json().get("verdict") != "READY_TO_EXECUTE"
