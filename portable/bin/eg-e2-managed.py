#!/usr/bin/env python3
"""Scoped fail-closed E2 execution demo: signed PRE/POST, action proof, durable intent.

A managed operation only; it does not intercept arbitrary Colab shell processes.
"""
import base64
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path
from urllib.error import HTTPError

W = Path("/content/workspace")
D = W / "artifacts/eg-managed"
JOURNAL = D / "journal"
SANDBOX = D / "sandbox"
DEMO = D / "outputs"
for directory in (D, JOURNAL, SANDBOX, DEMO):
    directory.mkdir(parents=True, exist_ok=True)
spec = importlib.util.spec_from_file_location("gated_e0", W / "bin/eg-gated-run.py")
eg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(eg)
CHILD = "Registered E2 action applied and independently read back"
PARENT = "All child criteria verified"
GLOBAL = eg.GLOBAL
AGENT = eg.AGENT


def write_durable(path, data, exclusive=False):
    flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
    finally:
        pass
    dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def journal(task, stage, **details):
    p = JOURNAL / (task + ".json")
    # Stage transitions in the same process are permitted; each task ID is unique.
    # A recovered task with an unknown effect is never automatically resumed.
    data = eg.js({"task_id": task, "stage": stage, **details}).encode()
    tmp = p.with_suffix(".new")
    write_durable(tmp, data)
    os.replace(tmp, p)
    dfd = os.open(JOURNAL, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(dfd)
    finally: os.close(dfd)


def proof_binding(task, action, purpose, cp, matcher):
    intent = {k: action[k] for k in
              ("action_type", "target", "effect_class", "reversible", "real_world_effect")}
    fp = hashlib.sha256(eg.js(intent).encode()).hexdigest()
    return {
        "kind": "action_proof", "eg_task_id": task, "step_key": "01.01",
        "purpose": purpose, "action_intent_fingerprint": fp,
        "phase": "PRE_EXECUTION", "checkpoint_no": cp,
        "matcher": {"kind": "contains", "value": matcher}
    }


def prove_sandbox(task, content):
    sandbox = SANDBOX / (task + ".check")
    if sandbox.exists():
        raise RuntimeError("sandbox collision")
    write_durable(sandbox, content, exclusive=True)
    if sandbox.read_bytes() != content:
        raise RuntimeError("sandbox readback mismatch")
    sandbox.unlink()
    if sandbox.exists():
        raise RuntimeError("rollback failure")
    return True


def run():
    private = eg.load_pem_private_key((eg.EG / "notary/notary_private.pem").read_bytes(), password=None)
    protocol = hashlib.sha256((eg.EG / "local-v3.0.1/runtime/docs/EXECUTOR_PROTOCOL.md").read_bytes()).hexdigest()
    task = eg.uid("eg-e2")
    target = DEMO / (task + ".txt")
    content = ("EG_E2_RUNTIME:" + task + "\n").encode()
    digest = hashlib.sha256(content).hexdigest()
    if not str(target.resolve()).startswith(str(DEMO.resolve()) + "/"):
        raise RuntimeError("target escaped sandbox")
    if target.exists():
        raise RuntimeError("target already exists")
    contract = eg.req("POST", "/v1/tasks/register", {
        "event_id": eg.uid("register"), "task_id": task, "protocol_hash": protocol,
        "agent": AGENT,
        "original_instruction": "One sandbox-limited, reversible E2 file creation",
        "acceptance_criteria": [GLOBAL],
        "steps": [
            {"step_key": "01", "title": "Verify managed E2 operation",
             "acceptance_criteria": [PARENT], "required": True},
            {"step_key": "01.01", "title": "Apply and read back bounded E2 write",
             "acceptance_criteria": [CHILD], "required": True}
        ]})["contract_hash"]
    skeleton = {"action_type": "write", "target": str(target),
                "effect_class": "E2", "reversible": True,
                "real_world_effect": False, "proofs": []}
    prove_sandbox(task, content)
    proof_values = {
        "sandbox_pass": "SANDBOX=PASS",
        "rollback_ready": "ROLLBACK=READY",
        "reversible": "REVERSIBLE=YES"
    }
    signed_ref = eg.notarize(
        [proof_binding(task, skeleton, purpose, 0, text)
         for purpose, text in proof_values.items()],
        "\n".join(proof_values.values()), private)
    action = dict(skeleton)
    action["proofs"] = [{"purpose": purpose, "evidence":
                          {"source_type": "knid_task", "reference": signed_ref}}
                         for purpose in proof_values]
    journal(task, "PROOFS_READY", target=str(target))
    pre = eg.eval_step(task, contract, protocol, "01.01", CHILD, "PRE_EXECUTION",
                       0, 0, "PRE=PASS", private, action)
    if pre.get("verdict") != "READY_TO_EXECUTE":
        journal(task, "BLOCKED", verdict=pre.get("verdict"))
        raise RuntimeError("EG denied PRE authorization")
    journal(task, "EFFECT_UNKNOWN", target=str(target),
            gate_checkpoint_no=pre["gate_checkpoint_no"],
            pre_checkpoint_no=pre["checkpoint_no"])
    # The durable journal is fsynced before this E2 effect. A crash must not retry.
    write_durable(target, content, exclusive=True)
    actual = target.read_bytes()
    if actual != content or hashlib.sha256(actual).hexdigest() != digest:
        raise RuntimeError("runtime E2 readback failed")
    journal(task, "EFFECT_APPLIED", target=str(target), sha256=digest)
    post = eg.eval_step(task, contract, protocol, "01.01", CHILD, "POST_EXECUTION",
                        pre["checkpoint_no"], pre["gate_checkpoint_no"],
                        "SHA256=" + digest, private, action)
    if post.get("verdict") != "VERIFIED_PASS" or not post.get("step_verified"):
        raise RuntimeError("EG POST was not verified")
    journal(task, "CHILD_VERIFIED", checkpoint_no=post["checkpoint_no"], sha256=digest)
    parent_pre = eg.eval_step(task, contract, protocol, "01", PARENT, "PRE_EXECUTION",
                              post["checkpoint_no"], post["checkpoint_no"],
                              "PARENT_PRE=PASS", private, None)
    if parent_pre.get("verdict") != "READY_TO_EXECUTE":
        raise RuntimeError("EG parent PRE denied")
    final = eg.eval_step(task, contract, protocol, "01", PARENT, "POST_EXECUTION",
                         parent_pre["checkpoint_no"], parent_pre["gate_checkpoint_no"],
                         "PARENT_POST=PASS", private, None, True)
    audit = eg.req("GET", "/v1/audit/verify")
    state = eg.req("GET", "/v1/tasks/" + task + "/state")
    if not (final.get("verdict") == "VERIFIED_PASS" and
            final.get("contract_status") == "SATISFIED" and
            audit.get("status") == "PASS" and
            target.read_bytes() == content):
        raise RuntimeError("EG final/readback/audit not satisfied")
    journal(task, "EG_VERIFIED", sha256=digest, checkpoint_no=final["checkpoint_no"],
            audit_status=audit["status"])
    print(eg.js({"status": "EG_VERIFIED", "effect": "E2_FILE_WRITE",
                 "task_id": task, "sha256": digest,
                 "checkpoint": final["checkpoint_no"], "audit": audit["status"]}))


if __name__ == "__main__":
    try: run()
    except Exception as error:
        print("FAIL_CLOSED " + type(error).__name__ + ": " + str(error), file=sys.stderr)
        raise SystemExit(77)
