#!/usr/bin/env python3
"""Create an Evaluation Gateway evidence manifest v4 on a trusted producer.

Usage:
  notarize_evidence.py PRIVATE_KEY_PEM TASK_DIR BINDINGS_JSON

BINDINGS_JSON is a JSON file containing a non-empty list of binding objects. Every binding is
validated against the exact schema the gateway enforces, and its signed `matcher` assertion is
checked against stdout.log BEFORE signing, so the notary never attests something the evidence
does not show. state.json must report status PASS and exit_code 0.

Binding schemas (all keys required, no extras):
  step_criterion: kind, eg_task_id, step_key, criterion_index, criterion, phase, checkpoint_no, matcher
  task_criterion: kind, eg_task_id, criterion_index, criterion, phase(=POST_EXECUTION), checkpoint_no, matcher
  action_proof:   kind, eg_task_id, step_key, purpose, action_intent_fingerprint, phase(=PRE_EXECUTION), checkpoint_no, matcher
  matcher:        {"kind": contains|not_contains|equals, "value": non-blank string <= 10000 chars}

checkpoint_no: PRE_EXECUTION / FACT_CHECK -> the request checkpoint_no being submitted;
               POST_EXECUTION -> gate_checkpoint_no returned by the READY_TO_EXECUTE PRE response.
The private key must never be mounted into or exposed to the gateway/agent.
"""
import base64
import hashlib
import json
import math
import sys
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_pem_private_key

MANIFEST_VERSION = 4
MAX_BINDINGS = 200
MAX_MATCHER_VALUE_CHARS = 10_000
MATCHER_KINDS = ("contains", "not_contains", "equals")
PHASES = ("PRE_EXECUTION", "POST_EXECUTION", "FACT_CHECK")
PURPOSES = ("sandbox_pass", "rollback_ready", "reversible")
SCHEMAS = {
    "step_criterion": ({"kind", "eg_task_id", "step_key", "criterion_index", "criterion", "phase", "checkpoint_no", "matcher"}, PHASES),
    "task_criterion": ({"kind", "eg_task_id", "criterion_index", "criterion", "phase", "checkpoint_no", "matcher"}, ("POST_EXECUTION",)),
    "action_proof": ({"kind", "eg_task_id", "step_key", "purpose", "action_intent_fingerprint", "phase", "checkpoint_no", "matcher"}, ("PRE_EXECUTION",)),
}


def canon(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def die(msg):
    raise SystemExit(msg)


def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def validate_binding(b, stdout_text):
    kind = b.get("kind")
    if kind not in SCHEMAS:
        die(f"unknown binding kind: {kind!r}")
    keys, phases = SCHEMAS[kind]
    if set(b) != keys:
        die(f"{kind} binding keys must be exactly {sorted(keys)}")
    if b["phase"] not in phases:
        die(f"{kind} binding phase must be one of {list(phases)}")
    if not is_int(b["checkpoint_no"]) or b["checkpoint_no"] < 0:
        die("checkpoint_no must be a non-negative integer")
    if "criterion_index" in b and (not is_int(b["criterion_index"]) or b["criterion_index"] < 0):
        die("criterion_index must be a non-negative integer")
    if kind == "action_proof" and b["purpose"] not in PURPOSES:
        die(f"purpose must be one of {list(PURPOSES)}")
    m = b["matcher"]
    if not (isinstance(m, dict) and set(m) == {"kind", "value"} and m["kind"] in MATCHER_KINDS
            and isinstance(m["value"], str) and m["value"].strip() and len(m["value"]) <= MAX_MATCHER_VALUE_CHARS):
        die("matcher must be {kind: contains|not_contains|equals, value: non-blank string}")
    if m["kind"] == "contains":
        holds = m["value"] in stdout_text
    elif m["kind"] == "not_contains":
        holds = m["value"] not in stdout_text
    else:
        holds = stdout_text.strip() == m["value"].strip()
    if not holds:
        die(f"matcher assertion does not hold against stdout.log for {kind} binding; refusing to sign")


if len(sys.argv) != 4:
    die("usage: notarize_evidence.py PRIVATE_KEY_PEM TASK_DIR BINDINGS_JSON")

key_path, task_dir, bindings_path = map(Path, sys.argv[1:])
priv = load_pem_private_key(key_path.read_bytes(), password=None)
state_path = task_dir / "state.json"
stdout_path = task_dir / "stdout.log"
meta_path = task_dir / "evidence.json"

state_raw = state_path.read_bytes()
stdout_raw = stdout_path.read_bytes()
state = json.loads(state_raw)
bindings = json.loads(bindings_path.read_text(encoding="utf-8"))
if not isinstance(bindings, list) or not bindings or len(bindings) > MAX_BINDINGS or any(not isinstance(x, dict) for x in bindings):
    die(f"BINDINGS_JSON must contain 1..{MAX_BINDINGS} JSON objects")
serialized = [canon(x) for x in bindings]
if len(serialized) != len(set(serialized)):
    die("duplicate binding objects are forbidden")

task_id = str(state.get("task_id", ""))
finished_at = state.get("finished_at")
if not task_id or isinstance(finished_at, bool) or not isinstance(finished_at, (int, float)) or not math.isfinite(finished_at):
    die("state.json requires task_id and finite numeric finished_at")
if task_dir.name != task_id:
    die("TASK_DIR basename must exactly equal state.json task_id")
if state.get("status") != "PASS" or state.get("exit_code") != 0:
    die("state.json must report status PASS and exit_code 0 before notarization")

stdout_text = stdout_raw.decode("utf-8", errors="replace")
for b in bindings:
    validate_binding(b, stdout_text)

payload = {
    "manifest_version": MANIFEST_VERSION,
    "task_id": task_id,
    "state_sha256": hashlib.sha256(state_raw).hexdigest(),
    "stdout_sha256": hashlib.sha256(stdout_raw).hexdigest(),
    "finished_at": finished_at,
    "bindings": bindings,
}
signature = base64.b64encode(priv.sign(canon(payload).encode("utf-8"))).decode("ascii")
meta_path.write_text(canon({**payload, "notary_ed25519_signature_b64": signature}), encoding="utf-8")
for p in (state_path, stdout_path, meta_path):
    p.chmod(0o600)
task_dir.chmod(0o700)
print(canon({"task_id": task_id, "stdout_sha256": payload["stdout_sha256"], "binding_count": len(bindings), "manifest_version": MANIFEST_VERSION}))
