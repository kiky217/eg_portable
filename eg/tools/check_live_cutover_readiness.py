#!/usr/bin/env python3
"""Read-only fail-closed readiness check for an EG live cutover.

Reads canonical SQLite and authenticated EG HTTP state; never invokes a write,
POST, service control, key generation, or task action. This tool cannot attest
remote root isolation: a separate, externally audited trust domain is required.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from urllib.request import Request, urlopen

from tools.trusted_execution_worker import MAX_NEW_WRITE_LEASE_SECONDS

def parse_env(path: Path) -> dict[str, str]:
    values = {}
    for line in path.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if sep:
            values[key.strip()] = value.strip().strip('"').strip("'")
    return values

def get_json(url: str, api_key: str) -> dict:
    req = Request(url, method="GET", headers={"X-Evaluation-Key": api_key})
    with urlopen(req, timeout=10) as response:
        assert response.status == 200
        return json.load(response)

def canonical(db_path: Path, task: str) -> dict:
    conn = sqlite3.connect("file:" + str(db_path) + "?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT status,contract_status,checkpoint_no FROM task_registry WHERE task_id=?",
            (task,),
        ).fetchone()
        if row is None:
            raise RuntimeError("TASK_NOT_FOUND")
        counts = conn.execute(
            "SELECT COUNT(*) AS total,SUM(verified) AS verified "
            "FROM task_registry_steps WHERE task_id=?", (task,),
        ).fetchone()
        audit = conn.execute(
            "SELECT COUNT(*) AS records,MAX(seq) AS last_seq FROM audit",
        ).fetchone()
        gate = conn.execute(
            "SELECT step_key,pre_checkpoint_no,created_at,action_fingerprint "
            "FROM execution_gates WHERE task_id=? AND consumed=0 "
            "ORDER BY pre_checkpoint_no DESC LIMIT 1", (task,),
        ).fetchone()
        action = None
        if gate:
            for event in conn.execute(
                "SELECT request_json FROM audit WHERE task_id=? AND event_type='EVALUATION' "
                "ORDER BY seq DESC", (task,)
            ):
                payload = json.loads(event["request_json"])
                if (
                    payload.get("step_key") == gate["step_key"]
                    and payload.get("phase") == "PRE_EXECUTION"
                    and payload.get("checkpoint_no") == gate["pre_checkpoint_no"] - 1
                    and payload.get("action")
                ):
                    action = payload["action"]
                    break
        return {
            "status": row["status"],
            "contract": row["contract_status"],
            "checkpoint": row["checkpoint_no"],
            "total": counts["total"],
            "verified": counts["verified"] or 0,
            "audit_records": audit["records"],
            "audit_last_seq": audit["last_seq"],
            "gate": dict(gate) if gate else None,
            "action": action,
        }
    finally:
        conn.close()

def classify_gate(gate: dict | None, action: dict | None,
                  now: datetime | None = None) -> dict:
    if not gate:
        return {"present": False, "requires_fresh_pre": False,
                "executable_with_current_pre": False}
    now = now or datetime.now(timezone.utc)
    created = datetime.fromisoformat(gate["created_at"])
    if created.tzinfo is None:
        raise RuntimeError("GATE_CREATION_TIME_MISSING_TZ")
    elapsed = (now-created).total_seconds()
    future = elapsed < 0
    expired = elapsed > MAX_NEW_WRITE_LEASE_SECONDS
    target = Path(action.get("target", "")) if action else None
    effect_exists = target.exists() or target.is_symlink() if target else None
    concrete = bool(action and action.get("action_type") in ("write","read"))
    return {
        "present": True,
        "step": gate["step_key"],
        "pre_checkpoint": gate["pre_checkpoint_no"],
        "lease_seconds": MAX_NEW_WRITE_LEASE_SECONDS,
        "age_seconds": max(0, int(elapsed)),
        "expired_for_new_effect": expired,
        "future_dated": future,
        "concrete_action": concrete,
        "target_exists": effect_exists,
        "target_type": "symlink" if target and target.is_symlink() else (
            "regular" if target and target.is_file() else "absent"
        ),
        "executable_with_current_pre": False,
        "requires_fresh_pre": bool(concrete and expired and effect_exists is False),
    }

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("db", "task", "live-url", "runtime-env-file", "report"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    db = Path(args.db).resolve()
    runtime = Path(args.runtime_env_file).resolve()
    report = Path(args.report).resolve()
    if not db.is_file() or not runtime.is_file():
        raise RuntimeError("INPUTS_NOT_FOUND")
    if report.exists():
        raise RuntimeError("REPORT_ALREADY_EXISTS")
    env = parse_env(runtime)
    api_key = env.get("EVALUATION_GATEWAY_API_KEY")
    if not api_key:
        raise RuntimeError("API_KEY_UNAVAILABLE")
    url = args.live_url.rstrip("/")
    if url not in ("http://127.0.0.1:18765", "http://localhost:18765"):
        raise RuntimeError("REFUSE_NONLOCAL_OR_UNEXPECTED_LIVE_URL")
    before = canonical(db, args.task)
    audit = get_json(url + "/v1/audit/verify", api_key)
    live = get_json(url + "/v1/tasks/" + args.task + "/state", api_key)
    if audit.get("status") != "PASS":
        raise RuntimeError("LIVE_AUDIT_NOT_VERIFIED")
    if (
        audit["records"] != before["audit_records"]
        or live["latest_checkpoint"]["checkpoint_no"] != before["checkpoint"]
        or live["contract_status"] != before["contract"]
        or live["pending_execution_gate"] is None and before["gate"] is not None
    ):
        raise RuntimeError("LIVE_DB_API_MISMATCH")
    gate = before["gate"]
    if gate and (
        live["pending_execution_gate"]["pre_checkpoint_no"] != gate["pre_checkpoint_no"]
        or live["current_step"] != gate["step_key"]
        or live["pending_execution_gate"]["action_fingerprint"] != gate["action_fingerprint"]
    ):
        raise RuntimeError("LIVE_GATE_MISMATCH")
    after = canonical(db, args.task)
    if after != before:
        raise RuntimeError("CANONICAL_CHANGED_DURING_READ")
    gate_status = classify_gate(gate, before["action"])
    blockers = [
        "EXTERNAL_EXECUTOR_TRUST_DOMAIN_NOT_VERIFIED",
        "PRODUCTION_SINGLE_WRITER_CUTOVER_NOT_PERFORMED",
    ]
    if gate_status.get("expired_for_new_effect"):
        blockers.append("EXISTING_PRE_LEASE_EXPIRED_FOR_NEW_EFFECT")
    if before["verified"] < before["total"]:
        blockers.append("CANONICAL_ACCEPTANCE_INCOMPLETE")
    output = {
        "status": "BLOCKED",
        "task_id": args.task,
        "live_service_version": audit.get("version"),
        "audit": audit["status"],
        "audit_records": before["audit_records"],
        "audit_head_sha256": audit.get("head"),
        "checkpoint": before["checkpoint"],
        "verified_steps": before["verified"],
        "total_steps": before["total"],
        "current_step": live["current_step"],
        "latest_verdict": live["latest_checkpoint"]["verdict"],
        "gate": gate_status,
        "blockers": blockers,
        "production_cutover_performed": False,
        "external_signer_root_isolation_proven": False,
        "canonical_mutation_performed": False,
    }
    report.parent.mkdir(parents=True,exist_ok=True)
    fd = os.open(report, os.O_CREAT|os.O_EXCL|os.O_WRONLY, 0o600)
    with os.fdopen(fd,"w") as f:
        json.dump(output,f,indent=2,sort_keys=True)
        f.write("\n")
    print(json.dumps({"status": output["status"], "checkpoint": output["checkpoint"],
        "gate": gate_status, "blockers": blockers,
        "report": str(report)}, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
