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
import tarfile
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from tools.trusted_execution_worker import MAX_NEW_WRITE_LEASE_SECONDS
from tools.cutover_attestation import verify_independent_cutover

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

def parse_loopback_http_url(value: str) -> str:
    """Only local HTTP endpoints on explicitly configured valid ports."""
    try:
        parsed=urlsplit(value.rstrip('/'))
        if (parsed.scheme!='http' or parsed.hostname not in
                ('127.0.0.1','localhost','::1') or
                parsed.username is not None or parsed.password is not None or
                parsed.path or parsed.query or parsed.fragment or
                parsed.port is None or not 1<=parsed.port<=65535):
            raise ValueError('URL_NOT_RESTRICTED_LOOPBACK')
        return value.rstrip('/')
    except ValueError as error:
        raise RuntimeError('REFUSE_NONLOCAL_OR_UNEXPECTED_LIVE_URL') from error

def _next_current_step(rows) -> str | None:
    """Same postorder as EG hierarchy: children before parent, siblings numeric."""
    keys=[row['step_key'] for row in rows]
    verified={row['step_key'] for row in rows if row['verified']}
    children={}
    for key in keys:
        parent=key.rsplit('.',1)[0] if '.' in key else None
        children.setdefault(parent,[]).append(key)
    ordered=[]
    def walk(key):
        for child in sorted(children.get(key,[]),
                            key=lambda v:int(v.rsplit('.',1)[-1])):
            walk(child)
        ordered.append(key)
    for root in sorted(children.get(None,[]),key=lambda v:int(v)):
        walk(root)
    return next((key for key in ordered if key not in verified),None)

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
        steps=conn.execute(
            "SELECT step_key,verified FROM task_registry_steps "
            "WHERE task_id=? ORDER BY step_no",(task,)
        ).fetchall()
        current=_next_current_step(steps)
        gate=None
        if current:
            candidate=conn.execute(
                "SELECT step_key,pre_checkpoint_no,created_at,action_fingerprint,"
                "pre_verdict,consumed FROM execution_gates "
                "WHERE task_id=? AND step_key=? ORDER BY gate_id DESC LIMIT 1",
                (task,current),
            ).fetchone()
            if (candidate and candidate["pre_verdict"]=="READY_TO_EXECUTE"
                    and not candidate["consumed"]):
                gate=candidate
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
            "gate": {k:gate[k] for k in ("step_key","pre_checkpoint_no",
                     "created_at","action_fingerprint")} if gate else None,
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

def inspect_completed_cutover(path: Path | None, audit: dict,
                              state: dict, db_path: Path,
                              independent_attestation: Path | None = None,
                              cutover_public_key_b64: str | None = None) -> dict:
    """Check reported cutover file consistency WITHOUT certifying execution.

    Self-reported metadata, matching hashes, and a safe tar format do not
    prove an independently authorized cutover or a rehearsed restore.
    Never return verified=True until external provenance and actual restore
    rehearsal have a distinct verifiable contract.
    """
    if path is None:
        return {"verified": False, "reason": "NO_CUTOVER_REPORT_SUPPLIED"}
    if not path.is_file():
        return {"verified": False, "reason": "CUTOVER_REPORT_MISSING"}
    try:
        report = json.loads(path.read_text())
        if (report.get("status") != "CUTOVER_VERIFIED"
                or report.get("to") != audit.get("version")
                or not isinstance(report.get("audit_records"), int)
                or report["audit_records"] < 1
                or report["audit_records"] > audit.get("records", 0)
                or not report.get("legacy_runtime_directory_removed")
                or not report.get("rollback_available")):
            raise ValueError("CUTOVER_REPORT_DOES_NOT_MATCH_LIVE_EG")
        if report.get("checkpoint", -1) > state["checkpoint"]:
            raise ValueError("CUTOVER_CHECKPOINT_FUTURE")
        with sqlite3.connect("file:" + str(db_path) + "?mode=ro",
                             uri=True) as conn:
            record = conn.execute(
                "SELECT record_hash FROM audit WHERE seq=?",
                (report["audit_records"],)).fetchone()
        if record is None or record[0] != report["audit_head"]:
            raise ValueError("CUTOVER_AUDIT_RECORD_NOT_PRESERVED")
        paths = [
            ("db_dump", "db_dump_sha256"),
            ("anchor_copy", "anchor_sha256"),
            ("evidence_backup", "evidence_sha256"),
        ]
        for name, fingerprint in paths:
            file = Path(report[name]).resolve(strict=True)
            if not file.is_file() or file.stat().st_size == 0:
                raise ValueError("CUTOVER_BACKUP_MISSING_" + name)
            h = hashlib.sha256()
            with file.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1 << 20), b""):
                    h.update(chunk)
            if h.hexdigest() != report[fingerprint]:
                raise ValueError("CUTOVER_BACKUP_DIGEST_MISMATCH_" + name)
        old = Path(report["legacy_source_archive"]).resolve(strict=True)
        if not old.is_file() or old.stat().st_size == 0:
            raise ValueError("CUTOVER_ROLLBACK_RUNTIME_NOT_PRESERVED")
        expected=report.get("legacy_source_archive_sha256")
        if not isinstance(expected,str) or len(expected)!=64:
            raise ValueError("CUTOVER_ROLLBACK_ARCHIVE_DIGEST_REQUIRED")
        archive_digest=hashlib.sha256(old.read_bytes()).hexdigest()
        if archive_digest!=expected:
            raise ValueError("CUTOVER_ROLLBACK_ARCHIVE_DIGEST_MISMATCH")
        try:
            with tarfile.open(old,mode="r:*") as archive:
                entries=archive.getmembers()
                if not entries or any(Path(e.name).is_absolute() or
                                      '..' in Path(e.name).parts or
                                      not (e.isfile() or e.isdir())
                                      for e in entries):
                    raise ValueError("CUTOVER_ROLLBACK_ARCHIVE_UNSAFE")
                # Read every file stream to detect truncation/format corruption.
                for entry in entries:
                    if entry.isfile():
                        stream=archive.extractfile(entry)
                        if stream is None:
                            raise ValueError("CUTOVER_ROLLBACK_ARCHIVE_UNREADABLE")
                        for _ in iter(lambda:stream.read(1 << 20),b''):
                            pass
        except (tarfile.TarError,EOFError) as exc:
            raise ValueError("CUTOVER_ROLLBACK_ARCHIVE_INVALID") from exc
        independent,reason=verify_independent_cutover(
            path,old,independent_attestation,cutover_public_key_b64)
        return {
            "verified": bool(independent),
            "file_consistency_checked": True,
            "independent_provenance_verified": bool(independent),
            "restore_rehearsal_verified": bool(independent),
            "reason": reason if independent else (
                "CUTOVER_REPORT_CONSISTENT_BUT_INDEPENDENT_PROOF_MISSING"
                if reason=="INDEPENDENT_CUTOVER_ATTESTATION_MISSING"
                else "CUTOVER_REPORT_CONSISTENT_BUT_"+reason),
            "receipt_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    except (OSError, KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return {"verified": False, "reason": str(exc)[:180]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("db", "task", "live-url", "runtime-env-file", "report"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--cutover-report", help="Cutover report for read-only verification")
    parser.add_argument("--cutover-attestation", help="Externally signed cutover+restore attestation")
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
    url = parse_loopback_http_url(args.live_url)
    before = canonical(db, args.task)
    audit = get_json(url + "/v1/audit/verify", api_key)
    live = get_json(url + "/v1/tasks/" + args.task + "/state", api_key)
    if audit.get("status") != "PASS":
        raise RuntimeError("LIVE_AUDIT_NOT_VERIFIED")
    if (
        audit["records"] != before["audit_records"]
        or (live.get("latest_checkpoint") or {}).get("checkpoint_no",0) != before["checkpoint"]
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
    cutover = inspect_completed_cutover(
        Path(args.cutover_report).resolve() if args.cutover_report else None,
        audit, before, db,
        independent_attestation=Path(args.cutover_attestation).resolve() if args.cutover_attestation else None,
        cutover_public_key_b64=env.get("EVALUATION_GATEWAY_CUTOVER_PUBLIC_KEY_B64"))
    blockers = ["EXTERNAL_EXECUTOR_TRUST_DOMAIN_NOT_VERIFIED"]
    if not cutover["verified"]:
        blockers.append("OPERATIONAL_CUTOVER_NOT_INDEPENDENTLY_CONFIRMED")
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
        "operational_cutover": cutover,
        "production_cutover_performed": cutover["verified"],
        "owner_reported_cutover_file_consistency": cutover.get("file_consistency_checked",False),
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
        "operational_cutover": cutover,
        "report": str(report)}, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
