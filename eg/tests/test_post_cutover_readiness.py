"""Completed cutover proof is read-only and not executor authorization."""
import hashlib
import json
import sqlite3

from tools.check_live_cutover_readiness import inspect_completed_cutover


def fixture(tmp_path):
    db = tmp_path / "ledger.db"
    with sqlite3.connect(db) as conn:
        conn.execute("create table audit(seq integer primary key, record_hash text not null)")
        conn.execute("insert into audit values (184, ?)", ("a" * 64,))
    artifacts = {}
    for name in ("database", "anchor", "evidence"):
        file = tmp_path / (name + ".bin")
        file.write_bytes((name + "-preserved").encode())
        artifacts[name] = (str(file), hashlib.sha256(file.read_bytes()).hexdigest())
    legacy = tmp_path / "old-runtime.tar.gz"
    legacy.write_bytes(b"rollback-copy")
    data = {
        "status": "CUTOVER_VERIFIED", "to": "3.1.0-beta.1",
        "audit_head": "a" * 64, "audit_records": 184,
        "checkpoint": 26, "legacy_runtime_directory_removed": True,
        "rollback_available": True,
        "db_dump": artifacts["database"][0],
        "db_dump_sha256": artifacts["database"][1],
        "anchor_copy": artifacts["anchor"][0],
        "anchor_sha256": artifacts["anchor"][1],
        "evidence_backup": artifacts["evidence"][0],
        "evidence_sha256": artifacts["evidence"][1],
        "legacy_source_archive": str(legacy),
    }
    receipt = tmp_path / "cutover.json"
    receipt.write_text(json.dumps(data))
    audit = {"version": "3.1.0-beta.1", "records": 184, "head": "a" * 64}
    state = {"checkpoint": 26}
    return receipt, db, audit, state, data


def test_verified_cutover_keeps_executor_admission_separate(tmp_path):
    p, db, audit, state, _ = fixture(tmp_path)
    result = inspect_completed_cutover(p, audit, state, db)
    assert result["verified"]
    assert result["reason"] == "LIVE_AND_BACKUP_MATCH"


def test_subsequent_audit_events_do_not_undo_real_cutover(tmp_path):
    p, db, audit, state, _ = fixture(tmp_path)
    with sqlite3.connect(db) as conn:
        conn.execute("insert into audit values (185, ?)", ("b" * 64,))
    audit.update({"records": 185, "head": "b" * 64})
    state["checkpoint"] = 27
    assert inspect_completed_cutover(p, audit, state, db)["verified"]


def test_wrong_audit_head_never_claims_completed_cutover(tmp_path):
    p, db, audit, state, data = fixture(tmp_path)
    data["audit_head"] = "f" * 64
    p.write_text(json.dumps(data))
    result = inspect_completed_cutover(p, audit, state, db)
    assert not result["verified"]


def test_corrupted_backup_refuses_cutover_acceptance(tmp_path):
    p, db, audit, state, data = fixture(tmp_path)
    with open(data["db_dump"], "ab") as fp:
        fp.write(b"tampered")
    assert not inspect_completed_cutover(p, audit, state, db)["verified"]


def test_no_receipt_not_presumed_cutover(tmp_path):
    _, db, audit, state, _ = fixture(tmp_path)
    result = inspect_completed_cutover(None, audit, state, db)
    assert not result["verified"]
