"""Contract checks for the read-only canonical-ledger migration rehearsal."""

import sqlite3
import subprocess
import sys
from pathlib import Path

from tools import rehearse_ledger_migration as rehearsal


def test_source_state_is_read_only_and_keeps_existing_gate(tmp_path):
    db = tmp_path / "ledger.db"
    with sqlite3.connect(db) as conn:
        conn.executescript("""
            CREATE TABLE audit (seq INTEGER);
            INSERT INTO audit VALUES (1);
            INSERT INTO audit VALUES (2);
            CREATE TABLE task_registry
                (task_id TEXT, contract_status TEXT, checkpoint_no INTEGER);
            INSERT INTO task_registry VALUES ('historical','SATISFIED',48);
            INSERT INTO task_registry VALUES ('current','OPEN',26);
            CREATE TABLE execution_gates
                (task_id TEXT, step_key TEXT, pre_checkpoint_no INTEGER, consumed INTEGER);
            INSERT INTO execution_gates VALUES ('current','07.01',25,0);
        """)
    before = db.read_bytes()
    found = rehearsal.source_state(db, "current", "historical")
    assert found == {
        "audit": (2, 2),
        "historical": ("SATISFIED", 48),
        "current": ("OPEN", 26),
        "gate": ("07.01", 25, 0),
    }
    assert db.read_bytes() == before


def test_disallows_unregistered_or_absent_gate(tmp_path):
    db = tmp_path / "ledger.db"
    with sqlite3.connect(db) as conn:
        conn.executescript("""
            CREATE TABLE audit (seq INTEGER);
            CREATE TABLE task_registry
                (task_id TEXT, contract_status TEXT, checkpoint_no INTEGER);
            CREATE TABLE execution_gates
                (task_id TEXT, step_key TEXT, pre_checkpoint_no INTEGER, consumed INTEGER);
        """)
    found = rehearsal.source_state(db, "missing", "missing-old")
    assert found["historical"] is None
    assert found["current"] is None
    assert found["gate"] is None


def test_invocation_requires_explicit_paths_and_tasks():
    script = Path(rehearsal.__file__)
    result = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode != 0
    for arg in ("--db", "--anchor", "--evidence", "--runtime-env-file",
                "--historical-task", "--open-task"):
        assert arg in result.stderr
