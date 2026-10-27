"""Fail-closed, read-only live cutover readiness tests."""
import sqlite3
from datetime import datetime, timedelta, timezone

from tools.check_live_cutover_readiness import canonical, classify_gate
from tools.trusted_execution_worker import MAX_NEW_WRITE_LEASE_SECONDS

def test_expired_pre_with_missing_target_requires_fresh_pre(tmp_path):
    now = datetime(2026, 10, 15, 23, 0, tzinfo=timezone.utc)
    stamp = (now - timedelta(minutes=9)).isoformat()
    gate = {"step_key": "07.01", "pre_checkpoint_no": 25, "created_at": stamp}
    action = {"action_type": "write", "target": str(tmp_path / "never-created.txt")}
    state = classify_gate(gate, action, now=now)
    assert state["lease_seconds"] == MAX_NEW_WRITE_LEASE_SECONDS
    assert state["expired_for_new_effect"]
    assert state["target_exists"] is False
    assert state["requires_fresh_pre"]
    assert not state["executable_with_current_pre"]

def test_active_pre_is_never_automatic_authority(tmp_path):
    now = datetime(2026, 10, 15, 23, 0, tzinfo=timezone.utc)
    gate = {"step_key": "01.01", "pre_checkpoint_no": 1,
            "created_at": (now-timedelta(seconds=10)).isoformat()}
    action = {"action_type": "write", "target": str(tmp_path/"file.txt")}
    result = classify_gate(gate, action, now=now)
    assert not result["expired_for_new_effect"]
    assert not result["requires_fresh_pre"]
    assert result["executable_with_current_pre"] is False

def test_preexisting_effect_never_automatically_reauthorized(tmp_path):
    target = tmp_path/"existing.txt"
    target.write_text("existing")
    now = datetime.now(timezone.utc)
    gate = {"step_key": "07.01", "pre_checkpoint_no": 25,
            "created_at": (now-timedelta(hours=2)).isoformat()}
    result = classify_gate(gate, {"action_type": "write", "target": str(target)}, now)
    assert result["expired_for_new_effect"] and result["target_exists"]
    assert not result["requires_fresh_pre"]
    assert not result["executable_with_current_pre"]

def test_canonical_reader_does_not_mutate_ledger(tmp_path):
    db=tmp_path/"gate.db"
    with sqlite3.connect(db) as c:
        c.executescript("""
        CREATE TABLE task_registry (task_id TEXT, status TEXT,
             contract_status TEXT, checkpoint_no INTEGER);
        INSERT INTO task_registry VALUES ('eg-task','IN_PROGRESS','OPEN',26);
        CREATE TABLE task_registry_steps (task_id TEXT,step_no INTEGER,
             step_key TEXT,verified INTEGER);
        INSERT INTO task_registry_steps VALUES ('eg-task',1,'07',0);
        INSERT INTO task_registry_steps VALUES ('eg-task',2,'07.01',0);
        CREATE TABLE audit (seq INTEGER,event_type TEXT,task_id TEXT,request_json TEXT);
        INSERT INTO audit VALUES (1,'EVALUATION','eg-task',
          '{"phase":"PRE_EXECUTION","checkpoint_no":24,"step_key":"07.01","action":{"action_type":"write","target":"/tmp/file.txt"}}');
        CREATE TABLE execution_gates (gate_id INTEGER,task_id TEXT,step_key TEXT,pre_checkpoint_no INTEGER,
          created_at TEXT,action_fingerprint TEXT,pre_verdict TEXT,consumed INTEGER);
        INSERT INTO execution_gates VALUES (1,'eg-task','07.01',25,
          '2026-10-15T19:23:13+00:00','f','READY_TO_EXECUTE',0);
        """)
    snapshot=db.read_bytes()
    data=canonical(db,"eg-task")
    assert data["checkpoint"]==26 and data["verified"]==0 and data["total"]==2
    assert data["gate"]["pre_checkpoint_no"]==25
    assert data["action"]["action_type"]=="write"
    assert db.read_bytes()==snapshot

def test_missing_gate_is_not_execution_authorization():
    state=classify_gate(None,None)
    assert state["present"] is False
    assert state["executable_with_current_pre"] is False
