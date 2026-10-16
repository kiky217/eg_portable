"""Regression for issues #12 and #13; no real credentials or runtime."""
import sqlite3
import pytest
from tools.check_live_cutover_readiness import canonical,parse_loopback_http_url

@pytest.mark.parametrize("url",[
    "http://127.0.0.1:18765","http://127.0.0.1:18766",
    "http://localhost:22000","http://[::1]:18766"])
def test_local_endpoint_is_configurable(url):
    assert parse_loopback_http_url(url)==url

@pytest.mark.parametrize("url",[
    "https://localhost:18766","http://localhost.evil:18766",
    "http://evil@localhost:18766","http://127.0.0.1:0",
    "http://127.0.0.1:18766/unsafe",
    "http://127.0.0.1:18766?x=y","http://192.168.0.1:18766"])
def test_nonlocal_or_unsafe_endpoint_denied(url):
    with pytest.raises(RuntimeError,match='REFUSE_NONLOCAL'):
        parse_loopback_http_url(url)

def test_gate_query_only_current_step_latest_ready(tmp_path):
    db=tmp_path/'ledger.db'
    with sqlite3.connect(db) as conn:
        conn.executescript("""
        CREATE TABLE task_registry(task_id TEXT,status TEXT,contract_status TEXT,checkpoint_no INTEGER);
        CREATE TABLE task_registry_steps(task_id TEXT,step_no INTEGER,step_key TEXT,verified INTEGER);
        CREATE TABLE audit(seq INTEGER,task_id TEXT,event_type TEXT,request_json TEXT);
        CREATE TABLE execution_gates(
            gate_id INTEGER,task_id TEXT,step_key TEXT,pre_checkpoint_no INTEGER,
            created_at TEXT,action_fingerprint TEXT,pre_verdict TEXT,consumed INTEGER
        );
        INSERT INTO task_registry VALUES ('demo','IN_PROGRESS','OPEN',6);
        INSERT INTO task_registry_steps VALUES ('demo',1,'01',0);
        INSERT INTO task_registry_steps VALUES ('demo',2,'01.01',1);
        INSERT INTO task_registry_steps VALUES ('demo',3,'01.02',0);
        INSERT INTO execution_gates VALUES
            (1,'demo','01.01',1,'2026-01-01T00:00:00+00:00','old','READY_TO_EXECUTE',0),
            (2,'demo','01.02',5,'2026-01-01T00:00:00+00:00','new','UNVERIFIED',0);
        """)
    assert canonical(db,'demo')['gate'] is None
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE execution_gates SET pre_verdict='READY_TO_EXECUTE' WHERE gate_id=2")
    assert canonical(db,'demo')['gate']['pre_checkpoint_no']==5
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE task_registry_steps SET verified=1 WHERE step_key='01.02'")
        conn.execute("UPDATE task_registry_steps SET verified=1 WHERE step_key='01'")
    assert canonical(db,'demo')['gate'] is None
