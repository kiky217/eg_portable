"""Test #7 historical protocol resume, #9 fail-closed integrity across APIs."""
from harness import gw,CLIENT,HEAD,eid,register,step_ref,claim,raw_eval


def _suspend(task, contract, action, protocol):
    return CLIENT.post(f"/v1/tasks/{task}/{action}", headers=HEAD, json={
        "event_id": eid("suspension"), "contract_hash": contract,
        "protocol_hash": protocol, "checkpoint_no": 0,
        "reason": "safe test-only operator pause/resume"})


def test_legacy_protocol_resume_uses_intake_hash_and_new_validator(monkeypatch):
    prior = "8" * 64
    original = gw.protocol_hash
    monkeypatch.setattr(gw, "protocol_hash", lambda: prior)
    task, contract = register()
    monkeypatch.setattr(gw, "protocol_hash", original)
    assert _suspend(task, contract, "pause", prior).status_code == 200
    resumed = _suspend(task, contract, "resume", prior)
    assert resumed.status_code == 200, resumed.text
    assert resumed.json()["status"] == "IN_PROGRESS"
    state = CLIENT.get(f"/v1/tasks/{task}/state", headers=HEAD)
    assert state.status_code == 200
    ref = step_ref(task, "PRE_EXECUTION", 0)
    attempt = CLIENT.post("/v1/evaluate", headers=HEAD, json={
        "event_id": eid("legacy-after-upgrade"), "task_id": task,
        "contract_hash": contract, "protocol_hash": prior,
        "checkpoint_no": 0, "step_key": "01.01", "agent": "ChatGPT",
        "phase": "PRE_EXECUTION", "claims": [claim(ref)]})
    assert attempt.status_code == 200 and attempt.json()["verdict"] == "READY_TO_EXECUTE"
    assert CLIENT.get("/v1/audit/verify", headers=HEAD).json()["status"] == "PASS"


def test_tampered_materialized_state_blocks_all_mutations_and_worker_readback():
    task, contract = register()
    db = gw.conn()
    try:
        original = db.execute("SELECT original_instruction FROM task_registry WHERE task_id=?", (task,)).fetchone()[0]
        audit_before = db.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
        db.execute("UPDATE task_registry SET original_instruction=? WHERE task_id=?", ("tampered-unsigned", task))
        db.commit()
    finally:
        db.close()
    try:
        assert CLIENT.get("/v1/audit/verify", headers=HEAD).status_code == 409
        request = {
            "event_id": eid("tampered-register"), "task_id": eid("tampered-new"),
            "protocol_hash": gw.protocol_hash(), "agent": "ChatGPT",
            "original_instruction": "must be rejected", "acceptance_criteria": ["x"],
            "steps": [{"step_key": "01", "title": "parent", "acceptance_criteria": ["x"],"execution_required":False},
                      {"step_key": "01.01", "title": "child", "acceptance_criteria": ["x"],"execution_required":False}]
        }
        assert CLIENT.post("/v1/tasks/register", headers=HEAD, json=request).status_code == 503
        assert CLIENT.get(f"/v1/tasks/{task}/state", headers=HEAD).status_code == 503
        assert CLIENT.get(f"/v1/tasks/{task}", headers=HEAD).status_code == 503
        assert _suspend(task, contract, "pause", gw.protocol_hash()).status_code == 503
        assert _suspend(task, contract, "resume", gw.protocol_hash()).status_code == 503
        ref = step_ref(task, "PRE_EXECUTION", 0)
        res = raw_eval(task, contract, 0, claims=[claim(ref)])
        assert res.status_code == 503
        audit_after = gw.conn()
        try:
            assert audit_after.execute("SELECT COUNT(*) FROM audit").fetchone()[0] == audit_before
        finally:
            audit_after.close()
    finally:
        c = gw.conn()
        try:
            c.execute("UPDATE task_registry SET original_instruction=? WHERE task_id=?", (original, task))
            c.commit()
        finally:
            c.close()
    assert CLIENT.get("/v1/audit/verify", headers=HEAD).json()["status"] == "PASS"
