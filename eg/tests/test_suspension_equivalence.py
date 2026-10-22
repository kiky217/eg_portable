"""A refactor of pause/resume must preserve immutable event replay and audit proofs."""
from harness import CLIENT, HEAD, gw, eid, register


def test_pause_resume_equivalence_replay_and_denials():
    task, contract = register()
    base = {"contract_hash": contract, "protocol_hash": gw.protocol_hash(),
            "checkpoint_no": 0, "reason": "operator pause/resume semantic equivalence"}

    def request(route, event, **overrides):
        payload = {"event_id": event, **base, **overrides}
        return CLIENT.post(f"/v1/tasks/{task}/{route}", headers=HEAD, json=payload)

    assert request("resume", eid("premature")).json()["detail"]["code"] == "TASK_NOT_PAUSED"
    assert request("pause", eid("wrong-hash"), contract_hash="f" * 64).json()["detail"]["code"] == "PAUSE_STALE_CONTRACT_OR_CHECKPOINT"
    pause_event = eid("pause")
    paused = request("pause", pause_event)
    assert paused.status_code == 200 and paused.json()["status"] == "PAUSED"
    assert paused.json()["indefinite"] is True
    assert request("pause", pause_event).json()["idempotent_replay"] is True
    assert request("pause", eid("duplicate")).json()["detail"]["code"] == "TASK_NOT_PAUSABLE"
    assert request("resume", eid("stale"), checkpoint_no=99).json()["detail"]["code"] == "RESUME_STALE_CONTRACT_OR_CHECKPOINT"
    resume_event = eid("resume")
    resumed = request("resume", resume_event)
    assert resumed.status_code == 200 and resumed.json()["status"] == "IN_PROGRESS"
    assert resumed.json()["next_action"] == "EVALUATE_NEXT_STEP"
    assert request("resume", resume_event).json()["idempotent_replay"] is True
    assert request("resume", eid("duplicate")).json()["detail"]["code"] == "TASK_NOT_PAUSED"
    assert CLIENT.get("/v1/audit/verify", headers=HEAD).json()["status"] == "PASS"
