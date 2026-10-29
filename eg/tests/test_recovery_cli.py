import json
import pytest
from tools import recovery_cli
from tools.high_effect_admission import action_fingerprint

def setup(tmp_path):
    journal=tmp_path/"journal";journal.mkdir(mode=0o700)
    key=tmp_path/"eg-secret";key.write_text("local-fixture-credential")
    key.chmod(0o600)
    action={"action_type":"bounded_process_run","target":"/tasks/recover/item",
            "effect_class":"governed_operation","real_world_effect":True,"reversible":False,
            "payload_sha256":"a"*64,"payload_bytes":1}
    source=tmp_path/"action.json";source.write_text(json.dumps(action))
    source.chmod(0o600)
    return journal,key,source,action

def test_operator_cli_reports_unclaimed_gate_without_grant(monkeypatch,tmp_path):
    journal,key,source,action=setup(tmp_path)
    fp=action_fingerprint(action);task="task-local-recovery"
    gate={"task_id":task,"step_key":"01.01","checkpoint_no":3,
          "action_fingerprint":fp,"verdict":"READY_TO_EXECUTE",
          "high_effect_pin":{"adapter_id":"trusted-adapter-probe",
                             "approval_nonce":"nonce_example_123456",
                             "action_fingerprint":fp,"public_key_b64":"fixture"}}
    state={"status":"IN_PROGRESS","current_step":"01.01",
           "pending_execution_gate":gate,
           "latest_checkpoint":{"checkpoint_no":3,"verdict":"READY_TO_EXECUTE"}}
    detail={"task":{"contract_status":"OPEN"},
            "checkpoints":[{"checkpoint_no":3,"verdict":"READY_TO_EXECUTE",
                             "created_at":"2026-10-20T00:00:00+00:00"}]}
    monkeypatch.setattr(recovery_cli,"_get",
        lambda eg,key,tid,suffix: state if suffix=="/state" else detail)
    result=recovery_cli.inspect_live(eg_url="http://127.0.0.1:1100",
        api_key_file=key,journal_dir=journal,task_id=task,step_key="01.01",
        adapter_id="trusted-adapter-probe",approval_nonce="nonce_example_123456",
        action_file=source)
    assert result["status"]=="NOT_STARTED"
    assert not result["allow_new_effect"]
    assert result["mutated"] is False

def test_cli_rejects_insecure_input_and_untrusted_gateway(tmp_path):
    journal,key,source,action=setup(tmp_path)
    bad=tmp_path/"unsafe";bad.write_text("credential");bad.chmod(0o644)
    with pytest.raises(recovery_cli.RecoveryCliDenied,match="UNSAFE_PRIVATE"):
        recovery_cli._private_file(bad)
    link=tmp_path/"link";link.symlink_to(key)
    with pytest.raises(OSError):
        recovery_cli._private_file(link)
    with pytest.raises(recovery_cli.RecoveryCliDenied,match="UNTRUSTED_CANONICAL_GATEWAY"):
        recovery_cli.inspect_live(eg_url="http://untrusted.example",
            api_key_file=key,journal_dir=journal,task_id="task",
            step_key="01.01",adapter_id="trusted-adapter-probe",
            approval_nonce="nonce_example_123456",action_file=source)
