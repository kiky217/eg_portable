"""Generic catalog coverage without any provider-specific task executor."""
import os
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from tools.trusted_process_catalog import validate_profiles, TrustedProcessCatalog, ProcessDenied

# Cross-UID subprocesses must import from an independently readable test source.
ROOT = Path(os.environ.get("EG_TEST_SOURCE", Path(__file__).resolve().parents[1]))
PROFILES = [
    {"target": "/tasks/workflow/inspect", "executable": "/usr/bin/cat", "fixed_args": []},
    {"target": "/tasks/workflow/validate", "executable": "/usr/bin/cat", "fixed_args": [],
     "timeout": 7, "max_stdout": 4096},
    {"target": "/tasks/workflow/build", "executable": "/usr/bin/cat", "fixed_args": []},
    {"target": "/tasks/workflow/database", "executable": "/usr/bin/cat", "fixed_args": []},
]


def test_catalog_admits_several_pinned_targets_without_new_adapter_code():
    profiles = validate_profiles(PROFILES)
    assert len(profiles) == 4
    assert profiles[0]["target"] == "/tasks/workflow/inspect"
    assert profiles[1]["timeout"] == 7
    assert profiles[0]["fixed_args"] == ()


@pytest.mark.parametrize("invalid", [
    [],
    [{"target": "/tasks/workflow/inspect", "executable": "/usr/bin/cat", "fixed_args": []}] * 2,
    [{"target": "/tasks/workflow/../escape", "executable": "/usr/bin/cat", "fixed_args": []}],
    [{"target": "/tasks/workflow/inspect", "executable": "/usr/bin/cat",
      "fixed_args": [], "unexpected": "command"}],
    [{"target": "/tasks/workflow/inspect", "executable": "/usr/bin/cat",
      "fixed_args": [], "timeout": 90}],
    [{"target": "/tasks/workflow/inspect", "executable": "/usr/bin/cat",
      "fixed_args": ["a"] * 25}],
])
def test_catalog_rejects_unapproved_targets_and_unbounded_arguments(invalid):
    with pytest.raises(ProcessDenied):
        validate_profiles(invalid)


def test_catalog_target_denied_before_any_physical_dispatch(monkeypatch):
    class StubProcess:
        def __init__(self, **kwargs):
            self.ledger = object()
            self.target = kwargs["target"]
            self.execute_calls = 0

        def execute(self, **kwargs):
            self.execute_calls += 1
            return {"target": self.target}

    monkeypatch.setattr("tools.trusted_process_catalog.TrustedProcessEffect", StubProcess)
    catalog = TrustedProcessCatalog(journal_dir="/unused", private_key=object(),
        adapter_id="trusted-adapter-generic", hitl_key_b64="unused", profiles=PROFILES)
    assert catalog.workers["/tasks/workflow/inspect"].ledger is catalog.ledger
    assert catalog.workers["/tasks/workflow/validate"].ledger is catalog.ledger
    assert all(worker.ledger is catalog.ledger for worker in catalog.workers.values())
    with pytest.raises(ProcessDenied, match="TARGET_NOT_IN_OPERATOR_PROFILE_CATALOG"):
        catalog.execute(task_id="t", step_key="01.01",
            action={"target": "/tasks/workflow/unapproved"}, approval={},
            gate={}, gate_created_at="", stdin=b"test")
    assert all(p.execute_calls == 0 for p in catalog.workers.values())
    result = catalog.execute(task_id="t", step_key="01.01",
        action={"target": "/tasks/workflow/validate"}, approval={},
        gate={}, gate_created_at="", stdin=b"test")
    assert result["target"] == "/tasks/workflow/validate"
    assert catalog.workers["/tasks/workflow/validate"].execute_calls == 1
    for target in ("/tasks/workflow/build", "/tasks/workflow/database"):
        accepted = catalog.execute(task_id="t", step_key="01.01",
            action={"target": target}, approval={}, gate={},
            gate_created_at="", stdin=b"test")
        assert accepted["target"] == target
        assert catalog.workers[target].execute_calls == 1
    assert catalog.workers["/tasks/workflow/inspect"].execute_calls == 0


@pytest.mark.skipif(os.geteuid() != 0, reason="isolated nonroot fixture")
def test_one_private_service_config_supports_a_generic_catalog():
    from test_operator_process_service import _layout, _identity, WORKER_UID
    base = Path(tempfile.mkdtemp(prefix="eg-generic-catalog-", dir="/tmp"))
    try:
        config, settings, _, _ = _layout(base)
        settings["profiles"] = PROFILES
        config.write_text(json.dumps(settings))
        script = ("import json;from pathlib import Path;"
                  "from tools.operator_process_service import load_config;"
                  "v=load_config(Path(__import__('sys').argv[1]));"
                  "print(json.dumps([x['target'] for x in v['profiles']]))")
        cmd = [sys.executable, "-c", script, str(config)]
        env = {**os.environ, "PYTHONPATH": str(ROOT)}
        result = subprocess.run(cmd, cwd=ROOT, env=env,
            preexec_fn=_identity(WORKER_UID), capture_output=True, timeout=8)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == [x["target"] for x in PROFILES]
        settings["profiles"].append(PROFILES[0])
        config.write_text(json.dumps(settings))
        denied = subprocess.run(cmd, cwd=ROOT, env=env,
            preexec_fn=_identity(WORKER_UID), capture_output=True, timeout=8)
        assert denied.returncode != 0
        assert b"INVALID_OPERATOR_PROFILE_CATALOG" in denied.stderr
    finally:
        shutil.rmtree(base, ignore_errors=True)
