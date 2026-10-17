"""Issue #23/#24: active documentation cannot override fail-closed recovery."""
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def test_actionable_gate_cannot_be_normatively_superseded():
    protocol=(ROOT/"docs/EXECUTOR_PROTOCOL.md").read_text()
    runbook=(ROOT/"docs/PORTABLE_RUNBOOK.md").read_text()
    assert "outstanding actionable READY gate MUST NOT be superseded" in protocol
    assert "A later PRE supersedes earlier gates" not in protocol
    assert "SAME gate" in protocol
    assert "NOT_EXECUTED" in protocol and "UNKNOWN effect remains BLOCKED" in protocol
    assert ("fresh PRE" in runbook or "new PRE" in runbook) and "UNKNOWN" in runbook


def test_remediation_snapshot_identified_as_historical():
    snapshot=(ROOT/"artifacts/KNOWN_ISSUES_20261016.md").read_text()
    assert "**historical issue snapshot**" in snapshot
    assert "#19" in snapshot and "#20" in snapshot
    assert "#21" in snapshot and "#25" in snapshot
    assert "including staging" in snapshot
    assert "not** a live production" in snapshot
