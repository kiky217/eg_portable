"""Issue #16: active portable contract is separate from historical examples."""
from pathlib import Path
import hashlib
from harness import gw,CLIENT,HEAD

ROOT=Path(__file__).resolve().parents[1]

def test_generic_runbook_has_no_historical_runtime_defaults():
    text=(ROOT/"docs/PORTABLE_RUNBOOK.md").read_text()
    assert "REGISTER → PRE" in text and "POST → VERIFIED" in text
    assert "RECOVERY_PENDING" in text and "NOT_EXECUTED" in text
    assert "/content/workspace" not in text
    assert "12/16" not in text
    assert "checkpoint 26" not in text

def test_current_protocol_identity_is_stable_and_sha_bound():
    raw=(ROOT/"docs/EXECUTOR_PROTOCOL.md").read_bytes()
    r=CLIENT.get("/v1/protocol",headers=HEAD)
    assert r.status_code==200
    data=r.json()
    assert data["version"]=="3.1"
    assert data["hash"]==hashlib.sha256(raw).hexdigest()
    import re
    version=(ROOT/"VERSION").read_text().strip()
    assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+",version)
    assert gw.APP_VERSION==version
    assert gw.MANIFEST_VERSION==4
    assert "4.0 candidate" not in (ROOT/"app/execution_receipts.py").read_text()
    assert CLIENT.get("/v1/audit/verify",headers=HEAD).json()["status"]=="PASS"

def test_historical_reports_live_outside_runtime_docs():
    archives=ROOT/"artifacts"
    for name in ("ACCEPTANCE_POST_CUTOVER_20261016.md",
                 "acceptance-post-cutover-20261016.json",
                 "KNOWN_ISSUES_20261016.md"):
        assert (archives/name).is_file()
        assert not (ROOT/"docs"/name).exists()
    assert "historical" in (archives/"README.md").read_text().lower()
