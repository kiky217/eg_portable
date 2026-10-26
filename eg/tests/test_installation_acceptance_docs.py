"""Installer-facing documentation must always require complete generic EG acceptance.

This source-level check does NOT claim a live worker has been provisioned.
"""
from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parents[2]
GUIDES = (
    "SKILL.md",
    "README.md",
    "eg/README.md",
    "eg/docs/OPERATIONS.md",
    "eg/docs/PORTABLE_RUNBOOK.md",
    "eg/docs/ONE_TIME_STAGING_BOOTSTRAP.md",
    "eg/docs/OPERATOR_PROCESS_SERVICE.md",
    "eg/docs/SCOPED_STAGING_APPROVAL.md",
    "eg/docs/GENERIC_EXECUTION_MODEL.md",
)
HEADING = "MANDATORY FROM INSTALLATION — FULL CAPABILITY ACCEPTANCE"
REQUIREMENT = (
    "Install EG completely as a generic system and test it end-to-end "
    "until every supported, authorized capability is operational."
)


@pytest.mark.parametrize("relative_path", GUIDES)
def test_installation_document_cannot_omit_mandatory_e2e_gate(relative_path):
    path = ROOT / relative_path
    source = path.read_text(encoding="utf-8")
    first_lines = source.splitlines()[:12]
    assert sum(HEADING in line for line in first_lines) == 1, relative_path
    assert source.count(REQUIREMENT) == 1, relative_path
    block = source[source.index(HEADING):source.index(HEADING) + 3200]
    for effect in ("E0", "E2", "E3", "E4", "E5"):
        assert re.search(r"\b" + effect + r"\b", block), (relative_path, effect)
    for keyword in (
        "REGISTER", "PRE", "POST", "VERIFIED", "SATISFIED",
        "INCOMPLETE / BLOCKED", "independent", "generic",
    ):
        assert keyword.lower() in block.lower(), (relative_path, keyword)
    assert "health" in block.lower()
    assert "CI" in block
    if relative_path != "SKILL.md":
        link = re.search(r"\[canonical agent SKILL\]\(([^)]+)\)", block)
        assert link, relative_path
        target = (path.parent / link.group(1)).resolve()
        assert target == (ROOT / "SKILL.md").resolve(), relative_path
