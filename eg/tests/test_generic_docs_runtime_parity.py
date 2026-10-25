"""Guard provider-neutral operator docs against removed adapters and runtime drift."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "eg/docs"
OPS = (DOCS / "OPERATIONS.md").read_text(encoding="utf-8")
SCOPED = (DOCS / "SCOPED_STAGING_APPROVAL.md").read_text(encoding="utf-8")
BOOTSTRAP = (DOCS / "ONE_TIME_STAGING_BOOTSTRAP.md").read_text(encoding="utf-8")
GENERIC = (DOCS / "GENERIC_EXECUTION_MODEL.md").read_text(encoding="utf-8")
ROOT_README = (ROOT / "README.md").read_text(encoding="utf-8")


def test_all_operational_markdown_starts_with_a_real_heading():
    for document in [ROOT / "README.md", ROOT / "SKILL.md", ROOT / "SECURITY.md",
                     ROOT / "eg/README.md", *DOCS.glob("*.md")]:
        content = document.read_text(encoding="utf-8")
        if document.name == "SKILL.md":
            # Skill metadata uses required YAML front matter before its heading.
            assert content.startswith("---\\n".replace("\\n", "\n"))
            assert "\\n---\\n# ".replace("\\n", "\n") in content
        else:
            assert content.startswith("# "), document


def test_markdown_local_links_have_real_repository_targets():
    for doc in [ROOT / "README.md", ROOT / "SKILL.md", ROOT / "eg/README.md",
                *DOCS.glob("*.md")]:
        text = doc.read_text(encoding="utf-8")
        for match in re.finditer(r"\]\(([^)]+)\)", text):
            target = match.group(1).split("#", 1)[0].split("?", 1)[0]
            if not target or target.startswith(("https://", "http://", "mailto:", "data:", "/")):
                continue
            path = (doc.parent / target).resolve()
            assert path.is_relative_to(ROOT.resolve()) and path.exists(), (doc, target)


def test_runtime_and_documentation_are_same_generic_contract():
    first = (ROOT / "eg/tools/operator_first_run.py").read_text(encoding="utf-8")
    host = (ROOT / "eg/tools/operator_process_service.py").read_text(encoding="utf-8")
    catalog = (ROOT / "eg/tools/trusted_process_catalog.py").read_text(encoding="utf-8")
    process = (ROOT / "eg/tools/trusted_process_effect.py").read_text(encoding="utf-8")
    assert "catalog_required" in first and "profiles" in first
    assert "TrustedProcessCatalog" in host and "validate_profiles" in host
    assert "class TrustedProcessCatalog:" in catalog and "len(profiles)" in catalog
    assert 'action.get("effect_class")!="E3"' in process
    assert "E3 process catalog" in OPS and "E3 only" in OPS
    assert "E4/E5" in ROOT_README and "E3" in GENERIC
    assert "profiles" in BOOTSTRAP and "legacy" in BOOTSTRAP.lower()
    assert "E3" in SCOPED and "target scope" in SCOPED
    for stale in (
        "existing independent GitHub worker",
        "operation_kind: \"pull_requests\"",
        "github_pull_request",
        "E3 bounded_process_run in staging only",
        "actual E3 café",
        "projects must implement a bespoke executor",
    ):
        for path, content in [("OPERATIONS", OPS), ("SCOPED", SCOPED),
                              ("BOOTSTRAP", BOOTSTRAP), ("README", ROOT_README)]:
            assert stale not in content, (path, stale)


def test_archived_operational_evidence_is_explicitly_non_current():
    for file in (ROOT / "eg/artifacts").glob("*.md"):
        if file.name == "README.md":
            continue
        first = file.read_text(encoding="utf-8").splitlines()[:8]
        assert any("ARCHIVED" in line or "historical" in line.lower()
                   for line in first), file.name
