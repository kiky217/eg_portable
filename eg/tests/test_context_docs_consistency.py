"""Keep AI context Markdown aligned with real repository files and core EG boundaries.

Tests exercise repository documentation and source presence only; they do not
grant an effect, simulate a live production signer, or change durable EG state.
"""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2].resolve()
CONTEXT = ROOT / "docs" / "context"

REQUIRED = (
    "project-overview.md",
    "context-engineering-progress.md",
    "architecture/system-design.md",
    "architecture/decisions/adr-001-generic-gateway-bounded-worker.md",
    "components/gateway-evaluator-context.md",
    "components/trusted-worker-receipts-context.md",
    "components/evidence-audit-context.md",
    "workflows/development.md",
    "workflows/context-maintenance.md",
    "workflows/error-handling-and-logging.md",
)


def test_context_documents_exist_and_are_markdown():
    for name in REQUIRED:
        path = CONTEXT / name
        assert path.is_file(), name
        assert path.read_text(encoding="utf-8").startswith("# "), name


def test_all_context_markdown_relative_links_resolve_in_repo():
    """Check across every context Markdown file, including future additions."""
    for document in CONTEXT.rglob("*.md"):
        content = document.read_text(encoding="utf-8")
        for match in re.finditer(r"\]\(([^)]+)\)", content):
            raw = match.group(1).split("#", 1)[0].split("?", 1)[0]
            if not raw or raw.startswith(("https://", "http://", "mailto:", "data:")):
                continue
            assert not raw.startswith("/"), (document, raw)
            target = (document.parent / raw).resolve()
            assert target.is_relative_to(ROOT), (document, raw)
            assert target.is_file(), (document.relative_to(ROOT), raw)


def test_context_boundaries_match_canonical_runtime():
    source = (ROOT / "eg/app/main.py").read_text(encoding="utf-8")
    worker = (ROOT / "eg/tools/trusted_execution_worker.py").read_text(encoding="utf-8")
    overview = (CONTEXT / "project-overview.md").read_text(encoding="utf-8").lower()
    architecture = (CONTEXT / "architecture/system-design.md").read_text(encoding="utf-8").lower()
    workflow = (CONTEXT / "workflows/development.md").read_text(encoding="utf-8").lower()
    for route in (
        '/v1/tasks/register', '/v1/evaluate', '/v1/agent/capabilities',
        '/v1/agent/capability-match', '/v1/audit/verify',
    ):
        assert route in source, route
    assert "MAX_CONTENT = 512 * 1024" in worker
    for token in ("read", "create", "replace", "pre", "post", "staging"):
        assert token in overview and token in architecture, token
    assert "immutable" in workflow and "eg/version" in workflow
    assert "live" in overview and "live" in architecture
    # Keep retired internal effect classifications out of AI-facing context.
    for document in CONTEXT.rglob("*.md"):
        assert not re.search(r"\bE[0-9]+\b", document.read_text(encoding="utf-8")), document


def test_logging_review_separates_observability_from_authorization():
    review = (CONTEXT / "workflows/error-handling-and-logging.md").read_text(encoding="utf-8").lower()
    for term in ("fail-closed", "structured", "correlation", "retry",
                 "journal", "receipt", "redact", "retention", "audit", "log"):
        assert term in review, term
    assert "no runtime logging or error-handling behavior is changed" in review
