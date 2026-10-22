"""Read-only, SHA-pinned lexical inventory; candidates are NOT proven defects."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PATTERNS = {
    "ENVIRONMENT_CONFIG": re.compile(r"localhost|127\.0\.0\.1|/tmp/|/root/|/content/|C:\\\\|\.knid|\b(?:UID|GID|PORT)\s*=", re.I),
    "APP_SPECIFIC": re.compile(r"\b(?:github|solana|cargo|rustc|scanner)\b", re.I),
    "CONTRACT": re.compile(r"schema_version|capability_sha256|action_type|effect_class|version\s*[=:]|\b(?:E[0-5])\b", re.I),
    "SECURITY_REVIEW": re.compile(r"nonce|signature|public_key|hitl|uid|replay|\b(?:max_bytes|timeout|limit)\b", re.I),
    "MAINTENANCE": re.compile(r"TODO|FIXME|deprecated|legacy|hardcod", re.I),
}


# Candidate disposition is intentionally NOT an independent semantic sign-off.
# It names accountable producer/consumer and forces human review for risky core cases.
def _scope(name):
    if name.startswith("eg/app/"):
        return "GENERIC_EG_CORE", "HTTP_API_AND_CANONICAL_LEDGER"
    if name.startswith("eg/tools/github_") or name.endswith("/trusted_github_effect.py"):
        return "OPTIONAL_PROVIDER_ADAPTER", "INDEPENDENT_GITHUB_WORKER"
    if name.startswith("eg/tests/"):
        return "TEST_FIXTURE", "PYTEST_AND_CI"
    if name.startswith("eg/artifacts/"):
        return "HISTORICAL_EVIDENCE", "HUMAN_AUDIT"
    if name.startswith("eg/tools/"):
        return "PORTABLE_OPERATIONS", "OPERATOR_OR_INDEPENDENT_WORKER"
    if name.startswith(".github/") or "Dockerfile" in name or "compose" in name:
        return "PACKAGING_AND_CI", "BUILD_AND_RELEASE"
    return "DOCUMENTATION_OR_CONFIG", "OPERATOR"


def _review(name, line, category, literal):
    scope, consumer = _scope(name)
    if category == "APP_SPECIFIC" and scope == "GENERIC_EG_CORE":
        risk, action = "HIGH", "REVIEW_PROVIDER_COUPLING_IN_CORE"
    elif category in ("SECURITY_REVIEW", "SECURITY_INVARIANT") and scope not in (
            "TEST_FIXTURE", "HISTORICAL_EVIDENCE", "DOCUMENTATION_OR_CONFIG"):
        risk, action = "HIGH", "CHECK_SECURITY_CONTRACT_AND_NEGATIVE_TESTS"
    elif category == "ENVIRONMENT_CONFIG" and scope not in ("TEST_FIXTURE", "DOCUMENTATION_OR_CONFIG"):
        risk, action = "MEDIUM", "CHECK_ENVIRONMENT_OVERRIDE_AND_PORTABILITY"
    elif category == "MAINTENANCE" and scope == "GENERIC_EG_CORE":
        risk, action = "MEDIUM", "REVIEW_LEGACY_CONSUMERS_BEFORE_REMOVAL"
    else:
        risk, action = "LOW", "CHECK_EXPECTED_USE_AND_TEST"
    return {"origin": scope, "consumer": consumer, "risk": risk,
            "action": action, "review_status": "SEMANTIC_REVIEW_REQUIRED"}


def _literal_category(value):
    text = str(value)
    for category in ("APP_SPECIFIC", "ENVIRONMENT_CONFIG", "SECURITY_REVIEW", "CONTRACT"):
        if PATTERNS[category].search(text):
            return category
    if isinstance(value, (int, float)) and type(value) is not bool:
        return "PORTABLE_DEFAULT_REVIEW"
    return "UNKNOWN_REVIEW"


def inventory(root: Path = ROOT) -> dict:
    sha = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    # Never label an uncommitted worktree snapshot as an immutable commit.
    if subprocess.run(["git", "-C", str(root), "diff", "--quiet", "HEAD", "--"],
                      check=False).returncode != 0:
        raise ValueError("SOURCE_TREE_DIFFERS_FROM_PINNED_HEAD")
    names = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z"]).split(b"\0")
    paths = sorted(n.decode("utf-8") for n in names if n)
    files, findings, literal_sites = [], [], []
    for name in paths:
        if (root / name).is_symlink():
            raise ValueError("TRACKED_SYMLINK_CANNOT_BE_SOURCE_PINNED")
        raw = (root / name).read_bytes()
        meta = {"path": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        try:
            lines = raw.decode("utf-8").splitlines()
        except UnicodeDecodeError:
            meta["scan"] = "BINARY_NOT_TEXT"
            files.append(meta)
            continue
        meta["scan"] = "TEXT_SCANNED"
        files.append(meta)
        for line_no, line in enumerate(lines, 1):
            for category, pattern in PATTERNS.items():
                for match in pattern.finditer(line):
                    findings.append({
                        "path": name, "line": line_no,
                        "category": category, "match": match.group(0),
                        "status": "NEEDS_SEMANTIC_REVIEW",
                        **_review(name, line_no, category, match.group(0)),
                    })
        if name.endswith(".py"):
            try:
                tree = ast.parse("\n".join(lines), filename=name)
            except SyntaxError:
                meta["parse"] = "SYNTAX_ERROR_REVIEW_REQUIRED"
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Constant) or not isinstance(
                        node.value, (str, int, float, bool, bytes, type(None))):
                    continue
                literal = repr(node.value)
                category = _literal_category(node.value)
                literal_sites.append({
                    "path": name, "line": node.lineno,
                    "literal": literal[:160], "truncated": len(literal)>160,
                    "category": category,
                    **_review(name, node.lineno, category, literal),
                })
    return {"schema_version": 1, "source_commit": sha,
            "files_total": len(files),
            "files_scanned": sum(f["scan"] == "TEXT_SCANNED" for f in files),
            "files": files, "candidates_total": len(findings),
            "candidates": findings, "literal_sites_total": len(literal_sites),
            "literal_sites": literal_sites,
            "semantic_review_complete": False}



def semantic_disposition(site: dict) -> str:
    """Risk-triage class, never an independent approval of a literal."""
    scope, category = site["origin"], site["category"]
    if category == "APP_SPECIFIC":
        return "UNKNOWN" if scope == "GENERIC_EG_CORE" else "APP_SPECIFIC"
    if category == "SECURITY_REVIEW":
        return "SECURITY_INVARIANT"
    if category == "ENVIRONMENT_CONFIG":
        return "ENVIRONMENT_CONFIG"
    if category == "CONTRACT":
        return "CONTRACT"
    if scope in ("TEST_FIXTURE", "PACKAGING_AND_CI", "HISTORICAL_EVIDENCE"):
        return "PORTABLE_DEFAULT"
    if category == "PORTABLE_DEFAULT_REVIEW":
        return "PORTABLE_DEFAULT"
    # Low-risk schema fields and protocol strings are owned by their scoped
    # producers; vendor terms are caught by APP_SPECIFIC before this fallback.
    if scope in ("GENERIC_EG_CORE", "PORTABLE_OPERATIONS"):
        return "CONTRACT"
    if scope == "OPTIONAL_PROVIDER_ADAPTER":
        return "APP_SPECIFIC"
    if scope == "DOCUMENTATION_OR_CONFIG":
        return "PORTABLE_DEFAULT"
    return "UNKNOWN"


def semantic_matrix(report: dict, root: Path) -> list[dict]:
    """Trace every Python AST site to its exact source line and file SHA-256."""
    hashes = {f["path"]: f["sha256"] for f in report["files"]}
    lines = {}
    result = []
    for site in report["literal_sites"]:
        path, number = site["path"], site["line"]
        if path not in lines:
            lines[path] = (root / path).read_text(encoding="utf-8").splitlines()
        result.append({
            "source_commit": report["source_commit"], "file_sha256": hashes[path],
            "path": path, "line": number, "literal": site["literal"],
            "source_line": lines[path][number - 1].strip()[:240],
            "risk": site["risk"], "disposition": semantic_disposition(site),
            "producer": site["origin"], "consumer": site["consumer"],
            "review_action": site["action"], "review_status": "SOURCE_TRIAGE_NOT_SIGNOFF",
        })
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--matrix-output", type=Path)
    args = parser.parse_args()
    report = inventory()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    if args.matrix_output:
        matrix = semantic_matrix(report, ROOT)
        args.matrix_output.parent.mkdir(parents=True, exist_ok=True)
        with args.matrix_output.open("w", encoding="utf-8") as target:
            for site in matrix:
                target.write(json.dumps(site, sort_keys=True) + "\n")
    print(f"source={report['source_commit']} files={report['files_total']} candidates={report['candidates_total']} literals={report['literal_sites_total']} semantic_review_complete=false")


if __name__ == "__main__":
    main()
