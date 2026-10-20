"""Read-only, SHA-pinned lexical inventory; candidates are NOT proven defects."""
from __future__ import annotations

import argparse
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


def inventory(root: Path = ROOT) -> dict:
    sha = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    names = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z"]).split(b"\0")
    paths = sorted(n.decode("utf-8") for n in names if n)
    files, findings = [], []
    for name in paths:
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
                    })
    return {"schema_version": 1, "source_commit": sha,
            "files_total": len(files),
            "files_scanned": sum(f["scan"] == "TEXT_SCANNED" for f in files),
            "files": files, "candidates_total": len(findings),
            "candidates": findings}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = inventory()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"source={report['source_commit']} files={report['files_total']} candidates={report['candidates_total']}")


if __name__ == "__main__":
    main()
