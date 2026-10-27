# Code Analysis & Cleanup — Progress and Handoff

## Workflow contract for subsequent chats
Continue by reading this entire file first, re-fetching the GitHub `main` HEAD and comparing it against the frozen source SHA below. Use ONLY the GitHub connector. Do not access KNID, KNID-PC, inactive Colab or remote desktops. Initial analysis was on an **analysis-only** branch. Owner explicitly authorized cleanup on 2026-10-27 02:49 UTC, limited here to unused import bindings, retaining all functions, route handlers, dependencies, configuration semantics and workflows. Changes are isolated in `cleanup-unused-imports-20261027`. No other project-specific infrastructure is in scope. Report findings with file/line evidence and identify consumers, dynamic usage and regression risks before suggesting cleanup. Tests are not proof of unused code; analyze both source and external entrypoints. Keep GitHub `main` untouched. After each phase update this file on the analysis branch and preserve the complete instructions.

The owner's provided workflow is: discovery → systematic scanning for unused imports/dead code → analysis of reachability/dependency/impact → review and approval → incremental cleanup only if approved, with baseline/rollback and runtime/integration/regression verification. This document is the cross-chat checkpoint. Default scope: full project, conservative cleanup; include tests/config as consumers but avoid deleting test fixtures or generated artifacts as assumptions. No project path question needed: project is `kiky217/eg_portable`.

## Canonical project and source baseline
- Repository: https://github.com/kiky217/eg_portable
- Canonical default branch: `main`
- Source HEAD at discovery: `8c1917387c33d84f53e598fd4ab3427b77b9a40e`
- Latest verified published release: `v3.1.139`
- Platform: Python 3.12, FastAPI/Starlette/Pydantic, SQLite; portable Linux x86-64. Production packages locked to exactly 17; Debian Bookworm bundle copies reviewed native libraries. Docker and GitHub Actions CI.
- Previous release-validation workflow run: https://github.com/kiky217/eg_portable/actions/runs/40439313689 (success, 402 passed / 1 skipped).
- Branch for reports only: `code-analysis-audit-20261027`; unmerged; code state identical to canonical baseline.
- Structure from untruncated recursive GitHub tree: 118 tracked files (127 tree entries), 32 non-test Python source files (4 `eg/app`, 28 `eg/tools`), 61 Python test/harness files; 9 `eg/docs` files; 1 workflow. Largest source `eg/app/main.py` (130,673 bytes).
- Files may have CLI entrypoints, framework-decorated routes, string-reflection, signed protocol consumers, or indirect public references. Treat these as live until disproven.

## Completed phases
- [x] Discovery: GitHub tree and canonical commit verified (2026-10-27).
- [x] Baseline: branch isolated from main; no code changes.
- [x] Read-only lexical scan of 32 non-test Python source files (imports, top-level functions/classes; annotated false positives).\n- [x] Fetched and performed conservative lexical import scans for all 61 test/harness Python files.\n- [x] Selected root README/SKILL/security/operations and runtime documents, dependency names, CLI references, and FastAPI decorator exceptions cross-checked.\n- [ ] AST/Pyflakes/Ruff/control-flow reachability lint and runtime consumer verification (not available in GitHub read-only execution without modifying CI).
- [ ] Complete deeper reachability / external public CLI consumer cross-check (partially sampled; no function or file proven dead).
- [ ] Impact, prioritization, precise proposed diff (analysis only).
- [ ] Owner review and explicit approval (required before cleanup).
- [ ] Incremental cleanup/rollback/tests only after approval.

## Findings / candidate log
### 2026-10-27 — Initial source scan (conservative, not cleanup approval)
Read all 32 Python application/tools files at frozen source SHA. Ten `import` tokens have no further lexical references in their defining file. These are **candidates** pending test, runtime, and dynamic import consumers:
- `eg/app/execution_receipts.py:12` — `import math`.
- `eg/tools/adapter_liveness.py:11` — `import os`.
- `eg/tools/build_portable_bundle.py:9` — `argparse`, `tempfile`, `time`.
- `eg/tools/ensure_gateway_service.py:6` — `sys`.
- `eg/tools/recovery_cli.py:9` — `Path`.
- `eg/tools/recovery_inspector.py:8` — `base64`.
- `eg/tools/test_offline_portable.py:9` — `pwd`.
- `eg/tools/trusted_execution_worker.py:27` — `HTTPError`.

Method limitation: simple lexical usage scans are not full Python AST or Pyflakes/Ruff diagnostics; occurrences inside import blocks, multiline statements, strings, reflection or decorators need independent inspection.

Explicitly PROTECTED: `eg/app/main.py` contains decorated FastAPI handlers `database_busy_handler:203`, `agent_capabilities:1497`, `agent_capability_match:1533`, `pause_task:2120`, `resume_task:2125`, `reconcile_task:2130`, `abort_task:2190`, `task_state:2230`, `audit_verify:2293`. Their function names appear once but framework registration makes them reachable; **not dead**. Do not delete them.

No imports, code, tests, configurations or CI workflows modified. No cleanup allowed until explicit review approval.

## Cleanup approval and implementation checkpoint — 2026-10-27
- Owner approved cleanup at 2026-10-27 02:49 UTC.
- Baseline commit `8c1917387c33d84f53e598fd4ab3427b77b9a40e` (`v3.1.139`); rollback to that tag/commit if needed.
- Source cleanup prepared: precisely 10 lexical-unused imports in 8 production files and 29 in 18 test files. NO deletions of functions, API routes, files, packages, dependency pins or capabilities.
- New release version: `v3.1.140`; Docker Compose tag kept in sync.
- CI acceptance REQUIRED before merge: full regression + E2E + Docker import + portable archive relocation + license 17 wheel/10 native verification. Submission/build success is not accepted as production deployment.
- Status at this checkpoint: CHANGES PREPARED; CI not yet verified. Next verify PR SHA/runs and update post-merge state in next session.

## Phase 2 checkpoint — 2026-10-27
- Report: [code-analysis-findings.md](code-analysis-findings.md) (39 lexical unused-import candidates, not approved).
- Non-test: 10 candidate imported symbols across 8 source files.
- Tests: 29 candidate symbols across 18 test/harness files.
- Candidate package review: `httpx2` test-only and `opentelemetry-api` production appear only in manifests/documentation/license map via repository search; transitive dependencies/consumers **unverified**, not safe to remove.
- Explicit false positive protection: nine decorated FastAPI handlers are registered API routes/exception handler, not dead code.
- No confirmed dead functions, no confirmed orphan files, no source edits or runtime deployments.
- Runtime baseline: GitHub workflow `40439313689`, 402 passed, 1 skipped; status from 2026-10-27. These results predate *no source changes* and are not fresh tests of any cleanup.

## Analysis and safety rules
1. Read complete source and code consumers; do not rely on a grep hit alone. Check `eg/app/main.py` routes, decorators, tool CLIs (`if __name__ == "__main__"`), imports, tests, docs, GitHub workflow, `SKILL.md`, portable bundles.
2. Separate *unreferenced in scanned Python source*, *unused locally*, and *demonstrably unreachable*. Reflection/public API/installed tools may be used externally. Restrict high-confidence deletions to proven-unused private code.
3. Prefer static detection plus manual verification. Record exact path, symbol, lines, usages, side effects, risk and estimated savings. Preserve all current functionality.
4. Never call cleanup done merely because source, build or CI passes; require deployment/runtime evidence for live acceptance after approved changes.
5. Any change to source requires explicit owner authorization; snapshot original SHA and provide rollback to exact previous HEAD. Avoid touching main until tests and approval.
6. Keep responses in Indonesian, concise; use confirmed statuses.

## Next checkpoint
Reconcile `main` HEAD; review [code-analysis-findings.md](code-analysis-findings.md); run independently supported Python AST/linter verification **without modifying source** if tooling becomes available; assess dynamic/CLI entrypoints and dependency graph; present exact changes and obtain owner approval before any cleanup. On approval, work incrementally in a new branch, not `main`, with CI, E2E, legal gate and rollback. This audit branch contains documentation only. Update this file after each significant phase; do not perform code cleanup without approval.
