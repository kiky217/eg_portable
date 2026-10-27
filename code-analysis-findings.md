**Update 2026-10-27: Owner approved import-only cleanup; 10 production and 29 test-only lexical candidates are included in a single controlled PR at v3.1.140. Other findings remain unapproved. Check PR and CI before asserting successful cleanup.**

# EG Portable — Conservative Static Code Cleanup Findings
Snapshot: 2026-10-27 UTC; repository `kiky217/eg_portable`, pinned canonical source SHA `8c1917387c33d84f53e598fd4ab3427b77b9a40e`, release `v3.1.139`.

**Scope:** All 32 non-test Python source files and all 61 test/harness Python files were fetched and scanned from GitHub; 8 operational documentation/root files and code-search references were cross-checked. Only the GitHub connector was used. No source was modified and no cleanup was performed. This report is on an isolated unmerged audit branch. All findings are **candidates**, not safe-to-delete verdicts.

## Scan method and limitations
The scan inspected import tokens and textual references in each file (simple single-line import forms), top-level definitions in `eg/app/main.py`, and repository-wide references to selected modules/dependencies. It did **not** execute Ruff/Pyflakes, perform full AST control-flow analysis or independently run new CI. The GitHub validation already passed at baseline: [CI 40439313689](https://github.com/kiky217/eg_portable/actions/runs/40439313689) (402 PASS, 1 SKIP). Therefore *zero confirmed dead functions*, *zero proven orphan code files*, *zero cleanup modifications*. Multiline/aliased/dynamic imports and reflection require deeper checks before approval.

## Group A — non-test import candidates (10 tokens across 8 files)
| File (source pinned) | Line | Unreferenced tokens in that file |
|---|---:|---|
| [`eg/app/execution_receipts.py`](https://github.com/kiky217/eg_portable/blob/8c1917387c33d84f53e598fd4ab3427b77b9a40e/eg/app/execution_receipts.py#L12) | 12 | `math` |
| [`eg/tools/adapter_liveness.py`](https://github.com/kiky217/eg_portable/blob/8c1917387c33d84f53e598fd4ab3427b77b9a40e/eg/tools/adapter_liveness.py#L11) | 11 | `os` |
| [`eg/tools/build_portable_bundle.py`](https://github.com/kiky217/eg_portable/blob/8c1917387c33d84f53e598fd4ab3427b77b9a40e/eg/tools/build_portable_bundle.py#L9) | 9 | `argparse, tempfile, time` |
| [`eg/tools/ensure_gateway_service.py`](https://github.com/kiky217/eg_portable/blob/8c1917387c33d84f53e598fd4ab3427b77b9a40e/eg/tools/ensure_gateway_service.py#L6) | 6 | `sys` |
| [`eg/tools/recovery_cli.py`](https://github.com/kiky217/eg_portable/blob/8c1917387c33d84f53e598fd4ab3427b77b9a40e/eg/tools/recovery_cli.py#L9) | 9 | `Path` |
| [`eg/tools/recovery_inspector.py`](https://github.com/kiky217/eg_portable/blob/8c1917387c33d84f53e598fd4ab3427b77b9a40e/eg/tools/recovery_inspector.py#L8) | 8 | `base64` |
| [`eg/tools/test_offline_portable.py`](https://github.com/kiky217/eg_portable/blob/8c1917387c33d84f53e598fd4ab3427b77b9a40e/eg/tools/test_offline_portable.py#L9) | 9 | `pwd` |
| [`eg/tools/trusted_execution_worker.py`](https://github.com/kiky217/eg_portable/blob/8c1917387c33d84f53e598fd4ab3427b77b9a40e/eg/tools/trusted_execution_worker.py#L27) | 27 | `HTTPError` |

**Assessment:** low estimated functional risk to remove *individual import bindings* only, after independent static lint and regression. Do NOT delete the modules/files themselves. Keep unrelated bindings on shared import lines. In particular, `trusted_execution_worker`, builder, ledger, security and recovery paths must maintain all existing behavior.

## Group B — test-only import candidates (29 tokens across 18 files)
| File (source pinned) | Line | Unreferenced tokens in that file |
|---|---:|---|
| [`eg/tests/harness.py`](https://github.com/kiky217/eg_portable/blob/8c1917387c33d84f53e598fd4ab3427b77b9a40e/eg/tests/harness.py#L2) | 2 | `shutil` |
| [`eg/tests/test_admission_integrity_and_resume.py`](https://github.com/kiky217/eg_portable/blob/8c1917387c33d84f53e598fd4ab3427b77b9a40e/eg/tests/test_admission_integrity_and_resume.py#L2) | 2 | `H` |
| [`eg/tests/test_cutover_readiness.py`](https://github.com/kiky217/eg_portable/blob/8c1917387c33d84f53e598fd4ab3427b77b9a40e/eg/tests/test_cutover_readiness.py#L2) | 2 | `json` |
| [`eg/tests/test_execution_gate_protection.py`](https://github.com/kiky217/eg_portable/blob/8c1917387c33d84f53e598fd4ab3427b77b9a40e/eg/tests/test_execution_gate_protection.py#L2) | 2 | `gw, eid` |
| [`eg/tests/test_executor_capability_admission.py`](https://github.com/kiky217/eg_portable/blob/8c1917387c33d84f53e598fd4ab3427b77b9a40e/eg/tests/test_executor_capability_admission.py#L3) | 3 | `WORKER_OUTPUT` |
| [`eg/tests/test_install_preflight.py`](https://github.com/kiky217/eg_portable/blob/8c1917387c33d84f53e598fd4ab3427b77b9a40e/eg/tests/test_install_preflight.py#L2) | 2 | `base64, pathlib (L3)` |
| [`eg/tests/test_nested_workspace_bounds.py`](https://github.com/kiky217/eg_portable/blob/8c1917387c33d84f53e598fd4ab3427b77b9a40e/eg/tests/test_nested_workspace_bounds.py#L2) | 2 | `Path, gw (L4)` |
| [`eg/tests/test_no_effect_reconciliation.py`](https://github.com/kiky217/eg_portable/blob/8c1917387c33d84f53e598fd4ab3427b77b9a40e/eg/tests/test_no_effect_reconciliation.py#L2) | 2 | `CRIT` |
| [`eg/tests/test_notary_rotation.py`](https://github.com/kiky217/eg_portable/blob/8c1917387c33d84f53e598fd4ab3427b77b9a40e/eg/tests/test_notary_rotation.py#L9) | 9 | `PRIV, sb` |
| [`eg/tests/test_operator_runtime_registry.py`](https://github.com/kiky217/eg_portable/blob/8c1917387c33d84f53e598fd4ab3427b77b9a40e/eg/tests/test_operator_runtime_registry.py#L2) | 2 | `json` |
| [`eg/tests/test_recovery_cli.py`](https://github.com/kiky217/eg_portable/blob/8c1917387c33d84f53e598fd4ab3427b77b9a40e/eg/tests/test_recovery_cli.py#L1) | 1 | `os, ApprovalLedger (L5)` |
| [`eg/tests/test_recovery_crash_matrix.py`](https://github.com/kiky217/eg_portable/blob/8c1917387c33d84f53e598fd4ab3427b77b9a40e/eg/tests/test_recovery_crash_matrix.py#L6) | 6 | `H` |
| [`eg/tests/test_runtime_source_fingerprint.py`](https://github.com/kiky217/eg_portable/blob/8c1917387c33d84f53e598fd4ab3427b77b9a40e/eg/tests/test_runtime_source_fingerprint.py#L2) | 2 | `Path` |
| [`eg/tests/test_single_agent_workflow.py`](https://github.com/kiky217/eg_portable/blob/8c1917387c33d84f53e598fd4ab3427b77b9a40e/eg/tests/test_single_agent_workflow.py#L3) | 3 | `hashlib, Path (L5)` |
| [`eg/tests/test_unified_migration.py`](https://github.com/kiky217/eg_portable/blob/8c1917387c33d84f53e598fd4ab3427b77b9a40e/eg/tests/test_unified_migration.py#L7) | 7 | `hashlib, H (L8), do_pre and e2_action (L9)` |
| [`eg/tests/test_vnext_receipts.py`](https://github.com/kiky217/eg_portable/blob/8c1917387c33d84f53e598fd4ab3427b77b9a40e/eg/tests/test_vnext_receipts.py#L2) | 2 | `base64, datetime` |
| [`eg/tests/test_vnext_suspend.py`](https://github.com/kiky217/eg_portable/blob/8c1917387c33d84f53e598fd4ab3427b77b9a40e/eg/tests/test_vnext_suspend.py#L2) | 2 | `pytest, H (L3)` |
| [`eg/tests/test_worker_sealed_recovery.py`](https://github.com/kiky217/eg_portable/blob/8c1917387c33d84f53e598fd4ab3427b77b9a40e/eg/tests/test_worker_sealed_recovery.py#L3) | 3 | `Path` |

**Assessment:** test fixture imports may intentionally cause module initialization; some names (e.g. `H`, `gw`, `eid`, `PRIV`) are exported by `harness`. Need fixture/setup dependency review before removing any. Their apparent lack of a lexical reference does not prove a dead test. No tests are recommended for deletion.

## Explicitly not dead: FastAPI registered handlers
`eg/app/main.py` contains name-singleton functions at the following line numbers: 203 (sqlite exception handler), 1497 and 1533 (agent capability GET handlers), 2120/2125/2130/2190 (pause/resume/reconcile/abort POST handlers), 2230 (task state GET), 2293 (audit verification GET). Each is registered by an `@app` decorator, so direct text-reference counting alone is not a valid dead-code finding. Do not remove.

Likewise tools that appear import-free can be CLI entrypoints (e.g. `generate_notary_keypair.py`, `reanchor.py`, `recovery_cli.py`); tests, docs, CLI invocations and external operators can consume them without a Python import within the repository. Treat all as live until independently proven unreachable.

## Dependency candidates — NOT approved
- `httpx2==2.16.0` appears in `eg/requirements-test.txt` and `eg/README.md`, but a repository-wide code search found no direct Python use. It is **test-only**; investigate resolved dependency tree, package metadata, test diagnostics, and environment behavior before proposing removal.
- `opentelemetry-api==1.44.0` appears in `eg/requirements.lock` and the license inventory, with no direct Python import found by GitHub code search. It may be transitive or needed for compatibility. Do not remove before graph/metadata verification and license-closure rebuild.
- Neither is deemed a legal conflict or safe for removal based solely on source search.

## Architecture and risk
- `eg/app/main.py`: 130,673 bytes / 2,304 lines, a **maintainability hotspot**, not a dead-code conclusion. Extracting modules is a potentially high-regression refactor and outside conservative import cleanup.
- Entry points: FastAPI routes, SQLite/audit/recovery, protected signer and worker receipt flows, Docker, portable offline archive, `SKILL.md` and GitHub CI must remain consistent.
- Legal gate: v3.1.139's 17 locked Python packages, 10 bundled native libraries, third-party notices and SHA-256 validation must remain intact. Changing locked dependencies requires a distinct legal/version review.
- No code modification has been made. Current `main` remains the frozen baseline; original commit is the available rollback baseline if a subsequent approved PR is applied.

## Recommended review decisions (require explicit owner authorization)
1. **A — narrow import cleanup (lowest risk):** propose exact per-file diffs removing 10 bindings in the 8 non-test files, taking care of combined import statements. Then run full lint/static analysis, 402-test regression suite, E2E tests, Docker/offline build and legal notice validations on a PR. Owner approval required before source edit.
2. **B — separate test-only cleanup:** review 29 token candidates against module initialization/setup and pytest collection; remove only corroborated unused tokens in separately approved PR with the full suite.
3. **C — dependency changes:** resolve both dependency graphs first; any removal requires a separate approval, locked-hash updates, license review, Python/runtime/build/offline CI.
4. **D — major refactoring:** treat `main.py` decomposition as a distinct higher-risk project with API contracts and rollback, not routine cleanup.

## Completion and safety status
Discovery PASS; source-file lexical scanning PASS (93/93 Python files fetched); conservative issue classification partially verified; dynamic/control-flow/independent lint still INCOMPLETE; code cleanup **NOT STARTED — pending owner approval**. No production deployment or unrelated infrastructure was accessed.

Next chat instruction: first read [code-analysis-progress.md](code-analysis-progress.md), verify fresh `main` HEAD, and continue deeper dependency/dynamic verification. Do not turn lexical candidates into deletion instructions without evidence and approval.
