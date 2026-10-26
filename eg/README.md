# Evaluation Gateway — application and developer guide

## Mandatory ordered verification, including staging

**"Install EG completely as a generic system and test it end-to-end until every supported, authorized capability is operational."**

**Portable and generic:** The current canonical installation uses one gateway and built-in bounded read/create/replace; there is no mandatory external-worker or project-specific executor setup.

**Required for every fresh installation and upgrade (including staging):** Read the [canonical agent SKILL](../SKILL.md) first. Install one portable gateway with durable task/audit state and the built-in read, create and replace operations. Require task registration before any work and a verified PRE, exact execution receipt where an action occurs, independently checked POST, and completion of each step before starting the next; staging is not exempt. **Do not build project-specific executor code or infer privileges from the presence of source code.**

**Mandatory verification:** REGISTER → signed PRE → admitted action → signed receipt → independently checked POST → VERIFIED → next step → SATISFIED. No work before PRE, no retrospective claims, no staging exceptions.

**Fail closed:** Without registration, current-step PRE, signed action receipt or verifiable POST, the step stays BLOCKED. A healthy gateway or passing CI never proves task completion. Operations outside EG are not governed or eligible for retroactive acceptance.

Evaluation Gateway (EG) checks work **one step at a time**. An agent registers its plan, proves it is safe and ready to perform the next step, runs an authorized action through a trusted worker, and submits independent evidence that the result meets the plan.

**Every step must be verified — including staging, testing, recovery, and cutover steps.** EG does not allow a supported physical action to be presented as verified merely because it was performed or reported afterward.

For the project overview, see the [main README](../README.md). For agent operations begin with the [complete SKILL](../SKILL.md) and [source-verified operation reference](docs/PORTABLE_RUNBOOK.md).

## How a task progresses

1. **REGISTER:** Create an immutable task with ordered steps, required outcomes, and explicit logical/physical classification.
2. **PRE_EXECUTION:** Verify readiness using criteria separate from the future result. Required invariants are checked here too.
3. **EXECUTE:** A supported, independently protected worker checks the authorized gate and performs the effect once.
4. **POST_EXECUTION:** Verify the actual result and unchanged invariants, using fresh evidence and the original signed execution receipt.
5. **VERIFIED:** Only a verified step allows advancement. Final task completion additionally checks task-wide acceptance and the audit history.

```text
REGISTER → PRE → trusted worker → signed receipt → POST → VERIFIED → next step
```

If POST fails, EG does not authorize repeating the physical action. An interruption triggers recovery: prove the effect happened and reuse its receipt, prove it did not happen and request a fresh PRE, or remain blocked if the effect is unknown.

## Generic capabilities and runtime boundaries

A new project does **not** require a project-specific executor. Use the same portable gateway and the actual admitted operations; each step must obtain PRE and submit fresh POST evidence.

EG provides a task registry, hierarchical step ordering, evidence validation, explicit PRE/POST checkpoints, authenticated audit history, pause/resume, failure escalation, linked remediation, and controlled recovery. A separate cutover checker can verify signed provenance and rehearse restoration, but this does **not** by itself certify a production service cutover.

The built-in worker admits only restricted **E0 reads** and reversible **E2 exclusive file creation and compare-and-swap replacement** inside its private `output_root`, with a maximum content size of 512 KiB. Defaults remain `.txt` and valid `.json`; an operator may opt in additional file suffixes (for example `.py`, `.rs`, `.toml`) through the identical strict allowlist enforced by EG and the separate worker. This expands eligible file suffixes only; E2 replacement requires an existing worker-owned file, an exact prior SHA-256 commitment and a separately signed execution receipt. Arbitrary host-file overwrites, directories, shell execution and high-effect privileges remain unsupported. The canonical installation provides bounded reading, exclusive creation and compare-and-swap replacement; no external process workers are installed. Other host operations remain outside the gateway's admitted scope and must not be treated as verified.

A production instance requires external durable state, protected signing keys, and worker privileges isolated from the agent. Neither a GitHub release nor local tests prove that a specific external instance is production-ready.

Evidence provenance is independent of project identity. Bounded
`*_task` producer labels (including historical records) are not
provider-specific executors and confer **no** evidence authority without the
unchanged manifest-v4 independent signature, path/UID, checkpoint and
criterion checks. New tasks use the same provider-neutral source contract.
The [root SKILL operational cookbook](../SKILL.md#provider-neutral-operational-cookbook-normative-for-new-work)
includes registration examples, bootstrap, E0/E2/E3–E5 capability limits, dispatcher
inputs, recovery and acceptance.

## Environment and operations

The supported portable offline target is **Linux x86-64 with CPython 3.12-compatible glibc**. No particular Colab runtime or workspace path is required. Other platforms need independently tested adapters.

For deployment and recovery, use the [portable runbook](docs/PORTABLE_RUNBOOK.md). For exact request and evidence contracts, see the [executor protocol](docs/EXECUTOR_PROTOCOL.md). Historical acceptance reports document historical events; they are not substitutes for current authenticated task state.

## Build and test

Use a **disposable Python 3.12 test environment**, separate from the production
runtime and portable archive. The test-only manifest is pinned and shared
with GitHub Actions. From `eg/`:

```sh
python -m venv .venv-test
. .venv-test/bin/activate
python -m pip install --only-binary=:all: --require-hashes -r requirements.lock
python -m pip install --only-binary=:all: -r requirements-test.txt
PYTHONPATH=.:tests python -m pytest -q -p no:cacheprovider tests
PYTHONPATH=. python tools/run_trusted_e2e.py
PYTHONPATH=. python tools/run_remedial_e2e.py
python tests/live_e2e.py
python tools/build_portable_bundle.py
python tools/test_offline_portable.py
```

If the system Python lacks `venv`/`ensurepip` (common on notebook images),
use `uv venv --python python3.12 .venv-test`, then `uv pip install --python
.venv-test/bin/python --require-hashes -r requirements.lock` and `uv pip
install --python .venv-test/bin/python -r requirements-test.txt`. The production
runtime stays separate in either approach.

`requirements-test.txt` (pytest, httpx, httpx2) is for development/testing **only**; do not put these packages in `requirements.lock`, Docker production images or the portable bundle. A full root-run may show deliberate non-root-only SKIPs; rerun those tests with eligible unprivileged user identities instead of calling SKIPs a PASS.

The E2E scripts use isolated test-only instances. They do not take ownership of a production task or replace the current gateway's authenticated state.

## Project structure

| Location | Purpose |
| --- | --- |
| `app/main.py` | Canonical API, evaluation logic, task and audit state |
| `app/execution_receipts.py` | Signed executor receipt verification |
| `tools/trusted_execution_worker.py` | Bounded worker for admitted E0/E2 effects |
| `tools/check_live_cutover_readiness.py` | Read-only cutover readiness and provenance checks |
| `tests/` | Regression and E2E tests |
| `docs/` | Operational runbook, protocol, architecture, and release criteria |
| Git history | Historical reports remain recoverable by commit SHA; no obsolete snapshots ship in the current tree |

EG has **one canonical task registry and evaluator**. The trusted worker is an execution adapter, not an alternative evaluator.

For multiple admitted external E3/E4/E5 adapters on the same gateway, configure independently authorized class-bound signer public roots with `EVALUATION_GATEWAY_HIGH_EFFECT_HITL_PUBLIC_KEYS_JSON` as documented in [operator bootstrap](docs/PORTABLE_RUNBOOK.md). A shared legacy signer key does not establish per-class independent approval.
