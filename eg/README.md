# Evaluation Gateway — application and developer guide

## MANDATORY FROM INSTALLATION — FULL CAPABILITY ACCEPTANCE

**"Install EG completely as a generic system and test it end-to-end until every supported, authorized capability is operational."**

**Host-neutral operation:** EG supports a root or non-root gateway. Optional `EVALUATION_GATEWAY_LOCAL_HOST_MODE=enabled` runs its reusable typed E3–E5 worker on the existing host account; installing a separate OS account or project-specific executor is not required. REGISTRATION, PRE, scoped approval, signed worker receipt and POST still govern each effect.

**Required for every fresh installation and upgrade (including staging):** Read the [canonical agent SKILL](../SKILL.md) first. Inventory **E0, E2, E3, E4, and E5**. Install the EG gateway and durable audit/evidence state, configure independently protected credentials and trust roots, bring the built-in E0/E2 worker online, and provision/register/activate the **generic** E3/E4/E5 process catalog workers and independently administered scoped HITL signers for every effect class and target profile the operator has actually authorized. Verify live socket/UID identity, signed operator binding, exact typed capability match, and liveness. **Do not build project-specific executor code or infer privileges from the presence of source code.**

**Mandatory acceptance for every authorized capability:** Demonstrate the original EG **REGISTER → PRE → independently authorized execution → signed receipt → POST → VERIFIED → task SATISFIED** with a real physical effect where applicable, independent result readback, and relevant denial, replay/idempotence, crash recovery, and rollback tests. High-effect signed HITL must be valid **before PRE admission**. **CI PASS, `/health: PASS`, source/build completion, and capabilities merely listed/configured are never proof of live E2E readiness.**

**Fail-closed completion rule:** Missing independent operator approval, worker/UID, signer, scoped policy, profile, credentials, registration, or live PRE/POST evidence means the requested full installation is **INCOMPLETE / BLOCKED**, not COMPLETED. Identify the exact prerequisite; never fabricate independent authority, self-approve, or bypass EG by running the effect directly. Generic means reusable implementations with **separately authorized privileges**, not an unrestricted shell.

Evaluation Gateway (EG) checks work **one step at a time**. An agent registers its plan, proves it is safe and ready to perform the next step, runs an authorized action through a trusted worker, and submits independent evidence that the result meets the plan.

**Every step must be verified — including staging, testing, recovery, and cutover steps.** EG does not allow a supported physical action to be presented as verified merely because it was performed or reported afterward.

For the project overview, see the [main README](../README.md). For agent operations begin with the [complete SKILL](../SKILL.md) and [source-verified operation reference](docs/AGENT_OPERATIONS_REFERENCE.md).

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

A new project does **not** require a project-specific executor. The generic E3 service supports a reusable multi-target process catalog with one worker identity, one signed adapter, one nonce ledger and exact preapproved actions. See [Generic execution model](docs/GENERIC_EXECUTION_MODEL.md).

EG provides a task registry, hierarchical step ordering, evidence validation, explicit PRE/POST checkpoints, authenticated audit history, pause/resume, failure escalation, linked remediation, and controlled recovery. A separate cutover checker can verify signed provenance and rehearse restoration, but this does **not** by itself certify a production service cutover.

The built-in worker admits only restricted **E0 reads** and reversible **E2 exclusive file creation and compare-and-swap replacement** inside its private `output_root`, with a maximum content size of 512 KiB. Defaults remain `.txt` and valid `.json`; an operator may opt in additional file suffixes (for example `.py`, `.rs`, `.toml`) through the identical strict allowlist enforced by EG and the separate worker. This expands eligible file suffixes only; E2 replacement requires an existing worker-owned file, an exact prior SHA-256 commitment and a separately signed execution receipt. Arbitrary host-file overwrites, directories, shell execution and high-effect privileges remain unsupported. E3–E5 use the same reusable operator-pinned process-catalog implementation with an independently administered, authenticated class-bound E3, E4 or E5 worker. Arbitrary actions still require explicitly installed OS capability and permission. E4 signed operations are reversible with separately governed corrective steps; E5 is irreversible and never replayable. The generic dispatcher supports those explicitly provisioned adapters, but the built-in worker remains E0/E2-only. The repository's disposable E3–E5 workers are **CI-only fixtures** used to prove PRE, signed receipt, POST and crash recovery, never production executors. Real-world service changes and arbitrary shells remain BLOCKED without separately deployed trusted transports. HITL approval is separate from executor capability.

A production instance requires external durable state, protected signing keys, and worker privileges isolated from the agent. Neither a GitHub release nor local tests prove that a specific external instance is production-ready.

Evidence provenance is independent of project identity. Bounded
`*_task` producer labels (including historical records) are not
provider-specific executors and confer **no** evidence authority without the
unchanged manifest-v4 independent signature, path/UID, checkpoint and
criterion checks. New tasks use the same provider-neutral source contract.
The [root SKILL operational cookbook](../SKILL.md#provider-neutral-operational-cookbook-normative-for-new-work)
includes registration examples, bootstrap, E0–E5 capability limits, dispatcher
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
| `tools/trusted_process_catalog.py` | Operator-pinned generic E3 multi-target process catalog |
| `tools/operator_process_service.py` | Separate-UID generic E3 process host and signed RPC |
| `tools/governed_agent_dispatcher.py` | Shared E0–E5 typed action routing, not a shell |
| `tools/check_live_cutover_readiness.py` | Read-only cutover readiness and provenance checks |
| `tests/` | Regression and E2E tests |
| `docs/` | Operational runbook, protocol, architecture, and release criteria |
| Git history | Historical reports remain recoverable by commit SHA; no obsolete snapshots ship in the current tree |

EG has **one canonical task registry and evaluator**. The trusted worker is an execution adapter, not an alternative evaluator.

For multiple admitted external E3/E4/E5 adapters on the same gateway, configure independently authorized class-bound signer public roots with `EVALUATION_GATEWAY_HIGH_EFFECT_HITL_PUBLIC_KEYS_JSON` as documented in [operator bootstrap](docs/ONE_TIME_STAGING_BOOTSTRAP.md). A shared legacy signer key does not establish per-class independent approval.
