---
name: evaluation-gateway-agent
description: Operate EG end-to-end by reconciling live state, choosing typed capability, registering task, obtaining PRE, executing once, recovering receipt, submitting POST, and verifying final acceptance.
---
# Evaluation Gateway — Agent Operating Skill

Apply to **every** task governed by Evaluation Gateway. Read this file before attempting actions, takeover, retries or declaring completion. This skill documents behavior; it never grants permissions or enables an executor.

## Discover current canonical state
1. Obtain the exact target EG URL, deployment identity, task ID, runtime version, source revision and current credentials from authorized environment. Do not assume historical Colab paths, GitHub release state, or an unrelated EG instance represent the live system.
2. Use authenticated read-only API discovery and query health, audit validity, task detail, current step, current checkpoint, pending gate, lease and worker availability. Consult the **live endpoint's actual protocol** for request names; do not invent endpoint paths.
3. Record whether service is live, admission is enabled, independently protected signing root is provisioned, required adapter exists, and action is presently PRE-authorized. Those are **separate** facts. A running production service does not imply unrestricted execution.

## Live capability discovery (current runtime)
Call authenticated `GET /v1/agent/capabilities` on the **actual** EG instance before planning physical actions. It distinguishes installed bundled transport from untrusted capability declarations. `CONFIGURED_NEEDS_LIVE_PRE` is not worker attestation; `UNVERIFIED_NOT_AUTHORIZED` must never be dispatched. `EVALUATION_GATEWAY_AGENT_CATALOG_JSON` is a bounded optional JSON catalog (schema_version 1, capabilities with id/effect_class/action_type/adapter_id). It is diagnostic-only and does not affect immutable task contract or PRE admission. If missing or invalid, use the bundled worker or independently provision an approved adapter, not a shell bypass.

## Select capability before claiming a step
- Distinguish logical evaluation from an actual physical effect; never relabel the immutable task contract.
- Current bundled production worker handles bounded E0 reads, E2 exclusive **creation** and E2 SHA-256 compare-and-swap **replacement** of existing worker-owned files in its protected output_root (each payload <= 512 KiB). Default suffixes remain `.txt` and valid `.json`.
- The bundled worker cannot execute cargo/tests, shell, service control, Git push or E3–E5. These operations require independently provisioned typed external adapters and per-action PRE/HITL/POST. CI-only sandbox adapters are not deployable production capabilities.
- Before claiming, match exact desired action, effect class, target, adapter identity and testable result to a live, independently trusted adapter. If missing, report `CAPABILITY_UNAVAILABLE` and specify required adapter contract. Do not use direct shell, CI fixture, a dummy key, fabricated receipt, or HITL as a substitute.

## Portable capability model
EG must not hardcode Rust, Git, Docker or any programming toolchain as universal requirements. Discover **registered runtime capabilities** from the target deployment. Match typed action, effect class, scope, constraints, attested executor identity and evidence/receipt contract. Prefer an already-authorized native tool or adapter; agents may propose or install a new adapter only through the operator-approved onboarding and trust process. A self-declared capability is never automatically admitted. The bundled E0/E2 worker is a baseline, **not an upper bound of EG's extensible architecture**. The local readiness script reports only bundled-worker compatibility, not what an external deployment may provide.

## Governed source-file creation (operator opt-in)
The built-in independently signed E2 worker **can** create source files through exact PRE/POST when configured by the operator. EG allows suffixes from `EVALUATION_GATEWAY_EXECUTOR_ALLOWED_SUFFIXES` (comma-separated, default `.txt,.json`), and the separate worker must have the corresponding private-config `allowed_suffixes` list. Example: `.txt,.json,.py,.rs,.toml`. Both remain restricted to the private worker `output_root` (including explicitly pre-provisioned worker-owned 0700 subdirectories, never symlink ancestors), a signed payload commitment and exclusive creation with no overwrite. Neither setting grants command execution, dynamic privilege, Git push, nor E3–E5 support. For a language-independent workflow use the project-selected extension only if the operator's live policy permits it; do not change deployment admission mode to force a match.

## Independently provisioned high-effect transport (E3–E5)
A deployment may register a typed external adapter without hardcoding its toolchain in EG. An operator must separately provision the worker under an independent OS identity and signing domain, pin its UID/socket/signing public root, and configure a scoped capability and separate HITL signer. EG's `EVALUATION_GATEWAY_EXTERNAL_ADAPTER_MODE=enabled` is **not** a bypass: it refuses startup without the independent trust configuration, and each PRE challenges the same worker's live signed identity. The agent must use the unified `dispatch_action` interface with a **signed operator registry** (`EVALUATION_GATEWAY_EXTERNAL_REGISTRY_DIR` and its operator public key) that can resolve exactly one active typed/scope-matching worker **without** per-task socket/UID/signing-key input. Operator-provisioned explicit parameters `external_worker_socket`, `external_worker_uid`, `external_adapter_id`, `external_public_key_b64` are supported when registry routing is not used; both modes require independent signed `hitl_approval` and its pinned public key. Do not mix registry and manual route fields. The dispatcher validates the original EG PRE, signer pin, peer UID, lease, payload binding, and receipt; afterward the agent submits the exact receipt and independent outcome evidence to EG POST. A CI worker, an unverified catalog entry, or a healthy service is never enough.

## PRE → execute once → POST
1. Confirm immutable task criteria, dependencies, resource lease, and actual latest checkpoint.
2. Obtain actionable, unexpired READY PRE for the exact action fingerprint/payload, after satisfying admission and independent worker prerequisites.
3. Dispatch **once** through the registered trusted worker. Verify execution outcome through original journal/target and preserve the signed receipt.
4. Submit fresh independent result evidence plus the **same** receipt to canonical POST. Declare VERIFIED only if canonical step and regression checks truly pass. A successful dispatch or command exit is not VERIFIED.

## Timeouts, reconnect and retries
- A timeout means **UNKNOWN** until original request/job ID, journal, target and receipt are reconciled; never blindly replay a write.
- If effect exists, recover original signed receipt and continue POST; if independently proved NOT_EXECUTED, use canonical reconciliation and new PRE; if uncertain remain RECOVERY_PENDING.
- Retry only a safe, reconciled action without bypassing verification or security denial. A repeated claim/request does not establish execution.

## Admission diagnostic
- `EVALUATION_GATEWAY_ADMISSION_MODE=disabled`: historical audit/reconciliation may function but **all concrete PRE/POST** are fail-closed, regardless of service health.
- `enabled` is only a configuration condition; it does not provision the executor, signers, capability, root isolation, authenticated effect RPC or a live valid PRE.
- Run `python eg/tools/agent_readiness.py --effect E2 --action write` from the repo root for a **local, read-only configuration preflight**. It prints a diagnostic, not proof of live authorization. For Rust build/Git or unsupported effects, diagnostics must identify the missing production adapter rather than claim success.
- Never set admission enabled merely to clear a blocker. Provision and independently verify trusted worker and key isolation first.


## Complete agent run sequence and API navigation

Keep a single original task and its event history; an agent can operate it without another AI agent, but cannot supply its own independent signing authority. The HTTP routes in source `eg/app/main.py` are:

| Route | Use (all except `/health` require protected `X-Evaluation-Key`) |
| --- | --- |
| `GET /health`; `GET /v1/audit/verify` | Minimal liveness vs authenticated current audit/anchor/materialized-state integrity |
| `GET /v1/protocol` | Runtime protocol identity and hash; only new tasks bind this hash |
| `GET /v1/agent/capabilities`, `GET /v1/agent/capability-match` | Configured diagnostics and typed/scope match, **never** a granted effect |
| `GET /v1/tasks/{task_id}`, `GET /v1/tasks/{task_id}/state` | Immutable task detail and current checkpoint, step, pending gate, blocker |
| `POST /v1/tasks/register` | Register once: global acceptance, steps and explicit `execution_required`, with separate `preconditions` for physical steps; record returned `contract_hash` |
| `POST /v1/evaluate` | `PRE_EXECUTION` → original worker → `POST_EXECUTION`; `FACT_CHECK` is non-advancing; only final POST may set `finalize_task` and submit `task_claims` |
| `POST /v1/tasks/{task_id}/pause`, `/resume`, `/reconcile`, `/abort` | Audit-controlled suspension, signed no-effect recovery, and separately HITL-authorized abort |

An `EvalRequest` includes original task/contract/protocol, event ID, checkpoint, step key, agent, phase, criterion-indexed independently notarized `claims`, plus immutable `action` and `execution_receipt` where required. E2 action binds payload SHA-256 and size; E2 replace additionally binds the **previous** file SHA-256. Do not invent signing material, evidence references or replayed claim results. [Exact fields and operational decision table](eg/docs/AGENT_OPERATIONS_REFERENCE.md).

Use `tools.single_agent_workflow.run_step`/`run_task` with `pre_request(checkpoint)`, a real `dispatch_once` callback (via `tools.governed_agent_dispatcher.dispatch_action`), and `post_evidence(pre,receipt)` performing independent target readback. Dispatch status `RECEIPT_VERIFIED_POST_REQUIRED` is **not** a verified task. After each `VERIFIED_PASS`, reread the current step/receipt; after final task-wide criteria require `contract_status=SATISFIED` and `GET /v1/audit/verify` PASS. Never infer a completed task from an intermediate checkpoint.

## Operator-supplied first-run, runtime, test and promotion

For trusted E3–E5 capability, use the existing [operator-only first-run provisioning](eg/docs/ONE_TIME_STAGING_BOOTSTRAP.md), [bounded process service](eg/docs/OPERATOR_PROCESS_SERVICE.md) and [independent scoped approval](eg/docs/SCOPED_STAGING_APPROVAL.md). The operator installs separately protected OS identities, socket, signer, signed registry binding and target policy. An agent may *discover and use* this admitted capability, but not self-register authority. For persistent staging deploy/revise/rollback use [staging service guidance](eg/docs/PERSISTENT_STAGING_SITE.md); successful local staging is not production cutover.

Local source-only check (no live authorization), from repository root:

```sh
python eg/tools/agent_readiness.py --effect E2 --action write
python eg/tools/agent_readiness.py --effect E2 --action replace
python eg/tools/agent_readiness.py --effect E3 --action bounded_process_run --json
```

With `--url` and an authorized `EVALUATION_GATEWAY_API_KEY`, the readiness tool makes read-only live capability queries. For local development, from `eg/`, run `python -m pytest -q tests`; see `tests/test_single_agent_workflow.py`, `tests/test_process_external_e2e.py` and `tests/test_staging_site_eg_integration.py` for actual signed worker and recovery E2E. The manifest runner `python eg/tools/local_project_e2e.py eg/examples/cafe-website.json` runs **only** in an authorized disposable Linux staging environment with separate OS UIDs; it is not a production installer. Portable runtime supports Linux x86-64 with CPython 3.12-compatible glibc; use [portable startup, backup, restore and rollback guide](eg/docs/PORTABLE_RUNBOOK.md). CI, file creation and build success never substitute for live E2E, current protocol admission or [production promotion](eg/docs/PRODUCTION_PROMOTION.md).

## Failure reconciliation and acceptance states

- `ADMISSION_DISABLED` or `TRUSTED_EXECUTOR_UNAVAILABLE_FAIL_CLOSED`: retain historical audit, provision separate trust; do not set admission enabled just for a green status.
- `CAPABILITY_UNPROVISIONED`, `AMBIGUOUS_OR_MISSING_OPERATOR_ADAPTER`: resolve precise external worker and operator trust; do not claim a configured catalog entry is execution.
- `EG_PRE_NOT_READY`, `EG_GATE_OR_ACTION_MISMATCH`, stale checkpoint or 409: reread the **original** gate before any new action.
- `RECEIPT_VERIFIED_POST_REQUIRED`: signed receipt available, independently verify target and submit POST. Already verified → **no replay**.
- Timeout / `RECOVERY_PENDING` / ambiguous journal: **UNKNOWN** until exact old task/gate/journal/target reconciliation; recover a sealed original receipt or independently signed `NOT_EXECUTED` through canonical `/reconcile`; no blind retry or new task to evade denial.
- POST failed: inspect evidence/receipt and plan authorized remediation rather than repeating the effect.
- 401/403: check authorized credentials, not by disabling controls. 422: use original schema. Task-global SATISFIED and authenticated audit PASS are distinct from step `VERIFIED_PASS`.

Never confuse CREATED, SUBMITTED, RUNNING, COMPLETED, VERIFIED or UNKNOWN. Before reporting PASS, identify current runtime/source SHA, task ID/step/checkpoint, operator/adapter identity, original PRE, receipt/journal, physical readback, canonical POST, task acceptance, audit, regression and rollback. Unsupported production authority remains BLOCKED.

## Reporting
State exactly: target instance, software/version, timestamp, task/step/checkpoint, source state, admission, claimed capability, worker state, execution state, canonical verdict, unresolved blocker. Separate `SOURCE PASS`, `BUILD PASS`, `RUNTIME PASS`, `CANONICAL VERIFIED`. Cite actual logs/receipts/checkpoints; never infer them.

References: [complete API/operations reference](eg/docs/AGENT_OPERATIONS_REFERENCE.md), [agent onboarding](eg/docs/AGENT_QUICKSTART.md), [operations](eg/docs/OPERATIONS.md), [executor protocol](eg/docs/EXECUTOR_PROTOCOL.md).