---
name: evaluation-gateway-agent
description: Operate EG end-to-end by reconciling live state, choosing typed capability, registering task, obtaining PRE, executing once, recovering receipt, submitting POST, and verifying final acceptance.
---
# Mandatory EG-gated work, including staging

**"Install EG completely as a generic system and test it end-to-end until every supported, authorized capability is operational."**

**MUST:** Register an immutable plan before work begins; obtain the EG PRE gate before each step; execute only an admitted bounded action; read back its result and submit POST with the original receipt; advance only after VERIFIED. The same workflow applies in development, staging and production. Never finish a project and backfill its task claims.

**FAIL-CLOSED:** Current canonical operations are bounded read, create and replace. An unavailable action stays blocked, never silently reclassified as a logical step or performed outside EG. A source build, CI pass or healthy endpoint is not evidence that an unverified task is complete. Preserve historical audit and signed receipts.


**One installation, one procedure:** Follow this SKILL, [README](README.md) and [runbook](eg/docs/PORTABLE_RUNBOOK.md). Historical operator-process examples are not requirements for the current canonical installation. Every governed physical action, including staging, needs a verified PRE and POST; do not claim completion from deployment health alone.

# Evaluation Gateway — Agent Operating Skill

Apply to **every** task governed by Evaluation Gateway. Read this file before attempting actions, takeover, retries or declaring completion. This skill documents behavior; it never grants permissions or enables an executor.

## Discover current canonical state
1. Obtain the exact target EG URL, deployment identity, task ID, runtime version, source revision and current credentials from authorized environment. Do not assume historical Colab paths, GitHub release state, or an unrelated EG instance represent the live system.
2. Use authenticated read-only API discovery and query health, audit validity, task detail, current step, current checkpoint, pending gate, lease and worker availability. Consult the **live endpoint's actual protocol** for request names; do not invent endpoint paths.
3. Record whether service is live, admission is enabled, independently protected signing root is provisioned, required adapter exists, and action is presently PRE-authorized. Those are **separate** facts. A running production service does not imply unrestricted execution.

## Live capability discovery (current runtime)
Before any physical action, check the authenticated gateway's available operations and current step. Configuration or discovery does not grant execution permission; only a valid PRE for the exact supported operation does. This installation provides bounded file reading, creation and verified replacement. Do not use an external command as a substitute for an unavailable operation.

## Select capability before claiming a step
- Distinguish logical evaluation from an actual physical effect; never relabel the immutable task contract.
- Current bundled production worker handles bounded reads, exclusive **creation** and SHA-256 compare-and-swap **replacement** of existing worker-owned files in its protected output_root (each payload <= 512 KiB). Default suffixes remain `.txt` and valid `.json`.
- The bundled worker does not perform arbitrary shell, service control, Git push or other unsupported host actions. Keep those unavailable rather than bypassing EG or mislabeling them as logical tasks.
- Before claiming, check `GET /v1/agent/capability-match?action_type=read&target=/workspace/example.txt` (or `write` / `replace` with the intended target), followed by the exact EG PRE. The internal operation class is inferred automatically. If unavailable, report `CAPABILITY_UNAVAILABLE`; never use direct shell, dummy evidence or a fabricated receipt.

## Portable capability model
EG governs the same ordered workflow on any supported Linux host. Use only the actions actually returned by the live gateway and never create a new executor for each project. For the canonical installation, physical operations are limited to bounded reads, creation and replacement; unsupported operations remain unavailable.

## Governed source-file creation (operator opt-in)
The built-in signed worker **can** create source files through exact PRE/POST when configured by the operator. EG allows suffixes from `EVALUATION_GATEWAY_EXECUTOR_ALLOWED_SUFFIXES` (comma-separated, default `.txt,.json`), and the separate worker must have the corresponding private-config `allowed_suffixes` list. Example: `.txt,.json,.py,.rs,.toml`. Both remain restricted to the private worker `output_root` (including explicitly pre-provisioned worker-owned 0700 subdirectories, never symlink ancestors), a signed payload commitment and exclusive creation with no overwrite. Neither setting grants command execution, dynamic privilege, Git push, nor unapproved host operations. For a language-independent workflow use the project-selected extension only if the operator's live policy permits it; do not change deployment admission mode to force a match.

## Unsupported operations
An operation outside the canonical read/create/replace boundary is not an EG capability. Do not install historical optional process adapters to make staging look complete. Preserve old task and audit records for verification, but never reclassify an unsupported action as a logical step.

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
- **Source default:** unset `EVALUATION_GATEWAY_ADMISSION_MODE` means `enabled` in `eg/app/main.py`. Preserve that default unless an operator deliberately selects audit-only mode; do not infer live worker availability from this flag.
- `EVALUATION_GATEWAY_ADMISSION_MODE=disabled`: explicitly selected historical audit/reconciliation mode; **all concrete PRE/POST** are fail-closed, regardless of service health.
- `enabled` is only a configuration condition; it does not provision the executor, signers, capability, root isolation, authenticated effect RPC or a live valid PRE. With no worker output root, `/v1/agent/capabilities` still reports built-in effects `UNAVAILABLE`.
- Current portable `init.sh` requires an independently supplied executor **public** root and notary public root at fresh initialization even if `disabled` is selected. If either is missing, do not invent one; see [operator/audit-only bootstrap limitation](eg/docs/OPERATIONS.md#safe-historical-task-migration).
- Run `python eg/tools/agent_readiness.py --action write` from the repo root for a **local, read-only configuration preflight**. It prints a diagnostic, not proof of live authorization. For Rust build/Git or unsupported effects, diagnostics must identify the missing production adapter rather than claim success.
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

An `EvalRequest` includes original task/contract/protocol, event ID, checkpoint, step key, agent, phase, criterion-indexed independently notarized `claims`, plus immutable `action` and `execution_receipt` where required. File creation/replacement binds payload SHA-256 and size; replacement additionally binds the **previous** file SHA-256. Do not invent signing material, evidence references or replayed claim results. [Exact fields and operational decision table](eg/docs/PORTABLE_RUNBOOK.md).

Use [the canonical single-agent workflow](eg/tools/single_agent_workflow.py) through `run_step` or `run_task`. Provide `pre_request(checkpoint)`, a bounded trusted worker callback `dispatch_once`, and `post_evidence(pre, receipt)` backed by independent result readback. Dispatch status `RECEIPT_VERIFIED_POST_REQUIRED` is **not** a verified task. After each `VERIFIED_PASS`, reread the current step/receipt; after final task-wide criteria require `contract_status=SATISFIED` and `GET /v1/audit/verify` PASS. Never infer a completed task from an intermediate checkpoint.

## Canonical first-run and verification

For current portable installations use [the canonical runbook](eg/docs/PORTABLE_RUNBOOK.md) and bundled bounded file operations. Do not configure retired process adapters or special worker identities. Staging is governed by the same PRE, receipt and POST requirements as production.

Local source-only check (no live authorization), from repository root:

```sh
python eg/tools/agent_readiness.py --action write
python eg/tools/agent_readiness.py --action replace
```

With `--url` and an authorized `EVALUATION_GATEWAY_API_KEY`, the readiness tool makes read-only live capability queries. For local development, from `eg/`, run `python -m pytest -q tests`; see `tests/test_single_agent_workflow.py` and `tests/test_real_physical_pre_post_e2e.py` for verified step ordering and signed receipts. Portable runtime supports Linux x86-64 with CPython 3.12-compatible glibc; use [portable startup, backup, restore and rollback guide](eg/docs/PORTABLE_RUNBOOK.md). CI, file creation and build success never substitute for live E2E, current protocol admission or [production promotion](eg/docs/PRODUCTION_PROMOTION.md).

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

References: [complete API/operations reference](eg/docs/PORTABLE_RUNBOOK.md), [agent onboarding](eg/docs/PORTABLE_RUNBOOK.md), [operations](eg/docs/OPERATIONS.md), [executor protocol](eg/docs/EXECUTOR_PROTOCOL.md).

## Provider-neutral operational cookbook (normative for new work)

This section is an **agent procedure**, not a new executor. It applies to unrelated
applications without changing `eg/app/`, the signed dispatcher or the original
task contract. Always prefer a capability already admitted on the **target**
deployment. Do not confuse cross-project reuse with cross-host authority:
separate machines and signers retain separate security domains.

### Zero-assumption environment checklist

1. **Identify** the target EG URL, deployed source SHA/version, runtime
   `GET /v1/protocol` hash, exact task ID, and operator-provided credentials.
   A GitHub release, a local checkout and a running EG process are distinct.
2. **Discover** `/health`, authenticated `/v1/audit/verify`,
   `/v1/agent/capabilities` and exact `/v1/agent/capability-match`.
   For an existing task also fetch `/v1/tasks/{task_id}` and `/state`.
   Missing task or deployment identity is a discovery blocker, never a reason
   to register a replacement task.
3. **Determine** the exact requested operation (bounded read, file creation or verified replacement),
   action, destination, least privilege, input schema, independent readback,
   recovery strategy and rollback requirements.
4. **Select** the exact supported read, create or replace action from the live
   gateway, then obtain its current-step PRE. If unavailable, report BLOCKED;
   never dispatch through an ungoverned host shell. A new project never
   requires a project-specific executor.
5. **Register or resume** the original immutable task; bind original
   acceptance/preconditions separately and store returned `contract_hash`.
6. **PRE** with fresh, independently notarized criteria and immutable
   action/payload. Require actionable `READY_TO_EXECUTE`; a capability listing
   or readiness diagnostic is not authorization.
7. **Dispatch once**, preserve original nonce/journal and signed receipt.
   Inspect the actual process/target after execution; do not infer outcome
   from command exit or RPC acknowledgement alone.
8. **POST** with fresh independently notarized physical readback and the
   **same** gate/action/receipt. Verify each canonical checkpoint and finally
   task-wide `SATISFIED` plus authenticated audit PASS.
9. **Regression and reporting**: rerun impacted capabilities/legacy scenarios,
   verify rollback readiness and distinguish SOURCE, BUILD, RUNTIME and
   CANONICAL evidence. If one gate remains unavailable, report BLOCKED,
   not a percentage-based PASS.

Read-only HTTP discovery (shell syntax is illustrative; the AI agent is not
granted a shell by this documentation):

```sh
# The authorized operator supplies both values outside the repository.
curl -fsS "$EG_URL/health"
curl -fsS -H "X-Evaluation-Key: $EVALUATION_GATEWAY_API_KEY" "$EG_URL/v1/protocol"
curl -fsS -H "X-Evaluation-Key: $EVALUATION_GATEWAY_API_KEY" "$EG_URL/v1/audit/verify"
curl -fsS -H "X-Evaluation-Key: $EVALUATION_GATEWAY_API_KEY" "$EG_URL/v1/agent/capabilities"
```

Never log, print, embed in a URL, commit or synthesize the API key, HITL key
or private signing key. Loopback HTTP is valid only in an approved local
environment; external endpoints must use trusted HTTPS.

### Generic request shape and producer-neutral evidence

The following JSON illustrates **registration schema only**; the IDs,
criteria and protocol hash must be replaced with actual task-specific values
obtained from the live target. Submitting this illustration does **not**
authorize or execute a physical effect:

```json
{
  "event_id": "register-demo-001",
  "task_id": "task-demo-001",
  "protocol_hash": "REPLACE_WITH_LIVE_PROTOCOL_HASH",
  "agent": "authorized-agent",
  "original_instruction": "Verify one bounded operation against its acceptance criteria",
  "acceptance_criteria": ["All required steps independently verified"],
  "steps": [
    {"step_key": "01", "title": "Overall acceptance",
     "acceptance_criteria": ["Overall outcome verified"], "execution_required": false},
    {"step_key": "01.01", "title": "Authorized physical operation",
     "preconditions": ["Target and rollback prerequisites verified"],
     "acceptance_criteria": ["Target readback matches original desired state"],
     "execution_required": true}
  ]
}
```

The canonical `Evidence.source_type` contract is **producer-neutral**: a bounded
lowercase label ending in `_task` (for example `trusted_task` or
`external_task`) denotes a proposed signed evidence producer.
Historical labels matching the same grammar remain readable **without data
rewriting**. Neither an unfamiliar label nor any source name grants trust:
EG still checks the independently notarized manifest-v4 signature,
trusted ownership/path, fresh phase/checkpoint binding, exact criterion and
matcher. `manual` is accepted as an untrusted label but never authoritative.
Malformed labels are rejected by request schema validation. Do not transform
signed or audited historical records merely to rename a producer.

For `POST /v1/evaluate`, use the same original `event_id` on idempotent
request replay and a **new** event ID for a genuinely new PRE/POST. Required
fields are `task_id`, `contract_hash`, `protocol_hash`,
`checkpoint_no`, `step_key`, `agent`, `phase`, and criterion-indexed
`claims`. POST for physical work also requires the original `action` and
`execution_receipt`; for the final step use `finalize_task` and
independently notarized `task_claims`. The signer, evidence references,
action fingerprints and receipts must come from actual operations.
See `eg/app/main.py` request models and the
[agent operations reference](eg/docs/PORTABLE_RUNBOOK.md) before
forming a mutating request.

The agent supplies the exact task, step, action and payload to the admitted bundled worker after PRE. Never select an arbitrary executable or supply an unapproved shell command; preserve the signed receipt for POST.

### Portable first-run
Use the single canonical gateway and bundled trusted file operations. Never provision the retired process adapters.

### Failure matrix, runtime verification and regression

| Observed state | Required behavior |
| --- | --- |
| No installed/matched capability | `CAPABILITY_UNPROVISIONED`; inspect operator policy, do not execute |
| Typed match, no fresh signed PRE | Capability is **diagnostic only**; obtain exact PRE before dispatch |
| Expired or denied PRE | Do not dispatch; inspect the original gate and reconcile if needed |
| Dispatch pending or timeout | Reconcile **original** nonce/journal/target before any retry |
| Signed receipt and actual effect already present | Recover original receipt; submit POST, **never replay** effect |
| Independent `NOT_EXECUTED` proof | Use canonical reconciliation; only then obtain fresh PRE |
| POST evidence invalid after real effect | Repair evidence/remedial under original gate; no second execution |
| Step `VERIFIED_PASS`, task unfinished | Continue current canonical next step and required global acceptance |
| Task `SATISFIED`, audit PASS | Verify affected regressions and rollback; then report task VERIFIED |

On any failure distinguish file/source changes from command/runtime effects,
check the *same* original task and job, and bound retries. A skipped test is not a PASS; release verification must preserve original task evidence and the authenticated audit.

### Concrete acceptance for a provider-neutral release

- Source contains no project/provider-dependent **execution branches** in
  evaluator, dispatcher or worker catalog. Diagnostics, historical archives
  and example *data* are not runtime dispatch contracts.
- Supported read/create/replace operations use the same bounded worker and durable receipt journal; unknown targets fail before physical execution.
- New projects reuse the portable gateway; no new per-project executor.
- Evidence labels cannot bypass notarization; historical valid source labels
  remain verifiable. No signed historical audit/data is rewritten.
- Docs, `SKILL.md`, schemas, examples and runnable integration tests agree.
  All required isolation/regression tests are actually executed in eligible CI.
- Release is pinned to an exact HEAD that passed source tests and isolated
  worker runtime E2E. **Production** requires additional authorized live
  validation, full restoration and rollback evidence. Do not call CI PASS a
  production VERIFIED outcome.
