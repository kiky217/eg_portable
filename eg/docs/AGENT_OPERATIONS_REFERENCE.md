# EG Agent Operations Reference — current executable contract

Use one approved E3 process catalog for all matching actions. E4/E5 still
require independently provisioned typed workers. See
[Generic execution model](GENERIC_EXECUTION_MODEL.md).

Read [root SKILL](../../SKILL.md) first. This operational index is grounded in `eg/app/main.py`, `tools/governed_agent_dispatcher.py`, the supported E0/E2 worker and `docs/EXECUTOR_PROTOCOL.md`. It is guidance, **not** authority to execute, deploy, sign HITL, or operate an unprovisioned system. The actual target EG runtime and its original signed task always win over sample paths and a GitHub release.

## 1. Discover and reconcile actual live state (read-only)

Operator supplies the exact deployment URL, independently protected API credentials, live worker registry and task ID. For API authentication use **`X-Evaluation-Key`**; do not put tokens in URLs or reports. HTTP is appropriate only on approved loopback; remote deployments require trusted HTTPS.

| Method and route | Meaning |
| --- | --- |
| `GET /health` | Minimal unauthenticated integrity/liveness PASS or failure; **not** execution admission |
| `GET /v1/audit/verify` | Authenticated integrity of chain, anchor, materialized state, runtime version and admission |
| `GET /v1/protocol` | Live protocol version/hash, configured worker capabilities and output suffixes |
| `GET /v1/agent/capabilities` | Diagnostic bundled, catalog and registry capabilities; not signed PRE |
| `GET /v1/agent/capability-match?effect_class=E3&action_type=bounded_process_run&target=/tasks/EXAMPLE` | Read-only typed scope match; always `admission=false` |
| `GET /v1/tasks/{task_id}` | Immutable task detail, criteria, steps, checkpoint history |
| `GET /v1/tasks/{task_id}/state` | Current step, latest checkpoint, pending gate, block reason and next action |

From **repository root**, a static preflight (never executes effects) is:

```sh
python eg/tools/agent_readiness.py --effect E2 --action write
python eg/tools/agent_readiness.py --effect E2 --action replace
python eg/tools/agent_readiness.py --effect E3 --action bounded_process_run --json
```

Add `--url YOUR_AUTHORIZED_EG_URL` with operator-supplied `EVALUATION_GATEWAY_API_KEY` in environment for authenticated **read-only** live discovery. `CONFIGURED_NEEDS_LIVE_PRE`, `EXTERNAL_LIVE_PRE_ATTESTATION_REQUIRED`, `LIVE_PRE_REQUIRED` and `MATCHED_PRE_REQUIRED` are not effect authorization. `UNVERIFIED_NOT_AUTHORIZED` is never dispatchable.

## 2. Effects and worker authority

| Effect/action | Supported boundary |
| --- | --- |
| `read/E0` | Restricted separately signed bundled worker; exact admitted target |
| `write/E2` | Exclusive new worker-owned file inside private `output_root` |
| `replace/E2` | Existing worker-owned file, **atomic compare-and-swap** with exact `previous_sha256`; not arbitrary host overwrite |
| `E3–E5` typed | Only operator-provisioned external worker, independent UID/signing root, active signed operator registry, scoped HITL, fresh exact PRE and durable receipt |
| Logical evaluation | Criteria and evidence without pretending a physical effect was logical |

E2 is bounded to 512 KiB per payload and suffix allowlists (default `.txt`, valid `.json`). Other types require identical policy opt-in in EG (`EVALUATION_GATEWAY_EXECUTOR_ALLOWED_SUFFIXES`) and the independent worker (`allowed_suffixes`). Permission to create source files **does not** authorize running those files or provisioning directories.

Preferred executor entrypoint: `tools.governed_agent_dispatcher.dispatch_action(request, *, eg_url, api_key, ...)`; request fields are `task_id`, `step_key`, exact `action`, and `data_b64`. An E0/E2 route can reuse operator-set `EVALUATION_GATEWAY_WORKER_SOCKET` and `EVALUATION_GATEWAY_EXECUTOR_PUBLIC_KEY_B64`. E3–E5 can reuse `EVALUATION_GATEWAY_EXTERNAL_REGISTRY_DIR` and `EVALUATION_GATEWAY_EXTERNAL_REGISTRY_OPERATOR_PUBLIC_KEY_B64`: when adapter ID is omitted, the dispatcher selects **exactly one** active signed typed match, otherwise fails closed. An operator-provided explicit route is also supported, but never mix manual external UID/socket/key with registry routing. External dispatch still requires **separate signed `hitl_approval`** and pinned HITL public key. `request_scoped_approval` queries an independently administered signer; it is not AI self-approval. CI-only disposable adapters are not production workers.

For provisioning: [operator staging bootstrap](ONE_TIME_STAGING_BOOTSTRAP.md), [E3 service](OPERATOR_PROCESS_SERVICE.md), [standing signer](SCOPED_STAGING_APPROVAL.md), [generic execution model](GENERIC_EXECUTION_MODEL.md), [operator operations](OPERATIONS.md). None is a universal arbitrary-shell authority.

## 3. Mutating routes and exact task progression

| Method and route | Constraints |
| --- | --- |
| `POST /v1/tasks/register` | `event_id`, `task_id`, runtime `protocol_hash`, `agent`, `original_instruction`, global `acceptance_criteria`, `steps`; each step explicitly specifies `execution_required`; physical steps have separate `preconditions`. Store canonical returned `contract_hash`. |
| `POST /v1/evaluate` | `PRE_EXECUTION` for notarized precondition claims and immutable action, `POST_EXECUTION` for independent outcome evidence plus **original signed execution receipt**, `FACT_CHECK` for read-only checks. `finalize_task` may only be used at POST with task claims. |
| `POST /v1/tasks/{task_id}/pause` | Audited; original contract/protocol hashes, checkpoint, new event ID and reason. |
| `POST /v1/tasks/{task_id}/resume` | Audited; may enter `RECOVERY_PENDING` and does not reauthorize a pending physical effect. |
| `POST /v1/tasks/{task_id}/reconcile` | Only original pinned worker's **signed NOT_EXECUTED proof** with immutable original action; consumes gate **without** step verification. |
| `POST /v1/tasks/{task_id}/abort` | Separately authorized HITL in `X-Evaluation-HITL-Key` and immutable task state; open remedial must be resolved/aborted first. |

The `/v1/evaluate` request has `event_id`, `task_id`, `contract_hash`, `protocol_hash`, `checkpoint_no`, `step_key`, `agent`, `phase` and criterion-indexed `claims` with independent signed evidence. `Action` has `action_type`, `target`, `effect_class`, `reversible`, `real_world_effect`; for E2 write/replace it binds payload `payload_sha256` and `payload_bytes`, and E2 replace also binds `previous_sha256`. Do not invent receipt/manifest signatures or replay them across different gates.

**Canonical sequence**: REGISTER → DISCOVER exact typed capability → RESOLVE independently trusted worker → ADMIT → notarized PRE `READY_TO_EXECUTE` → original worker EXECUTE **once** → `RECEIPT_VERIFIED_POST_REQUIRED` → independent target readback and POST evidence → canonical `VERIFIED_PASS` → next step → task-wide `SATISFIED` + authenticated audit `PASS`. A command exit, output file, healthy server or valid signed receipt alone does not finish a task.

Prefer reusable `tools.single_agent_workflow.run_step`/`run_task`: callbacks provide the original `pre_request`, real `dispatch_once` and independent `post_evidence`; the `finalize` callback must separately submit task-wide acceptance. The helper **does not** mint its own approval or receipt. See [one-agent workflow](SINGLE_AGENT_WORKFLOW.md) and the provider-neutral request examples in `tests/test_single_agent_workflow.py`, `tests/test_trusted_process_catalog.py` and `tests/test_process_external_e2e.py`.

## 4. Timeout, unknown effect and no replay

| Canonical observations | Correct action |
| --- | --- |
| `VERIFIED_PASS` plus audit PASS | Advance once, do not repeat effect |
| Same original sealed signed receipt and actual target match | Recover original receipt, submit original canonical POST |
| Separately authenticated worker journal and target prove **NOT_EXECUTED** | Submit `/reconcile` with signed no-effect proof, then obtain **fresh PRE**; step remains open |
| Claimed journal but no valid receipt / ambiguous physical target | `RECOVERY_PENDING`, operator reconciliation; **no duplicate execute** |
| PRE denied or missing capability, with no effect | Correct prerequisite and request authorized PRE; never bypass via a new transport |
| POST failed after effect | Inspect the original evidence, receipt and remedial criteria; do not execute again to improve score |

For read-only diagnosis see `tools/generic_recovery.py`, `tools/recovery_inspector.py`, operator `tools/recovery_cli.py`. None authorizes execution. A timeout is **UNKNOWN**, not proof of failure. Event IDs may be replayed idempotently for original requests only; do not reuse them for a new action. Do not register a replacement task to escape a denied/ambiguous one.

## 5. Operational triage

- `ADMISSION_DISABLED`, `TRUSTED_EXECUTOR_UNAVAILABLE_FAIL_CLOSED`: independently protected trust/admission missing.
- `CAPABILITY_UNPROVISIONED`, `NO_ACTIVE_TYPED_ADAPTER`, `AMBIGUOUS_OR_MISSING_OPERATOR_ADAPTER`: missing/ambiguous operator binding; request precise signed provisioning.
- `EG_PRE_NOT_READY`, `EG_GATE_OR_ACTION_MISMATCH`, `STALE_CHECKPOINT`: wrong task/gate/step/fingerprint. Re-read canonical state.
- `RECEIPT_VERIFIED_POST_REQUIRED`: signed effect proven; canonical POST still due.
- `NO_EFFECT_WORKER_PROOF_INVALID`, `RECOVERY_PENDING`: reconcile with original worker; do not invent a proof.
- HTTP 401/403: check authorized API/HITL credentials without printing them. 409: inspect code and pending state. 422: use the model contract, not guessed fields.

## 6. Safe acceptance and diagnostics

From `eg/`: `python -m pytest -q tests`. Additional isolated regressions: `PYTHONPATH=. python tools/run_trusted_e2e.py`, `PYTHONPATH=. python tools/run_remedial_e2e.py`, `python tests/live_e2e.py`. Use the reusable E3 catalog and signed process tests (`tests/test_trusted_process_catalog.py`, `tests/test_process_external_e2e.py`) for an isolated operator-approved workflow. Tests do not authorize live effects. GitHub CI additionally checks separate-UID workers, independent signatures,
bounded catalog dispatch, receipt/recovery safeguards and portable archive relocation; it does **not** prove a particular live production installation.

Production requires independently operated persistent state, database/anchor/evidence backup and restore rehearsal, verified external worker liveness, authorized cutover, rollback and **fresh canonical POST**. See [portable runbook](PORTABLE_RUNBOOK.md) and [production promotion](PRODUCTION_PROMOTION.md). A task report should show timestamp/zone, actual runtime/source SHA, task/step/checkpoint and original event, signed worker result, target readback, PRE/POST, task-wide acceptance, audit, regression and rollback; label SOURCE, BUILD, RUNTIME and CANONICAL separately. Do not call it PASS without the required evidence.
