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
**Reusable generic E3 execution:** prefer an operator-pinned multi-target catalog (one adapter, several preapproved commands) via `trusted_process_catalog.py`. A new project never requires a bespoke executor implementation if a live catalog profile already matches. See [Generic execution model](eg/docs/GENERIC_EXECUTION_MODEL.md).

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
- **Source default:** unset `EVALUATION_GATEWAY_ADMISSION_MODE` means `enabled` in `eg/app/main.py`. Preserve that default unless an operator deliberately selects audit-only mode; do not infer live worker availability from this flag.
- `EVALUATION_GATEWAY_ADMISSION_MODE=disabled`: explicitly selected historical audit/reconciliation mode; **all concrete PRE/POST** are fail-closed, regardless of service health.
- `enabled` is only a configuration condition; it does not provision the executor, signers, capability, root isolation, authenticated effect RPC or a live valid PRE. With no worker output root, `/v1/agent/capabilities` still reports built-in effects `UNAVAILABLE`.
- Current portable `init.sh` requires an independently supplied executor **public** root and notary public root at fresh initialization even if `disabled` is selected. If either is missing, do not invent one; see [operator/audit-only bootstrap limitation](eg/docs/OPERATIONS.md#safe-historical-task-migration).
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

Use [the existing orchestrator](eg/tools/single_agent_workflow.py), `tools.single_agent_workflow.run_step`/`run_task`, with `pre_request(checkpoint)`, a real `dispatch_once` callback (via [the trusted agent dispatcher](eg/tools/governed_agent_dispatcher.py), `tools.governed_agent_dispatcher.dispatch_action`), and `post_evidence(pre,receipt)` performing independent target readback. Dispatch status `RECEIPT_VERIFIED_POST_REQUIRED` is **not** a verified task. After each `VERIFIED_PASS`, reread the current step/receipt; after final task-wide criteria require `contract_status=SATISFIED` and `GET /v1/audit/verify` PASS. Never infer a completed task from an intermediate checkpoint.

## Operator-supplied first-run, runtime, test and promotion

For trusted E3–E5 capability, use the existing [operator-only first-run provisioning](eg/docs/ONE_TIME_STAGING_BOOTSTRAP.md), [bounded process service](eg/docs/OPERATOR_PROCESS_SERVICE.md) and [independent scoped approval](eg/docs/SCOPED_STAGING_APPROVAL.md). The operator installs separately protected OS identities, socket, signer, signed registry binding and target policy. An agent may *discover and use* this admitted capability, but not self-register authority. For service workflows, use an admitted generic process catalog profile with signed PRE, independent readback and rollback evidence. A staging test is not proof of production cutover.

Local source-only check (no live authorization), from repository root:

```sh
python eg/tools/agent_readiness.py --effect E2 --action write
python eg/tools/agent_readiness.py --effect E2 --action replace
python eg/tools/agent_readiness.py --effect E3 --action bounded_process_run --json
```

With `--url` and an authorized `EVALUATION_GATEWAY_API_KEY`, the readiness tool makes read-only live capability queries. For local development, from `eg/`, run `python -m pytest -q tests`; see `tests/test_single_agent_workflow.py`, `tests/test_process_external_e2e.py` and `tests/test_trusted_process_catalog.py` for generic signed-worker and recovery E2E. Portable runtime supports Linux x86-64 with CPython 3.12-compatible glibc; use [portable startup, backup, restore and rollback guide](eg/docs/PORTABLE_RUNBOOK.md). CI, file creation and build success never substitute for live E2E, current protocol admission or [production promotion](eg/docs/PRODUCTION_PROMOTION.md).

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

## Provider-neutral operational cookbook (normative for new work)

This section is an **agent procedure**, not a new executor. It applies to unrelated
applications without changing \`eg/app/\`, the signed dispatcher or the original
task contract. Always prefer a capability already admitted on the **target**
deployment. Do not confuse cross-project reuse with cross-host authority:
separate machines and signers retain separate security domains.

### Zero-assumption environment checklist

1. **Identify** the target EG URL, deployed source SHA/version, runtime
   \`GET /v1/protocol\` hash, exact task ID, and operator-provided credentials.
   A GitHub release, a local checkout and a running EG process are distinct.
2. **Discover** \`/health\`, authenticated \`/v1/audit/verify\`,
   \`/v1/agent/capabilities\` and exact \`/v1/agent/capability-match\`.
   For an existing task also fetch \`/v1/tasks/{task_id}\` and \`/state\`.
   Missing task or deployment identity is a discovery blocker, never a reason
   to register a replacement task.
3. **Determine** the exact requested physical effect, class E0–E5, typed
   action, destination, least privilege, input schema, independent readback,
   recovery strategy and rollback requirements.
4. **Select** one already admitted, live, exact-scope worker from the signed
   registry. If absent, request operator onboarding of a bounded policy/profile.
   Never add project-name branches to the evaluator or dispatch through an
   ungoverned host shell. A new project does not imply a new executor module.
5. **Register or resume** the original immutable task; bind original
   acceptance/preconditions separately and store returned \`contract_hash\`.
6. **PRE** with fresh, independently notarized criteria and immutable
   action/payload. Require actionable \`READY_TO_EXECUTE\` and, for high effects,
   a separately signed, scoped approval. Admission diagnostics are not PRE.
7. **Dispatch once**, preserve original nonce/journal and signed receipt.
   Inspect the actual process/target after execution; do not infer outcome
   from command exit or RPC acknowledgement alone.
8. **POST** with fresh independently notarized physical readback and the
   **same** gate/action/receipt. Verify each canonical checkpoint and finally
   task-wide \`SATISFIED\` plus authenticated audit PASS.
9. **Regression and reporting**: rerun impacted capabilities/legacy scenarios,
   verify rollback readiness and distinguish SOURCE, BUILD, RUNTIME and
   CANONICAL evidence. If one gate remains unavailable, report BLOCKED,
   not a percentage-based PASS.

Read-only HTTP discovery (shell syntax is illustrative; the AI agent is not
granted a shell by this documentation):

\`\`\`sh
# The authorized operator supplies both values outside the repository.
curl -fsS "$EG_URL/health"
curl -fsS -H "X-Evaluation-Key: $EVALUATION_GATEWAY_API_KEY" "$EG_URL/v1/protocol"
curl -fsS -H "X-Evaluation-Key: $EVALUATION_GATEWAY_API_KEY" "$EG_URL/v1/audit/verify"
curl -fsS -H "X-Evaluation-Key: $EVALUATION_GATEWAY_API_KEY" "$EG_URL/v1/agent/capabilities"
\`\`\`

Never log, print, embed in a URL, commit or synthesize the API key, HITL key
or private signing key. Loopback HTTP is valid only in an approved local
environment; external endpoints must use trusted HTTPS.

### Generic request shape and producer-neutral evidence

The following JSON illustrates **registration schema only**; the IDs,
criteria and protocol hash must be replaced with actual task-specific values
obtained from the live target. Submitting this illustration does **not**
authorize or execute a physical effect:

\`\`\`json
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
\`\`\`

The canonical evidence-source contract is **producer-neutral**: a bounded
lowercase label ending in \`_task\` (for example \`trusted_task\` or
\`external_task\`) denotes a proposed signed evidence producer.
Historical labels matching the same grammar remain readable **without data
rewriting**. Neither an unfamiliar label nor any source name grants trust:
EG still checks the independently notarized manifest-v4 signature,
trusted ownership/path, fresh phase/checkpoint binding, exact criterion and
matcher. \`manual\` is accepted as an untrusted label but never authoritative.
Malformed labels are rejected by request schema validation. Do not transform
signed or audited historical records merely to rename a producer.

An E3 example **action** (illustrative, not an executable PRE or approval):

\`\`\`json
{
  "action_type": "bounded_process_run",
  "target": "/tasks/workflow/check",
  "effect_class": "E3",
  "reversible": false,
  "real_world_effect": true,
  "payload_sha256": "REPLACE_WITH_64_HEX_SHA256",
  "payload_bytes": 128
}
\`\`\`

For \`POST /v1/evaluate\`, use the same original \`event_id\` on idempotent
request replay and a **new** event ID for a genuinely new PRE/POST. Required
fields are \`task_id\`, \`contract_hash\`, \`protocol_hash\`,
\`checkpoint_no\`, \`step_key\`, \`agent\`, \`phase\`, and criterion-indexed
\`claims\`. POST for physical work also requires the original \`action\` and
\`execution_receipt\`; for the final step use \`finalize_task\` and
independently notarized \`task_claims\`. The signer, evidence references,
action fingerprints and receipts must come from actual operations.
See \`eg/app/main.py\` request models and the
[agent operations reference](eg/docs/AGENT_OPERATIONS_REFERENCE.md) before
forming a mutating request.

The dispatcher's common request is exactly
\`{"task_id":"...","step_key":"...","action":{...},"data_b64":"..."}\`.
Use \`tools.governed_agent_dispatcher.dispatch_action\`; never supply
runtime executable/argv through the agent request. E0/E2 require their
independent signed worker and socket. E3–E5 require a matching authorized
external binding **plus** a distinct scoped HITL approval and exact PRE.

### Reusable operator bootstrap: new environment, not new project

The supported packaged runtime is Linux x86-64 with CPython 3.12-compatible
glibc. Do not infer Windows/macOS/other-architecture support from the generic
action model. For a new Linux installation, an authorized independent
operator first provisions durable state, protected public/private roots,
existing distinct non-root OS identities, authenticated EG and a pinned
worker/signer. \`operator_first_run.py\` uses a root-owned mode-0600 policy,
does not create OS users automatically and refuses to overwrite an existing
installation. Root on the **same host** can still control all such accounts:
a root-capable agent must not claim its signer is independent solely by
dropping UID.

The multi-target policy has common fields \`root\`, \`worker_uid\`,
\`signer_uid\`, \`agent_uid\`, \`adapter_id\`, \`target_prefix\`, \`eg_url\`,
\`gateway_key_file\`, and \`profiles\` (1–32 unique \`/tasks/...\` targets).
Each profile pins an independently controlled absolute executable, immutable
fixed args and optional bounds. The alternative single-target form is only
a backward-compatible policy input, not the recommended new layout. See
[operator bootstrap](eg/docs/ONE_TIME_STAGING_BOOTSTRAP.md).
Provisioning files is not live admission: the operator must start the
separate services, prove worker UID/socket/key independence, activate the
signed registry and test a matching PRE. No capability or independent
signing authority is fabricated by the agent.

| Class | Actual bundled capability | Required when absent |
| --- | --- | --- |
| E0 | Restricted admitted reads via signed bundled worker | Existing target/scope and worker; otherwise approved capability |
| E1 | No blanket network read permission | Independently admitted typed worker |
| E2 | Worker-owned restricted create/compare-and-swap replace (512 KiB limit) | Matching allowed suffix/root, PRE proofs and independent worker |
| E3 | Bounded \`bounded_process_run\` via 1–32 operator-pinned profiles | New **operator-approved profile/policy**, not bespoke source module |
| E4 | Generic dispatcher only; no E4 process-catalog implementation | Independently governed E4 typed worker, compensation as applicable |
| E5 | Generic dispatcher only; no E5 process-catalog implementation | Independently governed E5 worker/HITL; compensation prohibited |

A profile cannot issue arbitrary agent-selected commands or escape its
configured OS permissions, fixed argv, bounded stdin/output and 1–30-second
timeout. \`trusted_process_catalog.py\` shares one adapter signer, socket
and durable nonce ledger across the profiles. Reuse the **same live policy**
for source checks, application tests, and database checks only if all three
actions were actually approved there. A different host/security domain
requires its own legitimate trust provisioning, not a new EG implementation.

### Failure matrix, runtime verification and regression

| Observed state | Required behavior |
| --- | --- |
| No installed/matched capability | \`CAPABILITY_UNPROVISIONED\`; inspect operator policy, do not execute |
| Typed match, no fresh signed PRE | Capability is **diagnostic only**; obtain exact PRE before dispatch |
| Expired/denied HITL | Do not route, retry with changed identity or self-sign |
| Dispatch pending or timeout | Reconcile **original** nonce/journal/target before any retry |
| Signed receipt and actual effect already present | Recover original receipt; submit POST, **never replay** effect |
| Independent \`NOT_EXECUTED\` proof | Use canonical reconciliation; only then obtain fresh PRE |
| POST evidence invalid after real effect | Repair evidence/remedial under original gate; no second execution |
| Step \`VERIFIED_PASS\`, task unfinished | Continue current canonical next step and required global acceptance |
| Task \`SATISFIED\`, audit PASS | Verify affected regressions and rollback; then report task VERIFIED |

On any failure distinguish file/source changes from command/runtime effects,
check the *same* original task and job, and bound retries. For E3 run independent
signed PRE→worker→POST and an unapproved-target rejection through the same
catalog. For cross-UID behavior run privileged isolated tests under legitimate
test-root; SKIP in an unprivileged suite is not PASS and must be covered by a
separate actually executed CI job. CI cannot certify a deployed production
worker or a particular destination's external effects.

### Concrete acceptance for a provider-neutral release

- Source contains no project/provider-dependent **execution branches** in
  evaluator, dispatcher or worker catalog. Diagnostics, historical archives
  and example *data* are not runtime dispatch contracts.
- Three or more unrelated approved target profiles execute through the same
  catalog class/worker identity and durable journal; unknown target fails
  before physical execution.
- New deployment reuses operator bootstrap; new project reuses active typed
  profiles unless a genuinely new permission is requested.
- Evidence labels cannot bypass notarization; historical valid source labels
  remain verifiable. No signed historical audit/data is rewritten.
- Docs, \`SKILL.md\`, schemas, examples and runnable integration tests agree.
  All required isolation/regression tests are actually executed in eligible CI.
- Release is pinned to an exact HEAD that passed source tests and isolated
  worker runtime E2E. **Production** requires additional authorized live
  validation, full restoration and rollback evidence. Do not call CI PASS a
  production VERIFIED outcome.
