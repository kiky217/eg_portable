# EG portable — canonical active runbook

This document applies to **new deployments and active runtimes**, not to a
historical Colab session. One registry, one current evaluator, one writer.

## Resolve actual state, never copied defaults

Discover from the owner's active environment: `EG_STATE_DIR` (durable external
database, evidence and anchor), `EG_RUNTIME_ENV_FILE`, `EG_LIVE_URL` (actual
loopback endpoint), `EG_TASK_ID`, task contract, source release SHA, current
checkpoint, admission mode and protected executor `output_root`. Authenticate
GET /health, /v1/audit/verify, /v1/tasks/{task_id}/state and task detail
before any plan or mutation. Never log keys or infer a fresh instance from
the previous Colab path. Missing database/signing roots are blockers.

## Software, protocol and receipts

| Identity | Authoritative source | Rule |
| --- | --- | --- |
| Software | `eg/VERSION` | Stable tag with exact-SHA CI success |
| Protocol | SHA-256 of `docs/EXECUTOR_PROTOCOL.md`, `GET /v1/protocol` | New intake binds current digest |
| Historical task contract | Original signed TASK_INTAKE event | Never re-hash/rewrite original task |
| Evidence manifest | Signed v4 envelope | Verify original criterion bindings |
| Execution receipt | Signed, independently keyed envelope | Bind step, PRE, target, action and output |

Changing the current protocol file changes its digest for *future* tasks.
An existing registered task retains the original authenticated hash while
the current hardened evaluator remains authoritative; no legacy evaluator or
retroactive approval is enabled.

## Mandatory step-by-step lifecycle — staging is included

**REGISTER → PRE → verified authorization → independent executor → signed
receipt → POST → VERIFIED → next step**.

1. Register acceptance, dependencies and a complete hierarchy *before*
   effects. Identify the current canonical step, immutable task contract,
   current checkpoint and valid permissions.
2. PRE must verify phase-appropriate evidence, capability, target and bounds,
   exact payload SHA-256/size for new E2 writes, sandbox and rollback proof.
   No READY gate means no new action.
3. Execute exactly once through the independent registered worker and
   maintain its durable intent and receipt. On a lost response, reconcile
   the latest ledger/gate/journal/target before attempting anything again.
4. POST verifies the exact original PRE, signed executor receipt (for any
   action), and independent result evidence. UNVERIFIED means no advancement
   and no renewed effect; never replace it with a second PRE.
5. Proceed only when step is VERIFIED. Full SATISFIED additionally requires
   task-global acceptance and authenticated audit chain PASS.

No staging action is exempt from this lifecycle.

## Cutover and rollback

Current built-in worker supports bounded E0 reads and E2 file writes only;
unsupported service cutover/E3 and shell must be BLOCKED until a separately
trusted tested executor adapter is admitted. Replan into bounded steps only
if each step actually uses a supported capability; never mislabel E3 as a
logical check to bypass admission.

A permitted cutover project separately verifies baseline, transactionally
consistent SQLite and external-anchor/evidence backups, restore rehearsal,
single-writer transition, runtime health and authenticated ledger continuity,
and documented rollback. Each mutation still needs PRE, execution receipt,
POST. Backup checksums or a self-reported owner PASS alone do not prove the
effect or mark the EG step VERIFIED. Issue #14 tracks independent archive
provenance and restore rehearsal.

## Timeout, pause and UNKNOWN effects

A delivery timeout is not a failed execution. Re-read the original event,
gate, task checkpoint, worker journal, signed receipt and target before any
retry. A sealed valid receipt may be recovered read-only without replay.
Keep uncertain effects in RECOVERY_PENDING.

**Known limitation #6:** there is not yet a complete independently signed
NOT_EXECUTED path for an unexecuted unresolved gate. Do not assert no-effect
or issue a new PRE based merely on an absent HTTP acknowledgement or empty
file. Keep the task BLOCKED pending authenticated reconciliation.

## Historical examples and release verification

Archive-only: `ACCEPTANCE_POST_CUTOVER_20261016.md` and the original JSON
record the previous Colab owner decision. Neither is a current task ID,
live deployment checkpoint, or skip-verification policy for other installs.

A validated GitHub release requires regressions, signed worker E2E, remedial
E2E, SHA-256 archive build, offline relocation and clean Debian startup on
its exact commit. Source release success is not evidence of live production
admission.


## Reconciled execution and independent cutover evidence

New `REGISTER` payloads MUST set `execution_required` explicitly on each
plan step. Execution-required steps MUST also declare `preconditions` distinct
from `acceptance_criteria`; immutable `invariants`, when supplied, are
checked in both PRE and POST. A physical step cannot be recast as logical by
omitting `action` at evaluation. Historical registrations are not rewritten.

When a reversible E2 write is interrupted, use the *same registered worker*
`reconcile_no_effect` operation (not the normal WRITE RPC). It checks the
canonical `RECOVERY_PENDING` gate, protected journal and target. Absent
journal/target yields a signed `NOT_EXECUTED` proof. A durable journal without
an output can be retired under the worker lock while preserving its bytes;
the proof can then be submitted to
`POST /v1/tasks/{task_id}/reconcile` with the exact action and pinned executor
public key. EG consumes the old gate in an append-only event, does NOT advance
step acceptance and requires a fresh PRE. A created target is recovered with
the original worker receipt, never replayed. Ambiguous or foreign journal /
target remains blocked; no HITL flag turns UNKNOWN into NOT_EXECUTED.

For independent cutover verification, provide an externally signed
`--cutover-attestation` and a separately provisioned
`EVALUATION_GATEWAY_CUTOVER_PUBLIC_KEY_B64`. The attestation binds report hash,
rollback archive hash, canonical checkpoint/audit head and all restored member
hashes. The verifier performs an actual isolated extraction and byte readback;
missing or changed evidence is denied. The attestor key must not be supplied
by the report or the agent controlling it. This is verification of the
reported cutover evidence; it does NOT authorize an unsupported E3 service
cutover, restore a historical Colab session, or waive the independent EG
step/capability/runtime checks for a new deployment.
