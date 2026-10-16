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
