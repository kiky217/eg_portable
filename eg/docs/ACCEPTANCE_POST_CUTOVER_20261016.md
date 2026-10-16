# Owner acceptance revision — EG 3.1 after completed Colab cutover

**Effective revision:** 2026-10-16-v2

**Scope:** Operational/release acceptance of the completed EG 3.0.1 → 3.1 migration in Google Colab.

**Source of authority:** Owner's explicit instruction to update acceptance because cutover has already been performed.

## Revised acceptance: cutover is complete

The previous operational cutover check must **not** continue to report
"cutover not performed" merely because trusted executor admission remains
disabled. These are independent outcomes.

| Criterion | Confirmed status |
| --- | --- |
| One primary EG writer on Colab | PASS |
| Old 3.0.1 process stopped and old runtime removed | PASS |
| EG 3.1.0-beta.1 running on the same canonical endpoint | PASS |
| Existing SQLite task registry and audit chain preserved | PASS |
| Historical completed task checkpoint 48 preserved | PASS |
| Open unified-refactor task checkpoint 26 and its PRE25 gate preserved | PASS |
| Authenticated audit 184/184; anchor and materialized state valid | PASS |
| Transactional DB dump, evidence and old-runtime rollback copies retained | PASS |
| 131/131 source regression tests passed | PASS |
| GitHub main is the unified source; portable distribution available | PASS |

**Operational cutover verdict:** `PASS`. The owner-authorized cutover has
already been executed; **do not perform another cutover** to prove completion.

Evidence:
- `/content/workspace/eg/program-vnext/unified-refactor/eg-colab-cutover-20261015-2347.json`
- `/content/workspace/eg/program-vnext/unified-refactor/post-cutover-release-check-20261015-2354.json`
- Rollback: `/content/workspace/eg/backups/eg-cutover-20261015-2347/`
- Active source: `/content/workspace/eg/program-vnext/publish-branch/repo/eg/`

## Separate acceptance: trusted executor for future task execution

This is **not a prerequisite for declaring the completed service cutover
operationally successful**. It remains a separate readiness gate for starting
and verifying new governed concrete actions.

- Current runtime admission is `disabled`. Thus operations that require an
  independent trusted executor remain unavailable.
- Before enabling it, an executor identity and protected Ed25519 signing
  authority must actually exist, and the registered public key must differ
  from the evidence notary key.
- A real PRE, still-authorized execution, independent readback, signed receipt
  and fresh signed POST criterion evidence are still necessary where the
  protocol requires them. Do not forge or backdate receipts.
- QEMU within Colab shares the Colab-root control domain. Do not claim its
  private key is independent of Colab root based solely on QEMU isolation.
- No VPS is part of this project.

## Registered EG task: preserve original acceptance and audit

Task: `task-eg-unified-portable-refactor-20261015-v1`

Registered contract SHA-256: `4915fc7b8550dbbdf36220bc4901c9be6daba51c46e77bbd1928e389910fcceb`

The registered original contract remains **immutable**. At revision time its
state was `IN_PROGRESS / OPEN`, checkpoint `26`, **12/16 VERIFIED**, with
`07.01`, `07`, `08.01` and `08` not formally VERIFIED.

The prior `07.01` PRE gate at checkpoint 25 is older than its bounded
authorization lease; it must not authorize a new write. The real cutover
already happened outside that expired gate. It is **not valid** to invent an
old signed execution receipt or to mark a step VERIFIED by updating SQLite,
rewriting audit history or relaxing EG's evidence verifier.

Therefore:
1. **Accept and record** migration/release engineering as operationally
   complete in this revision. Remove cutover as a pending operational work
   item.
2. Track formal task-ledger closure separately via the supported authenticated
   append-only EG workflow; no retrospective certification.
3. Track genuine trusted-executor admission as a separate future-operation
   workstream, not as an undo/repeat instruction for the completed cutover.
4. If formal acceptance must be changed, use a new owner-authorized,
   explicitly versioned contract/successor through supported EG interfaces;
   never silently mutate the original registered contract.

**Meaning of this revision:** a superseding owner operational acceptance,
not a replacement for an EG `VERIFIED_PASS`/terminal `SATISFIED` receipt.

Machine-readable version: `docs/acceptance-post-cutover-20261016.json`.
