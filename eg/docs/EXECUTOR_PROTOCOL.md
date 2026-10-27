# Evaluation Gateway Executor Protocol 3.1

This is the current, hash-bound contract for Evaluation Gateway (EG). All MUST
requirements are enforced fail-closed. Read [the canonical runbook](PORTABLE_RUNBOOK.md)
for installation; this document is a verification contract, **not** an
instruction to install optional execution adapters.

## Scope and authority

- The canonical portable installation admits bounded file **read**, exclusive
  **write** (create), and SHA-256 compare-and-swap **replace** only, inside the
  configured private worker output root. Default allowed suffixes are
  `.txt` and validated `.json`. Operator-approved additional suffixes change
  file eligibility, not execution privileges.
- There is one gateway, task registry, audit chain, and authoritative evaluator.
  Other host operations (shell, service control, Git push and deployment cutover)
  are **not** bundled capabilities; a successful external command cannot be
  claimed as an EG-governed execution.
- Task-gate authority, independent evidence-notary authority, and the bounded
  worker's receipt signer have separate cryptographic purposes. No agent may
  invent signer keys, self-approve unavailable actions or retroactively mint
  proof of execution.

## Task registration and ordered steps

1. REGISTER MUST precede work. A task binds its original instructions,
   immutable acceptance criteria, ordered hierarchical step keys and protocol
   digest. Steps execute in canonical post-order; every required hierarchy
   node must be satisfied.
2. Each new step MUST explicitly declare `execution_required`. A physical
   step additionally requires separate `preconditions` and
   `acceptance_criteria`; an optional `invariants` set must hold in PRE and
   POST. A logical step does not grant authority for a physical side effect.
3. Every current-step criterion MUST be claimed at its registered index with
   identical text. A request MUST NOT inject matchers or freshness policies.
   Unknown request fields are rejected.
4. FACT_CHECK is read-only; it MUST NOT close a step, authorize an operation,
   advance a checkpoint or finalize a task.

## BEFORE execution: original PRE

5. An execution-required step MUST obtain actionable `READY_TO_EXECUTE`
   PRE before dispatch. PRE checks exact target, capability, payload, criteria,
   permissions, resource lease and independently notarized readiness.
6. PRE and FACT_CHECK evidence MUST have been produced after task registration.
   Every authoritative evidence claim has exactly the signed manifest-v4
   binding for its task, step, criterion or proof purpose, phase and checkpoint.
   Evidence producer labels alone carry no authority.
7. File creation and replacement PRE MUST bind lowercase
   `payload_sha256` and `payload_bytes` for the exact proposed content
   (1..524288 bytes); replacement also binds the original
   `previous_sha256`. The applicable signed `sandbox_pass`,
   `rollback_ready` and `reversible` proofs bind action intent, step,
   phase and PRE request checkpoint.
8. An outstanding actionable READY gate MUST NOT be superseded by later PRE.
   An expired gate, missing worker, invalid signature or unavailable action
   remains BLOCKED rather than enabling direct shell fallback.

## Execution, recovery and original POST

9. The admitted worker verifies the exact PRE and executes only its bounded
   authorized operation. It checks file type, permitted suffix, ownership,
   symlink safety, payload and (for replacement) preimage before mutation.
   The worker persists the original journal and issues an independent signed
   receipt after committed work and target readback.
10. Every POST for a concrete file operation MUST carry the **same** complete
    action fingerprint and the original signed execution receipt tied to task,
    step, PRE gate, target and output. Claim evidence alone is insufficient.
    Logical no-action steps have no physical execution receipt to fabricate.
11. POST evidence MUST be newly obtained after the original PRE gate and
    bind its `gate_checkpoint_no`. PRE/FACT_CHECK evidence instead binds the
    request checkpoint. Evidence from another phase or checkpoint is rejected.
    Independent manifest-v4 signatures and `stdout.log` assertions
    (`contains`, `not_contains`, `equals`) are verified against the signed
    binding, never against a caller-supplied matcher.
12. A failed POST does **not** consume a READY gate. The agent may submit
    fresh POST evidence against the SAME gate and original receipt, but MUST
    NOT execute the operation again. UNKNOWN effect remains BLOCKED.
13. On timeout or crash, reconcile the ORIGINAL gate, durable journal, receipt
    and target. If the effect occurred, recover the sealed original receipt.
    Only independently signed `NOT_EXECUTED` reconciliation may consume the
    old gate without verifying a step, permitting a fresh PRE. Missing response
    alone does not prove non-execution.
14. Only verified POST closes the step. Advance only after `VERIFIED_PASS`;
    final `SATISFIED` also requires separately signed task-global acceptance
    and authenticated audit integrity. Never register work afterward merely
    to claim that completed work had been governed.

## Integrity, lifecycle, remediation

15. Mutations MUST supply the latest checkpoint and immutable contract/protocol
    identity. Event IDs are idempotent and request-hash bound; a different
    payload cannot reuse an event ID.
16. The audit ledger MUST remain a gap-free SHA-256 chain authenticated with
    sequence-bound HMAC and a separately authenticated external anchor.
    Database rollback, audit truncation, modified materialized state, unsafe
    evidence paths or invalid signatures fail closed.
17. Evidence access MUST enforce safe ownership, file mode, size and path
    limits. The notarized evidence manifest format remains version 4; manually
    declared results and unsigned/older manifest formats are not authoritative.
18. PAUSE keeps a durable checkpoint; RESUME with an outstanding gate enters
    recovery. Remediation is linked to the same original task and acceptance
    criteria and never replaces the original verified history. Aborts and
    sensitive baseline changes require their existing separate authorization.
19. These rules apply equally to development, staging, testing, recovery and
    production. CI/build success and healthy service responses are **not**
    permission to bypass PRE, receipts, POST or final acceptance.

## Protocol identity and historical tasks

- The human protocol label is `3.1`; the authoritative current identifier is
  SHA-256 of the **exact bytes of this document**, returned by
  `GET /v1/protocol`. New tasks MUST bind the current digest.
- An existing task MUST retain the original protocol hash authenticated in
  its signed `TASK_INTAKE` event. The current evaluator validates that
  historical task under current fail-closed controls without rewriting its
  record, re-signing its evidence or dispatching a legacy implementation.
- Earlier protocol text, including obsolete effect-class identifiers and
  optional adapter onboarding instructions, is preserved in Git history for
  forensic audit only. Those historical instructions are **not** required by
  the canonical installation.
