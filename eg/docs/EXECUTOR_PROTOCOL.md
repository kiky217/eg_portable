# Evaluation Gateway Hardened Executor Protocol 3.1

Normative rules. "MUST" violations are rejected fail-closed by the gateway.

## Contracts and hierarchy
1. Every task MUST be registered before evaluation with an immutable protocol-bound contract.
2. Every task MUST use hierarchical numeric step keys; every hierarchy node is required and execution follows canonical post-order.
3. Every criterion of the current step MUST be covered exactly once. `Claim.claim` MUST exactly equal the registered criterion text at its index.
4. Request bodies are strict: unknown fields are rejected (HTTP 422). In particular a client can NOT supply an evidence matcher or a freshness window.

## Evidence (signed manifest v4)
5. Every authoritative claim MUST be supported by fresh Ed25519-notarized manifest-v4 evidence. The signed bindings MUST contain exactly one binding whose identity equals what the gateway requires: task, step, criterion index, exact criterion text, **phase** and **checkpoint reference** (below).
6. The assertion applied to `stdout.log` is the `matcher` (`contains` / `not_contains` / `equals`) carried **inside the signed binding**. It is never client-supplied.
7. Checkpoint reference (`checkpoint_no` inside a binding): `PRE_EXECUTION` and `FACT_CHECK` use the request `checkpoint_no`; `POST_EXECUTION` uses the `gate_checkpoint_no` of the `READY_TO_EXECUTE` PRE gate being closed. Evidence for one phase/checkpoint can therefore never satisfy another.
8. POST evidence MUST have finished at or after the creation of its PRE gate (minus the configured clock skew); evidence that predates the gate is rejected.
9. Freshness is server policy (`EVALUATION_GATEWAY_EVIDENCE_MAX_AGE_SECONDS`, default 300 s); future timestamps beyond the clock-skew allowance and non-finite timestamps are rejected.
10. Task-global acceptance criteria are independently mandatory at finalization and require exact signed `task_criterion` bindings (phase `POST_EXECUTION`, checkpoint reference = gate of the final step).
11. Manual/self-declared evidence is never authoritative. Legacy manifests (any version other than 4) are rejected.

## Execution gates
12. Every step MUST obtain a `READY_TO_EXECUTE` `PRE_EXECUTION` gate before `POST_EXECUTION`. An outstanding actionable READY gate MUST NOT be superseded by any later PRE. The original gate must be closed by same-gate signed POST (including fresh POST evidence after a failed POST), or by independently signed `NOT_EXECUTED` reconciliation which consumes the old gate without verifying the step and permits a fresh PRE. An UNKNOWN effect remains BLOCKED; no retry or new PRE may authorize the action. A logical no-action gate does not authorize an effect; a failed/not-READY PRE never authorizes execution.
13. PRE and POST MUST use the identical full action fingerprint (including proofs). The action cannot be changed, omitted, or substituted after PRE.
14. A failed POST does NOT consume the gate. Verification is retried with `POST_EXECUTION` against the SAME gate (new fresh evidence, latest `checkpoint_no`); the action MUST NOT be authorized or executed again. Failed POSTs still count towards the remediation threshold.
15. E2 readiness requires exactly one notarized `sandbox_pass`, `rollback_ready`, and `reversible` proof, each with a signed `action_proof` binding to task, step, purpose, action-intent fingerprint, phase `PRE_EXECUTION` and the PRE request checkpoint.
16. E3-E5 and all real-world effects require the separate HITL key. The ordinary API key cannot supply HITL authorization.
17. `FACT_CHECK` is read-only: it never advances a checkpoint, closes a step, authorizes an action or finalizes a task.
18. `POST_EXECUTION` is the only phase that may verify/close a step. The final step MUST explicitly finalize the task and verify all task-global criteria.

## State, audit and integrity
19. Every mutating evaluation uses the exact latest checkpoint number; stale continuation is rejected. Event IDs are idempotent and request-hash bound.
20. Audit history is a SHA-256 hash chain with a gap-free sequence, plus a separate HMAC-SHA256 record authenticator bound to the sequence number.
21. The ledger head is mirrored to an external, HMAC-authenticated **audit anchor** in a different directory/volume. Every mutating request and every integrity check compares the ledger with the anchor; whole-database rollback or tail truncation is rejected (HTTP 503 / 409).
22. Materialized task, step, checkpoint, execution-gate, evidence, lifecycle, remediation, abort and terminal state are reconstructed from authenticated audit history in a single consistent read snapshot.
23. Evidence materialization identity is namespaced by task + step + criterion/purpose + verified evidence fingerprint.
24. Evidence is accepted only from the trusted evidence root with secure ownership/mode/path checks (root, evidence directory and files must not be group/other writable; owner = trusted UID) and bounded `state.json`, `stdout.log`, `evidence.json` sizes.
25. A task that cannot proceed is terminated only by an audited, HITL-authorized `POST /v1/tasks/{task_id}/abort`; an original task with an open remedial MUST abort the remedial first.

## Service surface
26. `GET /health` is unauthenticated and reveals only `PASS`/`FAIL`; its cost is bounded by a single-flight verification cache. Detailed status is available only from the authenticated `GET /v1/audit/verify`.
27. Requests are bounded by actual streamed bytes before parsing. Swagger/ReDoc/OpenAPI are disabled.
28. Fail closed on weak, placeholder or equal secrets, protocol mismatch, database/audit/anchor/state inconsistency, evidence/signature/binding errors, unsafe evidence paths, or trust-boundary errors.
29. Remediation is bounded and linked; historical VERIFIED state is reconstructed from authenticated history and cannot be silently rolled back.

## vNext mandatory execution proof and continuity (beta)
30. EVERY POST containing a concrete E0/E2 action MUST include independent Ed25519 executor receipt bound to task, step, exact PRE gate, immutable full action fingerprint, target, output digest and executor identity. Signed claim evidence alone is INSUFFICIENT.
31. Receipt trust root MUST be distinct from evidence notary trust root, and private signing authority belongs only to the restricted trusted executor; it signs AFTER actual work and independent readback, not retrospectively.
32. PAUSED task has no deadline and no task execution; checkpoint remains durable. RESUME with outstanding PRE transitions RECOVERY_PENDING. New PRE is forbidden until the existing effect is reconciled; duplicate WRITE is forbidden.
33. A sealed execution receipt may remain valid after a lengthy pause, but newly claimed state still requires fresh signed POST criterion evidence. Authorization leases remain bounded independently of task lifetime.
34. Remedial LOCAL_REPAIR and REPLAN MUST preserve immutable original acceptance, use linked tasks and obey all PRE/POST and signed-receipt controls; owner authorization is needed to change baseline or acceptance.
35. This protocol governs registered gateway/worker operations only. Host root, ungoverned shell commands and other external effects require independent isolation, not merely a policy declaration.

## Immutable E2 write payload admission (v3.1.7 extension)

- Every new `write/E2` PRE MUST include `payload_sha256` (lowercase SHA-256)
  and `payload_bytes` (1..524288) of the exact bytes to be written.
- Both fields bind the action fingerprint and the notary-verified
  `action_intent_fingerprint` for sandbox, rollback and reversibility proofs.
- The worker MUST compare bytes and digest BEFORE new journal or filesystem
  effects. Payload mismatch or absent commitment is denied fail-closed.
- An older already-sealed receipt may only be recovered by independently
  validating the original signer, target, output and existing gate.
  No older PRE may be reused to start an uncommitted write.

## Protocol identity and compatibility (stable)

Software version (SemVer) comes from `eg/VERSION`; the protocol human label
is `3.1`, while its authoritative identity is SHA-256 of this exact
UTF-8 file as returned by `GET /v1/protocol`. The Ed25519 evidence manifest
format is version 4. The signed executor receipt envelope has an independent
version number; it does not specify a replacement protocol.

New tasks bind the current hash. Existing tasks remain bound to their original
signed TASK_INTAKE hash and are interpreted under the current stringent
evaluator; legacy contracts are neither re-signed nor assigned a new hash.
Updating this file intentionally creates a new protocol digest for new
registrations, requiring regression and signed E2E validation before release.

The only currently provisionable built-in concrete actions are read E0 and
restricted reversible write E2 in an independently secured output root.
New write PRE binds exact payload SHA-256 and size plus signed sandbox and
rollback proofs. Unsupported cutover remains BLOCKED. Pending UNKNOWN effect
must not be replayed or treated as NOT_EXECUTED without signed independent
reconciliation (implemented under issue #6).


## Explicit step execution classification (new task intake)

Every new plan step must explicitly declare `execution_required` as a boolean.
For `true`, the immutable plan also requires distinct `preconditions`;
PRE must validate readiness, trusted capability and bound action parameters,
while POST must validate postconditions with the original executor-signed
receipt. Supplying `action=null` for that step is rejected without checkpoint
advancement. `false` is an explicit logical classification, not permission
to report a physical side effect as completed. Historical task contracts stay
immutable and keep their intake protocol hash. Do not backfill or rewrite old
TASK_INTAKE events. Unsupported cutovers must use a registered adapter before
PRE can advertise executable readiness.

## Signed high-effect sandbox admission and production boundary (v3.1.37)
36. E3-E5 require a verified, scoped Ed25519 approval from the separate
    `EVALUATION_GATEWAY_HITL_PUBLIC_KEY_B64` authority. The legacy
    `X-Evaluation-HITL-Key` header alone MUST NOT convert high effect to READY.
37. Approval must bind exact task, step, PRE checkpoint, immutable full action,
    adapter identity, nonce, expiry and signed decision. A durable nonce claim
    is not proof that the physical effect occurred.
38. The verified PRE must record its selected high-effect executor identity,
    public signing key, immutable action fingerprint and signed approval nonce
    in the authenticated audit response. POST and NOT_EXECUTED reconciliation
    validate the receipt/proof against that **original** PRE signer, never
    a rotated mutable registry or the global E0/E2 worker key.
39. E3-E5 disposable sandbox adapters and `dispatch_disposable_ci` are
    **repository CI-only**. No production high-effect transport is currently
    provisioned by this portable distribution. A JSON registry, boolean
    `isolated=true` and signed HITL alone MUST NOT advertise online/live
    execution or grant real-world READY. Admission remains fail-closed pending
    independently protected worker transport and attestation.
40. On independently proven NOT_EXECUTED, reconcile the original gate without
    claiming step VERIFIED. Claimed, uncertain or unproven physical effects
    remain UNKNOWN/BLOCKED; no duplicate effect or automatic fresh PRE.
41. E3/E4 compensation requires its own canonical PRE, signed scoped approval,
    exact rollback operation digest/length, durable single-use claim and signed
    POST. E5 compensation remains forbidden.

## Immutable logical/physical admission hardening (v3.1.46)
42. For new PRE requests, an action of **any** concrete effect class E0–E5
    MUST be bound to a registered step whose immutable `execution_required`
    is `true`, with separately signed precondition evidence. A logical
    `execution_required=false` step cannot be relabelled via `evaluate.action`.
43. Historic actionable PRE gates retain their immutable registration and
    original signer; this change MUST NOT retroactively invalidate legitimate
    same-gate POST or rewrite audit records. New PRE requires current policy.

## Issue #26: read-only remote liveness prototype (v3.1.48)
`tools.adapter_liveness.probe_unix` sends a bounded, random-nonce,
gate/action/capability-scoped challenge to a separate Unix-socket process and
verifies a domain-separated Ed25519 response against the configured key.
Wrong key, stale response, different nonce/scope and offline process fail closed.
This attests **current key possession only**, not OS isolation, transport
authorization, physical execution, EG READY or production cutover.
Production E3–E5 dispatch remains unprovisioned until independent worker
admission, auditable effect journal and live promotion are separately proven.

## Issue #26: deployable read-only attester (v3.1.49)
Run `python -m tools.adapter_attestation_worker --socket PRIVATE_SOCKET
--private-key WORKER_PEM --adapter-id trusted-adapter-ID
--capability-sha256 PINNED_SHA256` as the **worker OS identity**.
The containing socket directory must be owned by that UID and mode 0700;
the private Ed25519 PEM must be owned by that UID and mode 0600.
Socket RPC permits only `attest`, with signed task/step/gate/action/capability
challenge. All other operations are denied; no physical actions are exposed.
A successful challenge proves signing-key possession, NOT independent
production executor authorization, effect journaling, or EG VERIFIED.

## Linux peer credential boundary (v3.1.50)
The attest-only worker CLI now requires `--controller-uid`, enforced via
kernel `SO_PEERCRED`. A controller can independently pin `expected_worker_uid`
when calling `probe_unix`; mismatched UIDs fail closed **before sending** a challenge.
The worker's original private 0700 directory and 0600 socket still allow only
same-UID access. Inter-UID access requires a separate audited owner/group ACL
layout and distinct identity smoke tests; do not open directory or key permissions
to make a missing transport work. Neither peer credentials nor signed liveness
grant E3–E5 production execution.
