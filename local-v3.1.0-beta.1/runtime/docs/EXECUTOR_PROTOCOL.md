# Evaluation Gateway Hardened Executor Protocol 3.1-beta

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
12. Every step MUST obtain a `READY_TO_EXECUTE` `PRE_EXECUTION` gate before `POST_EXECUTION`. A later PRE supersedes earlier gates; a failed later PRE blocks POST until a new READY PRE exists.
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
30. EVERY mutating POST MUST include independent Ed25519 executor receipt bound to task, step, exact PRE gate, immutable full action fingerprint, target, output digest and executor identity. Signed claim evidence alone is INSUFFICIENT.
31. Receipt trust root MUST be distinct from evidence notary trust root, and private signing authority belongs only to the restricted trusted executor; it signs AFTER actual work and independent readback, not retrospectively.
32. PAUSED task has no deadline and no task execution; checkpoint remains durable. RESUME with outstanding PRE transitions RECOVERY_PENDING. New PRE is forbidden until the existing effect is reconciled; duplicate WRITE is forbidden.
33. A sealed execution receipt may remain valid after a lengthy pause, but newly claimed state still requires fresh signed POST criterion evidence. Authorization leases remain bounded independently of task lifetime.
34. Remedial LOCAL_REPAIR and REPLAN MUST preserve immutable original acceptance, use linked tasks and obey all PRE/POST and signed-receipt controls; owner authorization is needed to change baseline or acceptance.
35. This protocol governs registered gateway/worker operations only. Host root, ungoverned shell commands and other external effects require independent isolation, not merely a policy declaration.
