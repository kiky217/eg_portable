---
name: evaluation-gateway-agent
description: Safely operate real EG tasks, diagnose admission and missing executor capabilities, and reconcile PRE/POST without duplicate effects.
---
# Evaluation Gateway — Agent Operating Skill

Apply to **every** task governed by Evaluation Gateway. Read this file before attempting actions, takeover, retries or declaring completion. This skill documents behavior; it never grants permissions or enables an executor.

## Discover current canonical state
1. Obtain the exact target EG URL, deployment identity, task ID, runtime version, source revision and current credentials from authorized environment. Do not assume historical Colab paths, GitHub release state, or an unrelated EG instance represent the live system.
2. Use authenticated read-only API discovery and query health, audit validity, task detail, current step, current checkpoint, pending gate, lease and worker availability. Consult the **live endpoint's actual protocol** for request names; do not invent endpoint paths.
3. Record whether service is live, admission is enabled, independently protected signing root is provisioned, required adapter exists, and action is presently PRE-authorized. Those are **separate** facts. A running production service does not imply unrestricted execution.

## Select capability before claiming a step
- Distinguish logical evaluation from an actual physical effect; never relabel the immutable task contract.
- Current built-in production worker only handles narrow E0 reads and E2 **creation** of .txt/valid .json within protected output_root (<= 512 KiB).
- Editing Rust/source files, running cargo/tests or arbitrary shell commands, controlling services, Git commit/push and E3–E5 effects are NOT implemented by that production dispatcher. CI-only sandbox adapters are not deployable production capabilities.
- Before claiming, match exact desired action, effect class, target, adapter identity and testable result to a live, independently trusted adapter. If missing, report `CAPABILITY_UNAVAILABLE` and specify required adapter contract. Do not use direct shell, CI fixture, a dummy key, fabricated receipt, or HITL as a substitute.

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

## Reporting
State exactly: target instance, software/version, timestamp, task/step/checkpoint, source state, admission, claimed capability, worker state, execution state, canonical verdict, unresolved blocker. Separate `SOURCE PASS`, `BUILD PASS`, `RUNTIME PASS`, `CANONICAL VERIFIED`. Cite actual logs/receipts/checkpoints; never infer them.

References: [agent onboarding](eg/docs/AGENT_QUICKSTART.md), [operations](eg/docs/OPERATIONS.md), [executor protocol](eg/docs/EXECUTOR_PROTOCOL.md).