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

## Live capability discovery (current runtime)
Call authenticated `GET /v1/agent/capabilities` on the **actual** EG instance before planning physical actions. It distinguishes installed bundled transport from untrusted capability declarations. `CONFIGURED_NEEDS_LIVE_PRE` is not worker attestation; `UNVERIFIED_NOT_AUTHORIZED` must never be dispatched. `EVALUATION_GATEWAY_AGENT_CATALOG_JSON` is a bounded optional JSON catalog (schema_version 1, capabilities with id/effect_class/action_type/adapter_id). It is diagnostic-only and does not affect immutable task contract or PRE admission. If missing or invalid, use the bundled worker or independently provision an approved adapter, not a shell bypass.

## Select capability before claiming a step
- Distinguish logical evaluation from an actual physical effect; never relabel the immutable task contract.
- Current built-in production worker only handles narrow E0 reads and E2 **creation** of .txt/valid .json within protected output_root (<= 512 KiB).
- Editing Rust/source files, running cargo/tests or arbitrary shell commands, controlling services, Git commit/push and E3–E5 effects are NOT implemented by that production dispatcher. CI-only sandbox adapters are not deployable production capabilities.
- Before claiming, match exact desired action, effect class, target, adapter identity and testable result to a live, independently trusted adapter. If missing, report `CAPABILITY_UNAVAILABLE` and specify required adapter contract. Do not use direct shell, CI fixture, a dummy key, fabricated receipt, or HITL as a substitute.

## Portable capability model
EG must not hardcode Rust, Git, Docker or any programming toolchain as universal requirements. Discover **registered runtime capabilities** from the target deployment. Match typed action, effect class, scope, constraints, attested executor identity and evidence/receipt contract. Prefer an already-authorized native tool or adapter; agents may propose or install a new adapter only through the operator-approved onboarding and trust process. A self-declared capability is never automatically admitted. The bundled E0/E2 worker is a baseline, **not an upper bound of EG's extensible architecture**. The local readiness script reports only bundled-worker compatibility, not what an external deployment may provide.

## Governed source-file creation (operator opt-in)
The built-in independently signed E2 worker **can** create source files through exact PRE/POST when configured by the operator. EG allows suffixes from `EVALUATION_GATEWAY_EXECUTOR_ALLOWED_SUFFIXES` (comma-separated, default `.txt,.json`), and the separate worker must have the corresponding private-config `allowed_suffixes` list. Example: `.txt,.json,.py,.rs,.toml`. Both remain restricted to single-level private worker `output_root`, a signed payload commitment and exclusive creation with no overwrite. Neither setting grants command execution, dynamic privilege, Git push, nor E3–E5 support. For a language-independent workflow use the project-selected extension only if the operator's live policy permits it; do not change deployment admission mode to force a match.

## Independently provisioned high-effect transport (E3–E5)
A deployment may register a typed external adapter without hardcoding its toolchain in EG. An operator must separately provision the worker under an independent OS identity and signing domain, pin its UID/socket/signing public root, and configure a scoped capability and separate HITL signer. EG's `EVALUATION_GATEWAY_EXTERNAL_ADAPTER_MODE=enabled` is **not** a bypass: it refuses startup without the independent trust configuration, and each PRE challenges the same worker's live signed identity. The agent must use the unified `dispatch_action` interface with explicit `external_worker_socket`, `external_worker_uid`, `external_adapter_id`, `external_public_key_b64`, and signed `hitl_approval`. The dispatcher validates the original EG PRE, signer pin, peer UID, lease, payload binding, and receipt; afterward the agent submits the exact receipt and independent outcome evidence to EG POST. A CI worker, an unverified catalog entry, or a healthy service is never enough.

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