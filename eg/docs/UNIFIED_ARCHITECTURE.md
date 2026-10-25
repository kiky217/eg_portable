# Unified EG architecture — one core and task lifecycle

The EG canonical codebase is **eg/app/main.py**. The only source of truth
for tasks, steps, checkpoints, pause/recovery and audit is its SQLite ledger,
external append-only authenticated anchor and signed evidence records.

Adapters: `eg/tools/trusted_execution_worker.py` is a capability-specific
trusted executor, never a second task manager. It verifies EG-issued current
gate and action fingerprint and returns a signed runtime receipt. It MUST NOT
register tasks or independently declare steps VERIFIED.

EG server owns immutable registration; per-step PRE; action admission; POST
verification; verdict, checkpoint and task terminalization. No alternative
portable policy manager or task store is retained in the repository.

Authorized job lifecycle:
REGISTER → PRE → trusted executor → signed receipt → POST →
VERIFIED_PASS → next step. UNKNOWN effect: reconcile before any retry.

The only supported offline bundle currently targets Linux x86-64. Unsupported
platform or missing independent executor trust root must fail closed.
The platform root can bypass local uid separation; production isolation
requires an independently administered signing and enforcement domain.

Legacy task histories remain in the canonical EG database. Never reset or
retroactively rewrite task records on deployment. Migration must verify
pre/post anchor continuity and previously satisfied task IDs.

## Scope of physical enforcement

The EG API cannot intercept arbitrary privileged shell commands. Its verified
action types are only those implemented by the restricted signed executor.
If the agent controls host root or the executor private signing key, EG must
not claim independent work proof, irrespective of its audit PASS. Task
progress is blocked on unsupported effects. Production deployment requires
an independent executor security domain; a local Colab host-root agent
therefore cannot satisfy universal enforcement without a privilege-boundary
change outside this repository.

## Capability contract and security domains (v3.1.37)
- The canonical evaluator in `app/main.py` owns one PRE/POST ledger.
- E0/E2 is implemented by a separate restricted Unix-socket worker. Its
  `EXECUTOR_PUBLIC_KEY_B64` is the trusted receipt key.
- E3/E4/E5 capability registry uses typed `AdapterCapability` records.
  The repository adapter and `dispatch_disposable_ci` are **CI-only**.
  Neither a manifest entry nor a claimed `isolated` boolean demonstrates a
  live independently secured executor.
- Authenticated PRE audit records pin high-effect adapter identity, signing
  root, action fingerprint and signed approval nonce for POST/reconciliation.
- `GET /v1/protocol` distinguishes executable E0/E2 capabilities from
  configured high-effect diagnostics; signed worker identity and exact PRE
  remain separate prerequisites.
- Production E3–E5 dispatch requires an explicitly provisioned and separately protected RPC transport,
  worker attestation/liveness and independently verified trust model exist.
- Historical accepted task contracts and their hashes remain immutable;
  signed task audit and NO_EFFECT recovery must never be rewritten.

## Unified agent action interface (v3.1.43)
`tools.governed_agent_dispatcher.dispatch_action` is the fail-closed
single action-routing contract. E0/E2 route via the privileged worker socket;
E3/E4/E5 can use independently operated external RPC workers after explicit
operator signing and activation. The core never performs the physical effect;
disposable E3/E4/E5 adapters remain **CI-only** and are not production workers.

The versioned `AdapterCapability` schema explicitly marks repository high-effect
entries `ci_only=True` and rejects unsupported schema versions. A production high-effect descriptor requires an actual independently
provisioned transport, kernel UID isolation, scoped signed HITL, live
attestation, immutable PRE, signed receipt and canonical POST.

## Reusable generic E3–E5 typed execution catalog

One operator-provisioned `TrustedProcessCatalog` allows up to 32 exact action targets under a single signed class-bound E3/E4/E5 adapter, worker UID, socket, signing key and durable nonce journal. The canonical gateway and dispatcher remain provider-neutral: targets select only operator-pinned executables and arguments, never commands from agent-supplied stdin. A new project or language does not require a bespoke Python executor. Where OS permissions or an exact operation are genuinely unavailable, add an approved profile through the independent operator, not a hardcoded project adapter. Read [Generic execution model](GENERIC_EXECUTION_MODEL.md).
