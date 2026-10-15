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
