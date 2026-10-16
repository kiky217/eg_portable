# Evaluation Gateway — one system

EG has one canonical implementation: `app/main.py`, one schema-backed task
registry, one authenticated audit chain, and one protocol: `docs/EXECUTOR_PROTOCOL.md`.
The `tools/trusted_execution_worker.py` is a capability adapter bound to EG
PRE gates, **not** another task manager or verification implementation.

## Supported environments

Portable offline target is Linux x86-64 compatible with bundled CPython 3.12
and its shared libraries. Other OS/architectures fail closed until a platform
adapter has been independently tested. No Colab-specific path is required.

## Lifecycle

REGISTER → sequential PRE → EG-authorized trusted executor → signed execution
receipt → independently verified POST → VERIFIED_PASS → next step. Completion
requires every required step and the task-global acceptance; the returned
SATISFIED status must be read back with authenticated full-chain audit PASS.

Pause can persist indefinitely; new execution authorizations expire separately.
Resume after uncertain mutations enters RECOVERY_PENDING, preventing duplicate
WRITE. Remediation and REPLAN are governed by the same task registry, and
linked remedial tasks are governed records, not alternative EG instances.

## Historical Colab cutover evidence (NOT current runtime state)

The following is a dated historical event, not an onboarding instruction or
fresh service health check. The Colab upgrade from EG 3.0.1 to 3.1 was completed on
2026-10-15 at 23:48 UTC. Its operational acceptance is PASS and must not
be kept open solely because future-action executor admission is disabled.
The registered task's historical 12/16 VERIFIED status is preserved
separately without rewriting its immutable acceptance.

See `docs/ACCEPTANCE_POST_CUTOVER_20261016.md` and
`docs/acceptance-post-cutover-20261016.json`.

## Production admission

Never grant the worker signing key to the agent. An EG instance configured
with a trusted-worker public key that is not backed by an actually isolated
executor must refuse all actionable effects. Same-host UID separation does
not constrain a Colab host-root agent. For E0 reads and restricted reversible
E2 file creates, the worker binds receipts to the EG gate and action. The
bounded worker supports `.txt` and valid `.json` output inside its protected
`output_root`, never an arbitrary host-owned path. Other operations are
currently unsupported and must fail closed.

Initialize only as nonroot, with an external EG_STATE_DIR on a trusted durable
volume and externally protected signing roots. The offline bundle ships neither
secrets nor initialized task databases. Do not interpret an arbitrary mounted
path as a proven persistent database/anchor.

## Build and test

Run tests from this directory with the selected Python 3.12 environment:

```sh
python -m pytest -q tests
PYTHONPATH=. python tools/run_trusted_e2e.py
PYTHONPATH=. python tools/run_remedial_e2e.py
python tests/live_e2e.py
python tools/build_portable_bundle.py
python tools/test_offline_portable.py
```

The E2E scripts use isolated test-only EG process instances. They never own
a second production task lifecycle. Full repo deployment is governed by a
canonical EG task; Git source history is not an alternate runtime.
