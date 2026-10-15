# EG 3.1.0-beta.1 — Staging only

This branch preserves the canonical **EG 3.0.1** release unchanged and carries
an **experimental vNext runtime** under `local-v3.1.0-beta.1/runtime/`.

## Colab-stage verification (2026-10-15)

- 118/118 Python unit + regression tests PASS, including a new hardcoded 300-second execution-lease boundary test.
- 25/25 real-process end-to-end checks: PASS.
- Independent worker E2 tests: 10 pre-existing effects rejected; forged/missing executor receipt HTTP 409; 10 proper PRE→worker→POST steps VERIFIED / checkpoint 20 / audit PASS.
- Pause after WRITE before POST: PAUSED → RECOVERY_PENDING → sealed receipt reconciliation → same effect, no repeated WRITE, audit PASS.
- Bounded self-repair and adaptive REPLAN: two controlled cases, exactly 3 failed attempts then 10-step linked remedial task, original task SATISFIED, audit PASS.

## Security controls added

- Detached Ed25519 execution receipts verified server-side for mutating POST.
- Execution trust root separate from claim-evidence notary.
- Non-root trusted writer with exclusive no-symlink writes, bound gate/checkpoint/intent, readback and durable journal.
- Indefinite PAUSED and auditable RESUME / RECOVERY_PENDING; no new PRE until outstanding effect reconciliation.
- Existing mandatory linked remedial, bounded retry, immutable acceptance preserved.

## NOT ready for production

1. Colab root can bypass same-host UID isolation; executor signing must be moved to an independently protected security domain to resist host-root compromise.
2. Trusted writer is currently limited to reversible E2 file creation. Other mutation capabilities lack equivalent signed backends.
3. Persisting task state through Colab runtime destruction needs durable external secure storage and protected independent audit-anchor restoration.
4. Full autonomous diagnosis of arbitrary unforeseen design errors has not been proven; current scenarios are controlled.
5. This release is not a self-contained cross-platform, one-click portable installer.
6. Canonical Colab EG on port 18765 has **not been upgraded**.

**Do not merge to main or tag as stable until all mandatory owner acceptance
criteria are independently VERIFIED.**

See `local-v3.1.0-beta.1/runtime/docs/VNEXT_STAGING.md`.

## Canonical Evaluation Gateway task status

- Task: `task-eg-portable-self-audit-remediation-20261015-v1`
- 22/24 required EG steps independently re-evaluated through their own PRE/POST checkpoints (checkpoint 44), authenticated audit `PASS`.
- Phase 12 remains intentionally `NOT VERIFIED` because stable portable deployment, stronger isolation from Colab host root, and full release acceptance remain outstanding.
- All source changes in this branch are **beta only**, not promoted to canonical EG 3.0.1 or GitHub `main`.
- Additional fault injection: durable intent recovery after a simulated crash-after-WRITE-before-receipt is successful without repeated write.
