# Evidence, notary, audit and recovery

**Canonical source:** [main.py](../../../eg/app/main.py), [execution_receipts.py](../../../eg/app/execution_receipts.py), [no_effect_receipts.py](../../../eg/app/no_effect_receipts.py), [remedial protocol](../../../eg/docs/REMEDIAL_PROTOCOL.md). See [system design](../architecture/system-design.md).

## Purpose and trust boundary

The evaluator requires evidence signed independently of the agent requesting a task decision. It ties each claim to task, criterion, step, phase, checkpoint and authenticated provenance; physical POST also requires the **original** worker-signed execution receipt.

Evidence producer labels alone never grant verification authority. Notary and worker signing identities serve distinct purposes from task-gate/admission authority. Historical signed evidence must not be rewritten to fit a newer protocol.

## Canonical persistent records

`eg/app/main.py` defines SQLite `audit`, `task_registry`, `task_registry_steps`, `task_registry_checkpoints`, `evidence_records` and `execution_gates` tables. The audit links records by prior hash and authenticates each record with an HMAC; the separately stored anchor detects divergence/rollback and materialized state is checked against immutable event history.

- `init_db` creates the schema and uses WAL/FULL synchronous writes; filesystem path, DB ownership and backup remain **deployment-specific**.
- `verify_audit_chain` checks ordered hashes/MACs.
- `verify_materialized_state` reconstructs consistency of state from the authenticated history.
- `GET /v1/audit/verify` reports the authenticated integrity result; `GET /health` alone is insufficient to declare task acceptance.

## Precondition/acceptance evidence flow

1. Register immutable criteria and plan first.
2. PRE validates separately signed prerequisite claims, current step and exact action scope.
3. The independently trusted worker records the effect and seals a signed receipt.
4. POST checks fresh phase-appropriate evidence and original receipt. Only canonical `VERIFIED_PASS` can advance the step; separately notarized task-wide criteria determine `SATISFIED`.
5. Audit verification and readback confirm the canonical persisted result, not just a successful client request.

## Failure, pause and reconciliation

- Delivery timeout is **UNKNOWN**, not proof of failure. Reread original task, checkpoint, gate, journal, target and receipt; do not blindly retry a write.
- Original sealed receipt + matching target supports evidence recovery without new execution.
- Independently worker-signed `NOT_EXECUTED` supports the audited original gate reconciliation if genuinely no effect occurred. Uncertain effects remain blocked.
- Repeated failed verification may require linked remedial task with original criteria, not a fresh task to bypass the old gate. See [REMEDIAL_PROTOCOL.md](../../../eg/docs/REMEDIAL_PROTOCOL.md).

## Safety and test references

Do not place signing keys, DB records, private evidence or external audit anchors in source or context docs. Live production backup/recovery requires approved consistent snapshots and restore rehearsal; CI is insufficient.

- [test_notary_domain_e2e.py](../../../eg/tests/test_notary_domain_e2e.py)
- [test_admission_integrity_and_resume.py](../../../eg/tests/test_admission_integrity_and_resume.py)
- [test_recovery_crash_matrix.py](../../../eg/tests/test_recovery_crash_matrix.py)
- [test_restore_rehearsal_isolated.py](../../../eg/tests/test_restore_rehearsal_isolated.py)
