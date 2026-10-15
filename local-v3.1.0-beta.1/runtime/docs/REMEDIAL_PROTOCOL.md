# Hardened Remedial Protocol 3.0

After three independently recorded failed attempts (failed PRE or failed POST verifications) on the same NORMAL current step, ordinary continuation is rejected and a linked REMEDIAL task is required. Nested remedial tasks are forbidden. The original task is frozen while a remedial is open. Core hierarchy and titles are mandatory. A remedial step is bounded to three failed attempts; after that it must truthfully prove `EXHAUSTED`.

Final `RECOVERED` requires `LOCAL_REPAIR`, `ROLLBACK`, `COMPENSATION`, or `REPLAN`; `UNRESOLVED` requires `EXHAUSTED`. The remedial task's global acceptance criteria are mandatory and evidence-bound before terminalization. A recovered original task resumes from its preserved origin checkpoint; an unresolved result terminates the original task.

All remedial steps use the same 3.0 controls as ordinary tasks: manifest-v4 evidence bound to phase and checkpoint with signed matchers, mandatory PRE→POST action binding with same-gate POST retry, action-bound E2 proofs, separate HITL authorization for E3-E5/real-world effects, exact checkpoint fencing, authenticated and externally anchored audit records, and full materialized-state reconstruction.

## Escape hatch: audited abort
A remedial that cannot be proven (for example because no trusted evidence can ever be produced) no longer blocks the original task forever:

- `POST /v1/tasks/{remedial_task_id}/abort` (API key + HITL key, `reason` required) terminates that remedial with `contract_status=ABORTED`. The original task is then no longer blocked by it; if the failure threshold is still met, a new remedial attempt (`remedial_attempt` = previous + 1) may be registered.
- `POST /v1/tasks/{task_id}/abort` on an original task is rejected with `ABORT_REMEDIAL_FIRST` while a linked remedial is OPEN.
- Aborts are recorded as authenticated `TASK_ABORT` audit events and reconstructed by the state verifier; an aborted task is terminal.

`GET /v1/tasks/{task_id}/state` reports `next_action` (`EXECUTE_OR_EVALUATE`, `REGISTER_REMEDIAL`, `COMPLETE_REMEDIAL`, `SUBMIT_EXHAUSTED_DISPOSITION`, `STOP`), `blocked_reason` and `remedial_task_id` so a recovering agent never has to guess.
