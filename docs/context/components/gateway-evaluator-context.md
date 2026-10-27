# Gateway, task registry and evaluator

**Component:** canonical FastAPI service in [eg/app/main.py](../../../eg/app/main.py); [system design](../architecture/system-design.md). This describes baseline v3.1.141; verify later changes.

## Purpose and responsibilities

Owns one authoritative task plan and status, ordered hierarchical steps, original PRE and POST checkpoints, evidence validation, failure/remedial lifecycle, authenticated audit, and task-wide final acceptance. Strict Pydantic request models reject extra input rather than silently accepting potentially security-relevant fields.

## Key interfaces and files

- [main.py](../../../eg/app/main.py): `RegisterRequest`, `EvalRequest`, `PlanStep`, `Action`, `Claim`, evaluator `register`/`evaluate`, `task_state`, `audit_verify`; decorators register API handlers and are **not** dead code even when not statically called.
- [executor_policy.py](../../../eg/app/executor_policy.py): bounded target suffix parsing shared between evaluator/worker.
- [single_agent_workflow.py](../../../eg/tools/single_agent_workflow.py): optional caller-side sequence; **not** a second evaluator.
- [EXECUTOR_PROTOCOL.md](../../../eg/docs/EXECUTOR_PROTOCOL.md): normative phase/request/evidence contract.

| Endpoint | Intended meaning |
| --- | --- |
| `GET /health` | Integrity-gated minimal health, **not** effect authorization |
| `GET /v1/protocol` | Hash-bound active protocol, runtime source fingerprint and admission diagnostics |
| `GET /v1/agent/capabilities`, `/v1/agent/capability-match` | Read-only capability/scope diagnostics; no PRE grant |
| `POST /v1/tasks/register` | Immutable plan and criteria recorded before work |
| `POST /v1/evaluate` | PRE/POST/FACT_CHECK with original signed criteria and checkpoint |
| `GET /v1/tasks/{task_id}`, `/state` | Reconcile actual current step, gate, status and checkpoint |
| `POST /v1/tasks/{task_id}/pause`, `/resume`, `/reconcile`, `/abort` | Controlled lifecycle and no-effect handling |
| `GET /v1/audit/verify` | Authenticated audit, anchor and materialized-state integrity |

All routes except `/health` require the protected API key. For actual body schemas consult code and [SKILL](../../../SKILL.md).

## Data and security boundaries

SQLite stores `task_registry`, `task_registry_steps`, `task_registry_checkpoints`, `evidence_records`, `execution_gates` and append-only audit records. The service uses WAL, FULL synchronous writes, an external anchor and audit-chain revalidation; never edit the DB directly to mark work complete.

`EVALUATION_GATEWAY_ADMISSION_MODE` defaults to `enabled` in source, but enabled configuration is **not** a provisioned trusted worker and is **not** an active PRE. The evaluator can deny an action while `/health` remains PASS.

## Common integration mistakes

Do not infer step VERIFIED from HTTP 200 or a receipt alone. Do not register new work after an effect occurred. Do not turn a physical mutation into a logical check because a capability is unavailable. Do not rehash historical protocol identity. An unknown result stays UNKNOWN until reconciled.

## Verification evidence

Regressions: [test_single_agent_workflow.py](../../../eg/tests/test_single_agent_workflow.py), [test_admission_integrity_and_resume.py](../../../eg/tests/test_admission_integrity_and_resume.py), [test_protocol_docs_consistency.py](../../../eg/tests/test_protocol_docs_consistency.py); isolated [live_e2e.py](../../../eg/tests/live_e2e.py). CI checks source behavior, not any external production task.
