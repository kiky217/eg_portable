# Generic execution model

Evaluation Gateway (EG) is a portable, provider-neutral controller for tasks. It is not a project-specific executor or a root shell.

## Canonical installation

Install one gateway, one durable task and audit state, and the bundled trusted file worker. The active physical operations are **bounded reads, exclusive file creation and SHA-256-bound replacement** within the configured worker directory. No external process catalog or separate per-project worker is installed. An optional reusable [bounded process worker](GENERIC_PROCESS_WORKER.md) can be provisioned using operator-signed fixed profiles; it is not automatically enabled.

See [the operational SKILL](../../SKILL.md) and [the portable runbook](PORTABLE_RUNBOOK.md).

## Required sequence — including staging

1. **REGISTER:** Save the task, step order, preconditions and independent acceptance criteria before starting work.
2. **PRE:** Verify the current step and authorize the exact supported action.
3. **EXECUTE:** Dispatch the action once through the admitted worker; preserve its signed receipt and recover the original result if interrupted.
4. **POST:** Submit fresh evidence created after PRE, plus the exact receipt where an action occurred. EG independently verifies the result.
5. **ADVANCE:** Move to the next step only after VERIFIED. Mark the task SATISFIED only after all required steps and task-wide criteria pass.

A health check, successful command, test pass or completed external project does **not** retroactively verify a task. Staging is subject to the same PRE/POST gates.

## Historical compatibility

Older task records may contain effect-class and executor metadata that are retained for audit verification. Those historical names are not installation requirements or currently available worker capabilities. Do not deploy retired operator bootstrap, typed process adapters or signers merely because they appear in an old record or protocol reference.

**Boundary:** EG can block invalid task claims and withhold verification, but cannot physically stop actions performed with tools outside its controlled boundary. Integrations must route their physical work through the admitted path to be governed.
