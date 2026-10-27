# ADR-001 — One generic gateway with a bounded trusted file worker

- **Record status:** Documented existing canonical behavior (not an independently approved new design)
- **Recorded on:** 2026-10-27
- **Source snapshot:** `main@5a56e9b9ddf0d74479590075d166d4293c79366f`, v3.1.141
- **Primary evidence:** [GENERIC_EXECUTION_MODEL.md](../../../../eg/docs/GENERIC_EXECUTION_MODEL.md), [EXECUTOR_PROTOCOL.md](../../../../eg/docs/EXECUTOR_PROTOCOL.md), [SKILL.md](../../../../SKILL.md), [main.py](../../../../eg/app/main.py), [trusted_execution_worker.py](../../../../eg/tools/trusted_execution_worker.py)

## Context

EG coordinates a generic task/evidence verification lifecycle for agents working across projects. Historical adapter and effect-class metadata exist, but may be present only for backward-compatible audit validation. The current canonical runtime must not require a new project-specific executor simply to install or register a new task.

## Decision as implemented

1. Use one authoritative gateway, evaluator, task registry and audit chain for the canonical environment. An agent may orchestrate the workflow itself, but cannot sign as its own independent worker or notary.
2. Admit only bounded `read`, exclusive `write` (create), and SHA-256-expected `replace` through the separately trusted worker in its private `output_root`. Default eligible suffixes are `.txt` and validated `.json`; operator opt-in adds suffix eligibility, **not** arbitrary process or host authority.
3. For physical work, require register-before-work, fresh original READY PRE, exact authorized action executed **once**, independently signed receipt, independently verifiable POST evidence and canonical VERIFIED before advancement. Apply the same sequence in staging.
4. Treat unavailable actions and missing trusted keys/worker/signatures as fail-closed. Shell, service control, Git push and deployment side effects are **not** included in the canonical worker.
5. Keep historical task protocol identity and signed evidence immutable; validate using the canonical evaluator, without re-enabling retired executors.

## Alternatives and history

The current documentation explicitly excludes **per-project executor creation**, retrospective evidence, arbitrary shell fallback and treating historical metadata as active capability. A contemporaneous design review or formal alternatives-vote record was **not** found in the examined active source; do not claim this ADR records who approved an original design decision.

## Consequences

- **Benefits:** reusable installation and workflow, fewer project-specific execution paths, auditable separate cryptographic authorities, non-replay guarantees.
- **Constraints:** generic does **not** mean unlimited physical operations. Unsupported steps remain unavailable until governed capabilities exist; a healthy API or passing release CI does not establish execution authority.
- **Operational requirement:** external durable state, independent trust roots, worker sandbox, live admission diagnostics, receipt journal and recovery evidence must be verified for each installation.
- **Documentation requirement:** any new context, sample, workflow or test must describe capabilities as they are actually admitted and preserve the original PRE/POST lifecycle.

## Revisit triggers

Revisit only when a canonical change actually expands runtime capability, trust boundaries, signed evidence schema, or packaging. Such a change requires evidence, specific owner authorization, updated source and normative docs, regression/E2E, license review where relevant, and a new immutable release.

**Non-normative:** This ADR summarizes the observed current design; use the [executor protocol](../../../../eg/docs/EXECUTOR_PROTOCOL.md) and live authenticated gateway for exact authority.
