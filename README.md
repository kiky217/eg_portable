# Evaluation Gateway (EG)

**Verify every step as work happens — not after a project is finished.**

Evaluation Gateway is an open-source system for supervising agent-driven work. It keeps a task plan, checks that each step is ready **before** an action starts, and verifies the result **after** the action finishes. The next step cannot be marked verified until its evidence passes.

**The same rules apply to development, testing, staging, recovery, and production work.** Staging is not an exemption from verification.

## Why use it?

An AI agent might complete a long series of changes and only then report that everything went well. That makes missed requirements, weak evidence, and difficult cutovers harder to diagnose.

EG changes that workflow:

1. **Plan the work.** Register the task, its steps, and what success means.
2. **Check readiness (PRE).** Validate prerequisites, safety conditions, and the intended action before execution.
3. **Execute through an admitted worker.** Supported actions run under a separate trusted executor that records a signed receipt.
4. **Check the result (POST).** Independently verify the outcome against the original acceptance criteria.
5. **Continue only after verification.** If verification fails, keep the step open and reconcile or repair it without pretending it passed.

```text
REGISTER → PRE verified → authorized execution → signed receipt
         → POST verified → NEXT STEP → task acceptance
```

A step is not complete merely because a command exited successfully, the agent says “done,” or a staging deployment appears healthy.

## What it can do

- Manage immutable task plans and hierarchical steps.
- Verify PRE conditions, POST acceptance criteria, and invariants that must hold throughout.
- Bind evidence to the specific task, step, phase, and checkpoint.
- Authorize supported actions and verify separately signed executor receipts.
- Track checkpoints, pauses, resumes, recovery, and linked remediation.
- Detect duplicate events and protect the audit history with authenticated integrity checks.
- Reconcile interrupted work without blindly repeating an action.
- Check independently signed cutover evidence and rehearse restoring a rollback archive in isolation.

## What it does **not** do yet

EG is **not** a general-purpose remote shell or a universal controller of everything an agent can do.

The built-in trusted worker currently supports **bounded E0 reads** and **reversible E2 file creation** in a protected output directory (`.txt` or valid `.json`). E3–E5 have isolated disposable sandbox adapters for **repository-only CI testing**, including independently signed HITL, PRE/POST verification, crash recovery, and E3/E4 compensation. These are **not production executors**; the production dispatcher remains limited to E0/E2 until an independently provisioned and isolated high-effect transport is validated. Real service cutovers remain BLOCKED; HITL alone cannot make an unsupported operation executable. Other actions are blocked until a properly isolated and tested adapter is available.

EG also cannot prevent commands issued entirely outside its trusted execution boundary. A public repository or passing CI run is **not** evidence that a separate production installation has performed a verified cutover.

See [architecture and security boundaries](eg/docs/UNIFIED_ARCHITECTURE.md) and [production readiness](eg/docs/PRODUCTION_PROMOTION.md).

## Agent onboarding and local readiness

Agents should start with [SKILL.md](SKILL.md), then the [operational quickstart](eg/docs/AGENT_QUICKSTART.md). Before claiming any physical step, run the read-only [agent readiness preflight](eg/tools/agent_readiness.py) and separately verify the live instance's authenticated state and executor. This prevents treating a production release, healthy API, or a configured public key as proof of authorized real-world execution. The preflight does not enable admission or create unsupported adapters.

## Getting started

The source lives in [`eg/`](eg/). For installation, dependencies, credentials, and safe deployment, follow the [portable runbook](eg/docs/PORTABLE_RUNBOOK.md).

- **Supported offline target:** Linux x86-64 with CPython 3.12-compatible glibc.
- **Distribution:** portable archives are built and checked by GitHub Actions; see [Releases](https://github.com/kiky217/eg_portable/releases).
- **State and signing keys:** provided separately on protected, durable storage; no production credentials ship with the archive.
- **Testing:** see [testing and developer instructions](eg/README.md#build-and-test).

## Documentation

| Document | What you'll find |
| --- | --- |
| [How to run EG](eg/docs/PORTABLE_RUNBOOK.md) | Setup, daily operation, staging, recovery, and cutover rules |
| [Executor protocol](eg/docs/EXECUTOR_PROTOCOL.md) | Formal PRE/POST contract, evidence, checkpoints, and receipts |
| [Architecture](eg/docs/UNIFIED_ARCHITECTURE.md) | Components and trust boundaries |
| [Production promotion](eg/docs/PRODUCTION_PROMOTION.md) | Release checks versus real deployment readiness |
| [Open issues](https://github.com/kiky217/eg_portable/issues) | Bugs, enhancements, and current work |

**Contributions:** You can propose a change through a GitHub Issue and submit implementation through a Pull Request. Changes should retain step-by-step verification and pass the repository's tests.
