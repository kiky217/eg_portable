# Portable EG — Mandatory Governance Contract v1

Canonical workspace: `/content/workspace`.
Policy implementation: `/content/workspace/bin/eg-task.py`.
EG service: `http://127.0.0.1:18765` (loopback only).

## Non-negotiable programmatic rules
1. All tasks **managed by this portable executor** MUST enter through `eg-task.py JOB`.
2. A task is executable only if it has a registered immutable EG contract and EG issues `READY_TO_EXECUTE` for the relevant signed PRE_EXECUTION gate.
3. Each required step must have notarized evidence and both PRE/POST gate checkpoints, and each step must be independently marked VERIFIED_PASS by EG.
4. Final success requires EG task status SATISFIED, terminal STOP, a VERIFIED_PASS final checkpoint, and authenticated audit chain/anchor status PASS.
5. Tasks not in the code-owned allowlist are refused before execution; unknown/unsupported effects and E3–E5 have no execution route.
6. E2 effects additionally need signed sandbox, rollback-ready and reversible action proofs, durable pre-effect journal, and readback. UNKNOWN effects must be reconciled by original task and checkpoint; never automatically rerun WRITE.
7. Failure of any check is fail-closed with exit code 77; a successful child process is NOT sufficient for EG verification.
8. An EG receipt cannot be reused to validate a different job: the registered task instruction and agent, required steps and checkpoint history are checked against the named operation.
9. There is no environment override that disables these requirements.

Supported portable jobs: `hostname`, `uptime`, `workspace-list`, `e2-smoke`.
Authorized E0/E2 job routing is hardcoded in source; adding a new job requires a reviewed code change and tests.

Command:

```bash
/content/workspace/eg/.venv/bin/python /content/workspace/bin/eg-task.py hostname
/content/workspace/eg/.venv/bin/python /content/workspace/eg/test_portable_eg_policy.py
```

## Scope and honest security boundary
This is a portable, **application-level contract**, not an OS kernel restriction.
Shell sessions, raw Desktop Commander operations, notebook code and unrelated processes do not automatically pass through it. Every agent, client and automation that requires EG governance must explicitly call the canonical executor. Full enforcement against bypass would additionally require a restricted OS principal/container, filesystem permissions, and denied direct execution channels.

Do not report a generic, unmanaged process as VERIFIED. Do not claim unrestricted arbitrary task execution is currently governed: only explicitly registered supported jobs are.
