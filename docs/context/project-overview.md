# Evaluation Gateway (EG) — AI Context Overview

> **Role:** Minimal, AI-readable navigation. **Authority:** This file is descriptive only; the [agent SKILL](../../SKILL.md), [verification protocol](../../eg/docs/EXECUTOR_PROTOCOL.md) and authenticated live state govern operations. Do not use this index as an execution credential or substitute for PRE/POST.
>
> **Snapshot:** `main@5a56e9b9ddf0d74479590075d166d4293c79366f`, stable source release `v3.1.141`, examined 2026-10-27. Revalidate against HEAD and the target deployment before taking action.

## Quick navigation (start here)

| Task | Authoritative source |
| --- | --- |
| Agent operations, valid gates and API navigation | [SKILL.md](../../SKILL.md) |
| Project explanation and supported operations | [README.md](../../README.md) |
| Installation, durable state, backup, rollback | [Portable runbook](../../eg/docs/PORTABLE_RUNBOOK.md) |
| Exact hash-bound task/PRE/POST/receipt contract | [Executor protocol](../../eg/docs/EXECUTOR_PROTOCOL.md) |
| Generic execution model and historical boundary | [Generic execution model](../../eg/docs/GENERIC_EXECUTION_MODEL.md) |
| App internals and developer commands | [eg/README.md](../../eg/README.md) |
| Recovery and remedial task handling | [Remedial protocol](../../eg/docs/REMEDIAL_PROTOCOL.md) |
| Release vs live promotion and isolation | [Production promotion](../../eg/docs/PRODUCTION_PROMOTION.md) |
| Security limits and key handling | [SECURITY.md](../../SECURITY.md) |
| Verified previous cleanup and future code-analysis checkpoint | [code-analysis-progress.md](../../code-analysis-progress.md) |
| Why the primary execution model exists | [ADR-001](architecture/decisions/adr-001-generic-gateway-bounded-worker.md) |
| Cross-chat context-engineering status | [context-engineering-progress.md](context-engineering-progress.md) |

**Future content (not authored in phase 1):** `architecture/system-design.md`, `components/` and `workflows/`. Do not cite them as if present. See the progress document before extending.

## Project essentials

- **Purpose:** Generic, provider-neutral verification of ordered tasks, signed PRE readiness, admitted execution, signed receipts, independent POST evidence, audited checkpoints and final acceptance. Logical task coordination is not permission to perform physical actions.
- **Canonical application:** Python 3.12; FastAPI HTTP service with Pydantic schemas, SQLite durable task/audit state, Ed25519 verification/signatures and SHA-256 binding. HTTP is served by Uvicorn. Runtime direct dependencies are pinned in [eg/requirements.txt](../../eg/requirements.txt); exact redistributable closure and hashes are in [eg/requirements.lock](../../eg/requirements.lock).
- **Structure:** [eg/app/main.py](../../eg/app/main.py) is the canonical API and evaluator; [eg/app/execution_receipts.py](../../eg/app/execution_receipts.py) checks executor receipts; [eg/tools/trusted_execution_worker.py](../../eg/tools/trusted_execution_worker.py) implements bounded physical file effects; [eg/tools/single_agent_workflow.py](../../eg/tools/single_agent_workflow.py) coordinates one agent's gate/dispatch/verification flow; [eg/tests/](../../eg/tests/) holds regression and E2E tests.
- **Packaging:** Versioned Linux x86-64 portable offline archive targeting a CPython 3.12-compatible glibc environment; an optional Docker build is described in [eg/Dockerfile](../../eg/Dockerfile) and [eg/docker-compose.yml](../../eg/docker-compose.yml).
- **Capabilities in canonical distribution:** bounded file **read**, **exclusive creation**, and SHA-256 compare-and-swap **replacement**, within configured private worker `output_root`. Max content size 512 KiB. Defaults are `.txt` and validated `.json`; additional extensions require the operator's matching gateway + independently trusted worker policies. **No arbitrary shell, service management, Git push, broad host-write authority or project-specific executor is implied.**
- **Trust:** Gateway/evaluator, independent evidence-notary authority and bounded worker receipt signer are distinct purposes. A configured mode, healthy server, installed source, or listed capability cannot replace independently provisioned live signing roots and actual admission.
- **License:** EG source uses MIT; dependencies retain their own terms and notices. [Release workflow](../../.github/workflows/release-validation.yml) checks hash-locked dependencies, portable archive and third-party notices. This is not a legal opinion.

## Canonical workflow and API

`REGISTER → signed PRE → exact admitted action executed once → signed receipt → independent fresh POST → VERIFIED per step → SATISFIED task`.

All environments, including **staging**, use the same gates. Do not fabricate evidence, redo an ambiguous write or accept a task merely because CI passed.

- **Read-only discovery:** `GET /health`, authenticated `GET /v1/protocol`, `GET /v1/agent/capabilities`, `GET /v1/agent/capability-match`, `GET /v1/tasks/{task_id}/state`, `GET /v1/audit/verify`.
- **Mutation/verification:** `POST /v1/tasks/register`, `POST /v1/evaluate`, `POST /v1/tasks/{task_id}/pause`, `/resume`, `/reconcile`, `/abort`. Exact schemas are the running protocol and [source](../../eg/app/main.py).
- **Retries:** unknown response/timeout means **UNKNOWN**, not failure; reconcile original task, PRE, journal, target and receipt before continuing. A completed effect must not be dispatched again.
- **Lifecycle semantics:** `SOURCE PASS` / `CI PASS` / `SERVICE HEALTH` / `CAPABILITY AVAILABLE` / `CANONICAL VERIFIED` / `PRODUCTION READY` are different claims.

## Development and verification

In an isolated Python 3.12 environment, from `eg/`:

```sh
python -m pip install --only-binary=:all: --require-hashes -r requirements.lock
python -m pip install --only-binary=:all: -r requirements-test.txt
PYTHONPATH=.:tests python -m pytest -q -p no:cacheprovider tests
python tests/live_e2e.py
python tools/build_portable_bundle.py
python tools/test_offline_portable.py
```

The last two commands require the documented Linux build/root prerequisites; see [developer guide](../../eg/README.md#build-and-test). The [GitHub Actions workflow](../../.github/workflows/release-validation.yml) additionally checks Docker imports, isolated identities, relocatable archives and third-party license closure. **CI does not certify an external production deployment.**

## AI collaboration guardrails

1. **Read** this index, `../../SKILL.md`, the runbook, the verification protocol, and [progress](context-engineering-progress.md) before proposing changes.
2. **Pin** current `main` SHA, release, target runtime, task ID, current step/checkpoint and approved capability; never reuse historical deployments or credentials.
3. **Separate** observed facts from hypotheses. Cite a file/path or live proof. Historical names in old source/tests are not presently executable features.
4. **Protect** API contracts, immutable task history, evidence roots, key separation, rollback, license notices, and step-by-step PRE/POST.
5. **Prefer** minimal, independent documentation updates. If changing semantics, docs, dependencies or releases, use a reviewed PR and exact-SHA CI; publish an immutable **new** version instead of retargeting an old release.
6. **Do not include** credentials, state databases, evidence, signer keys or private deployment paths in documentation.

## Scope of this context system

The source code and canonical operational guides remain authoritative. This new context layer is a **navigation and handoff aid**, not an alternative EG runtime, policy, or source of permission. Where it conflicts with live protocol, stop and reconcile rather than silently choosing this summary.
