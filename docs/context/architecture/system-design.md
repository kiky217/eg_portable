# EG system design — as implemented

**Evidence baseline:** `main@5a56e9b9ddf0d74479590075d166d4293c79366f` (v3.1.141); later changes require revalidation. This explanatory document is not an authorization source. For normative rules use the [protocol](../../../eg/docs/EXECUTOR_PROTOCOL.md), [SKILL](../../../SKILL.md), and actual authenticated live state.

## Architecture in one view

```text
Agent / one-agent orchestrator (untrusted caller)
    | authenticated read / register / PRE / POST / recovery
    v
FastAPI EG evaluator + task registry + admission logic
    |                         |
    |                         +--> SQLite task/checkpoint/evidence/audit records
    |                                    |
    |                                    +--> external authenticated audit anchor
    |
    +--> validates independently signed notary evidence and worker receipts
    |
    v  only after exact READY PRE; never a self-authorization
Separate bounded worker (restricted output_root, private signer, durable journal)
    |
    +--> read / create-exclusive / compare-and-swap replace
    +--> sealed receipt + physical readback
    |
    v
Independent evidence notary + original POST --> canonical VERIFIED --> next step
```

The arrows describe responsibility and evidence relationships, **not** a claim that the gateway provides an unrestricted generic RPC or host shell. The same staged PRE/POST verification applies in development, **staging**, and production. An agent may coordinate work alone while **cryptographic trust roots remain independent**.

## Components and ownership

| Boundary | Source | Responsibility |
| --- | --- | --- |
| Public task API, schema, status and canonical evaluator | [eg/app/main.py](../../../eg/app/main.py) | Validate strict requests, task hierarchy, original gates and immutable acceptance |
| Executed-effect receipt contract | [eg/app/execution_receipts.py](../../../eg/app/execution_receipts.py) | Validate signed action/target/gate/output envelope |
| No-effect reconciliation proof | [eg/app/no_effect_receipts.py](../../../eg/app/no_effect_receipts.py) | Verify worker-signed proof for original unexecuted effect |
| Bounded execution / durable intent | [eg/tools/trusted_execution_worker.py](../../../eg/tools/trusted_execution_worker.py) | Check exact live PRE, enforce path/size and worker-owned scope, execute once and seal receipt |
| Single-agent sequence | [eg/tools/single_agent_workflow.py](../../../eg/tools/single_agent_workflow.py) | Register, PRE, one dispatch, independent POST; require explicit final task acceptance |
| SQLite/audit anchor and verification | [eg/app/main.py](../../../eg/app/main.py) | Event chain, record MAC, anchor and materialized-state consistency checks |
| Source/packaging | [release-validation.yml](https://github.com/kiky217/eg_portable/blob/main/.github/workflows/release-validation.yml) | Exact-source CI, Docker smoke, immutable release, archive relocation and license inventory |

Details are indexed in [component notes](../project-overview.md#quick-navigation-start-here): [gateway](../components/gateway-evaluator-context.md), [worker](../components/trusted-worker-receipts-context.md), [audit](../components/evidence-audit-context.md).

## Canonical operation sequence

1. Discover *this* deployment's current protocol, audit and capability state; never borrow a historical session's keys or assumptions.
2. `POST /v1/tasks/register` stores the immutable task, criteria and ordered steps before governed work.
3. Submit independently verifiable prerequisite evidence through `POST /v1/evaluate` phase `PRE_EXECUTION`. Only `READY_TO_EXECUTE` on the **correct step, checkpoint and action fingerprint** allows the separately trusted worker to start an effect.
4. Worker rechecks original gate/target/policy, durably records intent, executes the bounded operation once and issues the signed receipt. It recovers an existing sealed receipt instead of replaying a completed write.
5. Agent obtains **fresh independent evidence** and submits `POST_EXECUTION` with the original receipt. A `VERIFIED_PASS` is step-local; final `SATISFIED` requires independent task-wide acceptance.
6. Read task/state and authenticated `/v1/audit/verify`. A disconnected/unknown outcome triggers read-only reconciliation, not blind retries.

**Current bundled effects:** only bounded file read, exclusive create, and SHA-256 previous-content-bound replace in the worker's private root, with 512 KiB content limit; defaults `.txt` and validated `.json`. Extending suffix eligibility does not grant process, Git or service control.

## Trust, data and failure boundaries

- **Gateway:** authenticated API and signed evidence verification. Only `/health` is unauthenticated, and it provides liveness/integrity rather than authorization.
- **Evidence authority:** separately administered notary public/private trust material and manifest-v4 criterion/phase/checkpoint identity. An arbitrary evidence producer label has no privilege.
- **Worker:** non-root restricted process, separate protected Ed25519 signing key, private Unix socket/controller identity checks, append/durable intent journal and exact target readback. The same AI agent may orchestrate, but may **not** mint independent authorization.
- **Persistence:** external SQLite durable state, event chain with authenticated MAC and external anchor; storage consistency and rollback must be checked as a unit. No secrets or task DBs belong in source artifacts.
- **Fail-closed:** missing signer/worker, unknown effect, stale PRE, wrong step, bad receipt or mismatched audit means BLOCKED/RECOVERY_PENDING; no retrospective approval.
- **Operational reality:** source CI and a GitHub release are not a live production deployment. See [production promotion](../../../eg/docs/PRODUCTION_PROMOTION.md) and [runbook](../../../eg/docs/PORTABLE_RUNBOOK.md).

## Change impact map

- Changing `eg/docs/EXECUTOR_PROTOCOL.md` changes the hash-bound contract for new tasks; historical signed intake hashes must be preserved.
- Changing `eg/app/main.py`, receipt validation or worker affects authorization, audit and replay guarantees; exercise full tests and isolated E2E.
- Changing dependency closure or native packaging requires lock/license verification in the **actual archived bytes**.
- Changing root Markdown context should trigger link/fact checks but **does not** confer capability; read current canonical guides and live API first.
