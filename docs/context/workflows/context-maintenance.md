# AI context maintenance and cross-chat handoff

**Goal:** Keep `docs/context/` accurate without duplicating normative EG protocols or growing an uncontrolled collection of summaries. See [development/release workflow](development.md) and [master index](../project-overview.md).

## Entry procedure (every chat or source change)

1. Read [context-engineering-progress.md](../context-engineering-progress.md), [project-overview.md](../project-overview.md), [SKILL.md](../../../SKILL.md), [PORTABLE_RUNBOOK.md](../../../eg/docs/PORTABLE_RUNBOOK.md), [EXECUTOR_PROTOCOL.md](../../../eg/docs/EXECUTOR_PROTOCOL.md).
2. Retrieve live protected `main` HEAD, release/tag SHA, PR and CI status; record the difference from the last documented source snapshot. Do not guess that prior credentials, tasks or deployments still exist.
3. Inspect only affected source paths and their tests with source/line evidence. Separate tested observation, inference and unknown runtime facts.
4. Map the change to the smallest relevant context documents. Prefer updating a canonical link over copying long snippets.
5. Update the progress checkpoint with what is complete, unresolved, precise branch/SHA, next step and rollback/reconciliation information. Validate every local Markdown target, not only the first page.

## Trigger → document update

| Source/decision change | Context to review | Normative source to check |
| --- | --- | --- |
| New/changed API, task gate or schema | [gateway note](../components/gateway-evaluator-context.md), [system design](../architecture/system-design.md) | [main.py](../../../eg/app/main.py), [protocol](../../../eg/docs/EXECUTOR_PROTOCOL.md) |
| Worker action, path bound, signature or retry | [worker note](../components/trusted-worker-receipts-context.md), [ADR-001](../architecture/decisions/adr-001-generic-gateway-bounded-worker.md) | [worker](../../../eg/tools/trusted_execution_worker.py), [SKILL](../../../SKILL.md) |
| Evidence, notary, anchor, ledger or recovery | [audit note](../components/evidence-audit-context.md) | [main.py](../../../eg/app/main.py), [runbook](../../../eg/docs/PORTABLE_RUNBOOK.md) |
| Dependency, CI, version or portable packaging | [development workflow](development.md), [master index](../project-overview.md) | [release workflow](https://github.com/kiky217/eg_portable/blob/main/.github/workflows/release-validation.yml), [release guide](../../../eg/docs/PRODUCTION_PROMOTION.md) |
| Historical design decision with provenance | Add/mark a focused ADR | Verify dated source or actual decision record; **do not invent rationale or approvals** |

## Three-phase method and stop conditions

- **Phase 1 (done):** inventory, constraints, master index, first descriptive ADR and progress handoff.
- **Phase 2 (done):** system-design overview and three non-normative component context documents, backed by current source.
- **Phase 3 (done when CI/readback pass):** development/release workflow, this maintenance routine, automated link/scope tests, complete handoff, PR and immutable release validation.
- New design decisions or physical capabilities require a **new explicitly authorized change**, rather than retroactively expanding the completed context scope.
- **Fail closed on uncertainty:** if the document and actual runtime disagree, stop claiming availability and inspect source + current authenticated target.

## Minimal checkpoint template

```text
Context version / baseline SHA:
Phase completed:
Exact new/modified files:
Links/tests/CI run and SHA:
Release version, published target SHA (if applicable):
What source proves / what remains unverified:
Branch/PR and main merge status:
Next safe action / rollback baseline:
```

Store this in [progress](../context-engineering-progress.md) with dated corrections; never paste private credential values, task identifiers, private signing material or user-specific secrets.

## Release-sensitive update rule

The project publishes immutable exact-SHA tags. Never merge a documentation-only commit on `main` without anticipating release versioning: a published `eg/VERSION` cannot be silently reused for a new SHA. Add version + Docker image tag change to the same reviewed PR when appropriate, then verify resulting CI and new release. A historical red run remains in GitHub history even after the present HEAD turns green.

## Meaning of "E2E complete"

All context files present, internal links resolve, authoritatively mapped descriptions match inspected source, full GitHub validation and published-archive legal checks pass on the exact SHA, resulting `main` matches immutable release target, and progress is readable from a new chat without needing missing context. This is **documentation/release E2E**, not verification of a live external EG worker or production task.
