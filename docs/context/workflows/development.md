# Development, validation and immutable release workflow

**Scope:** EG source and documentation collaboration. This is an explanatory checklist for contributors, not a substitute for [SKILL](../../../SKILL.md), [protocol](../../../eg/docs/EXECUTOR_PROTOCOL.md), or a live task's authorization. For context-doc maintenance see [context-maintenance.md](context-maintenance.md).

## 1. Establish the actual baseline

1. Read [project overview](../project-overview.md), [source developer guide](../../../eg/README.md), [generic execution model](../../../eg/docs/GENERIC_EXECUTION_MODEL.md) and [security boundary](../../../SECURITY.md).
2. Read the current protected `main` SHA, `eg/VERSION`, immutable release tag and CI status; do not infer HEAD from an earlier chat. Check for open PRs and changed source since this documentation snapshot.
3. Identify affected components and consumers (runtime, tests, CLI, docs, Docker, portable archive, external admissions). Describe proposed behavior and security boundary before coding.
4. Use an isolated feature branch. Avoid changing credentials, durable data, signed historical evidence or live production tasks for source review.

## 2. Change by explicit contract

- Keep `REGISTER → original READY PRE → one bounded execution → original signed receipt → fresh independent POST → VERIFIED → SATISFIED`.
- `GET /v1/agent/capabilities` and capability-match are **diagnostics**, not execution grants.
- Canonical bundled effects are bounded read, exclusive create and verified replace within the private output root. A generic API does **not** provide arbitrary shell, Git push or service cutover.
- Preserve separate notary and worker trust authority and a readback/reconciliation path for UNKNOWN effects.
- Any edited [EXECUTOR_PROTOCOL.md](../../../eg/docs/EXECUTOR_PROTOCOL.md) changes the new-task hash-bound protocol identity; original signed historical tasks stay immutable.
- Add focused tests for changed behavior and fail-closed cases. A test-only signer/worker cannot establish external production readiness.

## 3. Local checks (disposable Python 3.12 environment)

From the `eg/` working directory, **outside any real production state**:

```sh
python -m pip install --only-binary=:all: --require-hashes -r requirements.lock
python -m pip install --only-binary=:all: -r requirements-test.txt
PYTHONPATH=.:tests python -m pytest -q -p no:cacheprovider tests
python tests/live_e2e.py
```

The portable offline build/relocation needs the documented Linux container and identity prerequisites; don't infer that a development laptop is equivalent. Refer to [eg/README.md](../../../eg/README.md#build-and-test).

## 4. GitHub Actions exact-SHA verification

The [release workflow](https://github.com/kiky217/eg_portable/blob/main/.github/workflows/release-validation.yml) runs for PRs and pushes to `main`: hash-locked dependencies, task/worker regression and isolated HTTP E2E, different OS identity evidence test, Docker import smoke, portable Linux/amd64 bundle, SHA-256 manifest, legal notice closure, relocatability and no-host-Python Debian smoke.

Only report CI PASS when the **exact head SHA** is completed successfully. An earlier PASS on another SHA is not the same evidence. Always inspect failed job logs, not merely a red badge.

## 5. Immutable promotion and rollback

- Publish-on-push `main` requires an **unused `eg/VERSION`** for each newly published SHA. A documentation-only commit is still a new SHA; reusing an existing immutable tag causes `VERSION_BUMP_REQUIRED` and a failing release job.
- Coordinate version + [Docker Compose tag](../../../eg/docker-compose.yml) **in the same PR** before merging; never retarget/delete a published tag or relax immutability just to make CI green.
- After merge, read back `main` SHA, final `publish_stable` PASS, release target/tag and archive/checksum. A PR PASS alone does not establish stable publication.
- Keep a previous tagged release as rollback reference. For stateful production, first evaluate task/DB/audit/anchor compatibility and authorized restoration; a Git tag is not a production rollback action.
- Preserve third-party license notices. EG's MIT source license does not relicense bundled dependencies. See [production promotion](../../../eg/docs/PRODUCTION_PROMOTION.md).

## 6. Documentation/context change checklist

1. Update this [overview](../project-overview.md), [system design](../architecture/system-design.md), relevant [component](../components/gateway-evaluator-context.md) and [handoff checkpoint](../context-engineering-progress.md) **only** where the verified behavior changed.
2. Cross-check links with `eg/tests/test_context_docs_consistency.py`; test that all context docs still exist, targets resolve and core authority boundaries remain explicit.
3. If behavior/installation changed, update canonical SKILL/runbook/protocol *with separate approval and exact hash implications*. Context notes do not supersede them.
4. Record source SHA, files changed, CI evidence, known skips, release SHA and unverified live conditions. Do not copy secrets or agent-private memory into repository docs.

**Completion label:** SOURCE/DOCS VERIFIED requires reviewed diff + SHA-matched regression; RELEASE VERIFIED additionally requires immutable published archive; LIVE ACCEPTANCE requires separate actual task/worker/audit evidence.
