# Production promotion gate

Repository: `kiky217/eg_portable`
Canonical branch: `main` only. Feature history remains in the `main` ancestry;
historical prerelease tags and assets are preserved.

## Release state

**Source: production-candidate hardening. Runtime: NOT PRODUCTION-ADMITTED.**

Version `3.1.0-beta.1` remains a prerelease until all gates below pass.
A repository label, a protected branch, or CI success does not constitute
production verification.

## Required gates

1. Build from exact immutable main SHA, with hash-locked runtime dependencies.
2. Execute unit, adversarial, E2E and portability validation on supported
   CPython 3.12 / Linux amd64; store independently reviewable results.
3. Provision genuinely independent executor signing keys and admission; EG
   notary and executor trust roots must differ and remain separately controlled.
4. Reconcile stale PRE gates and prior cutover effects without fabricated or
   retroactive signed execution receipts.
5. All required EG task steps and global acceptance are VERIFIED; the canonical
   task is SATISFIED, and authenticated audit chain verification is PASS.
6. Deployment uses one source, one active EG runtime, preserved state, backup,
   rollback, runtime health/readback, and no parallel EG.
7. Publish stable `v3.1.0` release only after all above gates are evidenced;
   retain the historical beta artifacts and references without re-labelling
   them as stable. Tag and published release must refer to the same SHA.

## Confirmed state (2026-10-16)

- `main` includes the old feature branch plus nine additional commits.
- Branch `feature/eg-3.1.0-beta-20261015` was safely retired.
- `main` is protected against force-push, deletion and nonlinear history.
- Historical beta tag and release retained as prerelease.
- Historical Colab cutover was operationally verified; the old canonical
  task remained **12/16** at checkpoint **26**, executor admission disabled.
- The previous Colab runtime expired. Production admission and fresh full
  release validation in the new runtime are **not** verified.
- `.github/workflows/release-validation.yml` is a manual validation
  workflow only. A workflow file is not a passing workflow run.

**Decision:** do not assert `PRODUCTION` or publish a stable release while
any runtime admission, acceptance, or validation gate remains open.

## Release sequence

Run the GitHub Actions `EG release validation` workflow on `main`.
After its successful run and an independently verified production-admission
and EG task acceptance, create the immutable stable tag and associated
release from the fully reviewed commit. Protect release tags and document
state migration plus rollback evidence.
