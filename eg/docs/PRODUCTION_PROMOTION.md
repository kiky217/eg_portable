# EG v3.1.0 — Stable source release and runtime deployment

The canonical GitHub repository has exactly one branch: `main`.
Version **3.1.0** is a stable **software release**. GitHub Actions must pass
on the exact release commit before publishing an immutable `v3.1.0` tag.

A stable software release is distinct from a running production service.
The previous Colab session expired. Publishing this source cannot restore
the old SQLite database, anchor, evidence, or task checkpoint.

## Stable source acceptance

- Single canonical implementation `eg/` from protected `main`
- Hash-locked Python 3.12 dependencies and regression suite
- Trusted-executor signing and remedial E2E tests
- Linux/amd64 portable build, verified SHA-256, and offline relocation test
- Immutable stable release tied to tested SHA, preserving historical beta
- No private keys, API tokens, audit databases, or runtime secrets in bundle

## Live deployment requirements

A production deployment separately needs a trusted executor with independently
protected Ed25519 private key, distinct notary root, valid PRE/POST receipts,
durable backed-up SQLite and anchor, nonroot service, and verified health/audit.
Unsupported capabilities remain fail-closed. A GitHub release never implies
a live server is deployed or a historic task is retrospectively VERIFIED.

The last known old Colab task was 12/16 VERIFIED at checkpoint 26.
Session expiry does not amend that immutable acceptance ledger.
