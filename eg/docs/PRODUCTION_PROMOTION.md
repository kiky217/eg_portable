# EG stable source releases versus production runtime

The canonical GitHub repository has exactly one branch: `main`.
The canonical release version comes from `eg/VERSION`. GitHub Actions must
pass on the exact release commit before publishing a corresponding immutable tag.
Every push, pull request, and manual workflow run rechecks the archive even if
the current version is already published. The release job alone may skip a tag
that already exists; it never replaces historical assets.

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
