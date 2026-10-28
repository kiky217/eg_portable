# EG stable source releases versus production runtime

The canonical GitHub repository has exactly one branch: `main`.
The canonical release version comes from `eg/VERSION`. GitHub Actions must
pass on the exact release commit before publishing a corresponding immutable tag.
Every push, pull request, and manual workflow run rechecks the archive even if
the current version is already published. The release job alone may skip a tag
that already exists; it never replaces historical assets.

A stable software release is distinct from a running production service.
Each deployment discovers its own database, anchor, evidence, signing authority,
current task/checkpoint, and authenticated audit. A source release does not imply
that any previous Colab deployment is available or current.

## Stable source acceptance

- Single canonical implementation `eg/` from protected `main`
- Hash-locked Python 3.12 dependencies and regression suite
- Signed bounded-worker receipts, PRE/POST, and remedial/recovery regression tests
- Linux/amd64 portable build, verified SHA-256, and offline relocation test
- Immutable stable release tied to tested SHA, preserving historical beta
- No private keys, API tokens, audit databases, or runtime secrets in bundle

## Live deployment requirements

A production deployment separately needs a trusted executor with independently
protected Ed25519 private key, distinct notary root, valid PRE/POST receipts,
durable backed-up SQLite and anchor, an operator-selected root or non-root host identity, and verified health/audit. Host root access does not itself establish independent signing authority. Root and non-root EG can operate concurrently only with isolated writable ledgers, ports and trust configurations.
Unsupported capabilities remain fail-closed. A GitHub release never implies
a live server is deployed or a historic task is retrospectively VERIFIED.

Historical task states are not inherited by a new deployment and cannot be
made SATISFIED retroactively by a software release.

## Generic worker promotion

A release ships the portable evaluator with bounded file operations. Promotion verifies task registration before work, signed PRE, bounded execution, original receipt, fresh POST, recovery and audit. Additional process executors are not part of the canonical installation.
