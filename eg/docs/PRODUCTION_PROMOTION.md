# EG stable source releases versus production runtime

The canonical GitHub repository has exactly one branch: `main`.
The canonical release version comes from `eg/VERSION`. GitHub Actions must
pass on the exact release commit before publishing a corresponding immutable tag.
Every push, pull request, and manual workflow run rechecks the archive even if
the current version is already published. The release job alone may skip a tag
that already exists; it never replaces historical assets.

A stable software release is distinct from a running production service.
The previous Colab session expired; this is only a historical fact. Each
new deployment discovers its own DB, anchor, evidence, signing authority,
current task/checkpoint, and authenticated audit.

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

The archived 2026-10-15 Colab case had 12/16 VERIFIED at checkpoint 26;
this historical state is not inherited by new deployments or retroactively
made SATISFIED by a software release.

## Generic worker promotion

A release ships one provider-neutral evaluator and reusable operator-pinned E3 process catalog. Promotion must verify multi-target routing, unapproved-target denial, original signed PRE, durable nonce, independently signed receipt, canonical POST and separated OS identities. Installing a new application does not demand a code release or bespoke executor; new permissions, if genuinely absent, are controlled by independently authorized environment policy. See [Generic execution model](GENERIC_EXECUTION_MODEL.md).
