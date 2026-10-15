# EG Portable — Evaluation Gateway

Portable Evaluation Gateway v3.0.1 source and mandatory managed-task policy for the canonical Colab local workspace.

**Scope:** an application-level, fail-closed task executor. It does **not** automatically intercept arbitrary root shells, notebooks, or unrelated processes.

## Repository layout

- `local-v3.0.1/runtime/` — EG server, hardened evaluation logic, protocols, Python dependencies, operations guide and regression/E2E test suites.
- `local-v3.0.1/MANIFEST.sha256` — source integrity manifest for the EG release package.
- `portable/bin/` — signed PRE/POST task execution, restricted E0/E2 operations and crash-safe reconciliation tools.
- `portable/EG_PORTABLE_POLICY.md` — hardcoded execution rules and honest enforcement boundary.
- `portable/install.sh` — installs and checks the portable policy in an **already configured** canonical Colab workspace.

## Runtime preconditions

The canonical local root is `/content/workspace` (not Google Drive).
This repository is source distribution; no credentials, initialized database, private notary key, live evidence, or virtual environment are included.

1. Prepare an EG runtime at `/content/workspace/eg/local-v3.0.1/runtime` from the source directory here. Run `sha256sum -c MANIFEST.sha256` from its parent folder.
2. Use Python 3.12 and the hash-locked dependencies in `runtime/requirements.lock`.
3. Follow `runtime/README.md` and `runtime/docs/OPERATIONS.md` to generate **new** credentials and notary keys and deploy the service on `127.0.0.1:18765`.
4. Once the EG server is healthy and the workspace has `/content/workspace/AGENTS.md`, run `bash portable/install.sh` to install the policy entrypoint and regression tests.
5. Run a registered task through the canonical executor:

```bash
/content/workspace/eg/.venv/bin/python /content/workspace/bin/eg-task.py hostname
```

Supported operations are currently `hostname`, `uptime`, `workspace-list` and `e2-smoke`. Unsupported operations fail closed with exit 77.

## Mandatory verification

Every managed task requires immutable EG registration, notarized PRE_EXECUTION, authorized execution, notarized POST_EXECUTION, terminal `SATISFIED` and authenticated audit verification. E2 uses reversible action-bound proofs and durable effect journaling; unknown effects are reconciled without blindly repeating writes. E3–E5 are unsupported by the portable executor.

## Security

Never commit `.env`, secrets, database, WAL/SHM, audit anchors, keypairs, runtime evidence or cached Python environments. See [SECURITY.md](SECURITY.md). This repository contains **source and examples only**.
