# Evaluation Gateway — unified canonical system

**Release stage: production candidate, not production-admitted.** The only
active branch is `main`; stable promotion requires signed executor admission,
full EG acceptance, and release validation. See
[production promotion gates](eg/docs/PRODUCTION_PROMOTION.md).

This repository contains **one** EG implementation in [eg/](eg/).
There are no alternate runtime versions, mirrored source trees, portable
policy wrappers or secondary task databases.

EG alone registers tasks and immutable contracts, validates PRE, authorizes a
restricted trusted executor, validates signed POST evidence and finalizes
the parent task. All checkpoint, pause/recovery, remediation, and audit events
belong to its authoritative task registry.

Supported offline target: **Linux x86-64, CPython 3.12-compatible glibc**.
Other operating systems require tested adapters and currently fail closed.
Portable bundle and clean-install test are built from eg/tools/.
Application code does not depend on /content/workspace or a named Colab runtime.
Secrets and state must be supplied separately, outside the installation.

A shell operated with host-root privileges is not constrained by application
policy; do not claim universal host-root interception. Deploy the trusted
executor in an independent security domain to protect signing authority.
See [eg/docs/UNIFIED_ARCHITECTURE.md](eg/docs/UNIFIED_ARCHITECTURE.md).
