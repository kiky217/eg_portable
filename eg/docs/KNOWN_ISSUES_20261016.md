# Controlled remediation status — 2026-10-16

Repository: `kiky217/eg_portable`. Preserve the single `main` branch, immutable
historic task contracts, existing stable release assets, and append-only audit.

This document describes **source changes**, not a LIVE production acceptance
claim. The original Colab runtime expired and its canonical database was not
restored. A successful test-only signed executor is not a production signer.

## Addressed in source and CI

- #10 — Native CPython and ELF dependencies bundled from Debian Bookworm;
  clean Debian container must import Python, ssl, sqlite3 and cryptography
  without a host Python or network.
- #11 — Source allowlist excludes collocated runtime state, evidence,
  backups, credentials, and symlinks; synthetic-leak regression tests run.
- #17 — A current-source portable build, hash verification, relocation,
  and clean-container smoke now run before publication on every candidate,
  regardless of whether a matching release already exists.
- #12 — Readiness uses current-step/latest-READY/unconsumed gate semantics.
- #13 — Readiness accepts configured HTTP loopback ports and rejects
  external URLs and unsafe URL components.
- #14 — Rollback source archive must have a matching recorded digest and
  pass tar safety/readability checks. **Remaining:** cryptographic provenance
  of the archive report and an actual restore rehearsal are not proven.

## Remaining protocol and governance blockers

- #2 PRE currently shares postcondition with POST; distinguish readiness,
  postconditions, invariants, and action authorization in versioned schema.
- #3 Step action requirement is client-selectable; action=null can misclassify
  physical work. Lock step execution type at task registration.
- #4 PRE fingerprint does not bind initial write payload digest.
- #5 An unresolved execution gate can be superseded; recovery protection
  may be lost after failed POST.
- #6 No signed NOT_EXECUTED reconciliation path for a paused unexecuted gate.
- #7 Historical protocol hashes cannot consistently resume across upgrade.
- #8 PRE may advertise readiness for unsupported executor actions.
- #9 Mutating endpoints can progress despite full integrity verification fail.
- #15 Sealed executor receipt recovery after failed POST needs idempotent lookup.
- #16 Historical Colab notes and protocol beta markers still require a
  versioned documentation/protocol migration.

These require coordinated state-machine / protocol migrations and adversarial
E2E tests. Do not silence failures by changing acceptance, faking a receipt,
bypassing executor admission, or marking an old task SATISFIED.

## Verification discipline

Every change must be tied to an exact commit SHA, regression run and issue
acceptance. State only `VERIFIED` for the specific test or gate whose
readback proves it. GitHub release success alone is not production runtime
SATISFIED, and no Colab checkpoint is reconstructed from this repository.
