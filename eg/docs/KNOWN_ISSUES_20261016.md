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

- #5 — v3.1.4 prevents superseding a pending actionable READY gate and
  preserves RECOVERY_PENDING through failed same-gate POST. Signed NO_EFFECT
  reconciliation remains separate issue #6.
- #7 — v3.1.3 resumes authenticated historical protocol hashes using the
  current stricter validator without replacing immutable TASK_INTAKE.
- #9 — v3.1.3 verifies chain/HMAC/anchor/materialized state on the same write
  transaction and rejects corrupted worker state/detail readback.
- #15 — v3.1.5 retrieves and validates an already-sealed receipt from durable
  journal after failed POST; retry never re-writes the file.

## Remaining protocol and governance blockers

- #2 PRE currently shares postcondition with POST; distinguish readiness,
  postconditions, invariants, and action authorization in versioned schema.
- #3 Step action requirement is client-selectable; action=null can misclassify
  physical work. Lock step execution type at task registration.
- #6 No signed NOT_EXECUTED reconciliation path for a paused unexecuted gate.
- #16 Historical Colab notes and protocol beta markers still require a
  versioned documentation/protocol migration.

These require coordinated state-machine / protocol migrations and adversarial
E2E tests. Do not silence failures by changing acceptance, faking a receipt,
bypassing executor admission, or marking an old task SATISFIED.

## Completed release evidence (CI exact SHA)

- v3.1.3 (#7, #9):
  https://github.com/kiky217/eg_portable/actions/runs/38928398664
- v3.1.4 (#5):
  https://github.com/kiky217/eg_portable/actions/runs/38929218945
- v3.1.5 (#15):
  https://github.com/kiky217/eg_portable/actions/runs/38929818603

**Remaining technical issues:** #2, #3, #6, #14.
Issue #16 awaits this patch's documentation/hash migration E2E result.
The audit tracking issue #18 stays open until the remediation program is
finished. No stable source release equals a LIVE production EG task SATISFIED.

## Verification discipline

Every change must be tied to an exact commit SHA, regression run and issue
acceptance. State only `VERIFIED` for the specific test or gate whose
readback proves it. GitHub release success alone is not production runtime
SATISFIED, and no Colab checkpoint is reconstructed from this repository.

## Newer verified work

- v3.1.6 #8: worker capability admission, signed E2E PASS:
  https://github.com/kiky217/eg_portable/actions/runs/38934279298
- v3.1.7 #4: payload identity bound before PRE, adversarial signed E2E PASS:
  https://github.com/kiky217/eg_portable/actions/runs/38935737285
