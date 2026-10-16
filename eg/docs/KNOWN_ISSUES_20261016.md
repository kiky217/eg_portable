# Remediation history and current boundaries

This file is a **historical issue snapshot**, originally written on 2026-10-16 before completion of issues #2–#18. Do not treat its original "remaining" statements as current instructions. The authoritative current issue state is [GitHub Issues](https://github.com/kiky217/eg_portable/issues).

## Completed repository remediation (historical issues)

Issues **#2–#18** were marked closed on GitHub after source and CI remediation. In particular:

- **#2:** PRE readiness has independent preconditions; invariants are verified at PRE and POST.
- **#3:** New registered steps require explicit immutable `execution_required` classification; physical steps cannot use `action=null`.
- **#5:** An unresolved actionable READY gate cannot be superseded by a new PRE.
- **#6:** Independently signed `NOT_EXECUTED` reconciliation is implemented under a verified worker trust root and append-only task audit. UNKNOWN remains BLOCKED.
- **#14:** Independent signed rollback archive provenance and isolated restore rehearsal are implemented. This verifies archive evidence, **not** a live production service cutover.
- **#16:** Historical Colab notes are archival; no old session or checkpoint establishes current runtime state.
- **#17:** Full regression, portable bundling, and relocation tests run even when a release already exists.
- **#18:** Prior repository audit umbrella was closed. It did **not** certify an external live production cutover.

Repository E2E reference: [exact-SHA CI run 38946377609](https://github.com/kiky217/eg_portable/actions/runs/38946377609), HEAD `309f51c0f0235b76a5989777d5483b0f83bc8b44`, 190 tests passed.

## Open follow-up work (recorded 2026-10-16)

- [#19](https://github.com/kiky217/eg_portable/issues/19): portable E3–E5 executor capability + hybrid HITL; no approval-only READY.
- [#20](https://github.com/kiky217/eg_portable/issues/20): mandatory EG-gated agent execution within integrated dispatcher boundaries, including staging; no retrospective verification.
- [#21](https://github.com/kiky217/eg_portable/issues/21): portable notary secret separation.
- [#22](https://github.com/kiky217/eg_portable/issues/22): immutable release version versus tested HEAD mismatch.
- [#23](https://github.com/kiky217/eg_portable/issues/23): documentation drift (this file, now identified as historical).
- [#24](https://github.com/kiky217/eg_portable/issues/24): PRE supersession protocol contradiction.
- [#25](https://github.com/kiky217/eg_portable/issues/25): archive/resource budget hardening.

Status may change: follow GitHub rather than interpreting this list as a live snapshot.

## Mandatory operational distinctions

Every registered step requires EG PRE and POST validation **including staging**. An executable step requires an admitted independent executor and a signed execution receipt. Agent claims, command exit codes, and GitHub CI success are not equivalent to EG VERIFIED. When effects are uncertain, reconcile the original gate and durable work evidence without replay.

GitHub source CI, published immutable release assets, independently signed rollback evidence, and an authenticated live production EG `SATISFIED` outcome are **four different claims**. A successful one never implies the others. The historical Colab task records are preserved and cannot be recreated from source control.

For current operational instructions, use [PORTABLE_RUNBOOK.md](PORTABLE_RUNBOOK.md), [EXECUTOR_PROTOCOL.md](EXECUTOR_PROTOCOL.md), and [PRODUCTION_PROMOTION.md](PRODUCTION_PROMOTION.md).
