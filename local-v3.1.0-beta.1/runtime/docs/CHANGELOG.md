# Changelog

## 3.0.0-local-orchestrator-rehardened (2026-10-07) — BREAKING
Closes audit findings B1–B8 and L1–L8 (details and tests in `HARDENING_REPORT.md`).

Breaking changes:
- Evidence manifest **v4**: bindings gain `phase`, `checkpoint_no` and a signed `matcher`; v3 evidence is rejected.
- Request schemas are strict (`extra=forbid`); `Claim.max_age_seconds` and `Evidence.matcher`, and manual-evidence `observed_at`/`payload`, were removed.
- `POST_EXECUTION` evidence must be bound to the PRE gate checkpoint and postdate the gate; a failed POST is retried against the same gate.
- `GET /health` returns only `{"status":"PASS"}`; former fields (`version`, `audit_chain`, …) moved to `GET /v1/audit/verify`; the obsolete `legacy_mode` field is gone.
- Audit schema adds `seq`; record MAC and hash include the sequence. A new database is required (no migration).
- New mandatory `EVALUATION_GATEWAY_ANCHOR_PATH` (separate volume `gateway_anchor` in Compose).
- Secrets are validated for charset/entropy; `.env.example` ships empty values.
- SQLite runs in WAL mode.

Additions: `POST /v1/tasks/{id}/abort`, `pending_execution_gate`/`next_action`/`blocked_reason` in task state, `tools/generate_secrets.py`, `tools/reanchor.py`, `docs/OPERATIONS.md`, bounded tunables (`EVIDENCE_MAX_AGE_SECONDS`, `CLOCK_SKEW_SECONDS`, `INTEGRITY_CACHE_SECONDS`), 49 regression tests.

Removed: `schema_mysql.sql`, `baseline/` (pre-hardening MySQL snapshot with host paths), per-version hardening notes (consolidated here).

## 2.2.0-local-orchestrator-rehardened (2026-10-06)
Signed evidence binding manifest v3; mandatory task-global acceptance verification; exact E2 proof/action binding; cross-task/step-safe evidence materialization; authenticated audit HMAC; full materialized-state reconstruction; read-only functional `FACT_CHECK`; aligned Compose/versioning; digest-pinned base image; hash-locked dependency closure; recovery handoff.

## 2.1.2-local-orchestrator-rehardened
Criterion/action-scoped evidence fingerprints (a reused evidence object materializes once per criterion); bounded evidence metadata (2,000,000 bytes per file); read-only reconciliation endpoint `GET /v1/tasks/{task_id}/state`.

## 2.1.1 local rehardening
Actual-byte request bound at the ASGI boundary (413 above 1,000,000 bytes, 400 on invalid `Content-Length`); SQLite file mode 0600; loopback-only deployment, disabled docs/OpenAPI, separate API/HITL keys, public-key-only gateway.

## v3.0.1 — Audit anchor fail-closed correction (local patch)
- A post-commit anchor write error returns HTTP 503 with explicitly uncertain commit outcome; it is never reported as success.
- An authenticated anchor behind the committed DB ledger refuses new mutations and integrity verification, rather than silently accepting/auto-advancing the anchor.
- Concurrent integrity reads tolerate a bounded transient DB-commit-to-anchor-write window without automatically modifying the anchor; persistent lag requires offline verified `tools/reanchor.py --confirm` with gateway stopped.
- Includes fault injection regression for repeated anchor EIO, restart health, and recovery. Existing protocol and evidence semantics unchanged.
