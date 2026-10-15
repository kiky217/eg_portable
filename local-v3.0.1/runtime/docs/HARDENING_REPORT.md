# Evaluation Gateway 3.0.0 Hardening Report

## Scope
3.0.0 closes the findings of the independent audit of the clean 2.2.0 archive (SHA-256 of the audited archive in `../../ARCHIVE_INFO.md`). Every finding was reproduced with a proof-of-concept against 2.2.0 before being fixed; each fix has regression tests in `tests/test_v3_regressions.py`.

## Findings and closure

| ID | Severity | Finding (2.2.0) | Fix (3.0.0) | Regression tests |
|---|---|---|---|---|
| B1 | High | Signed bindings carried no phase/checkpoint and no ordering vs. the PRE gate: pre-action evidence verified POST. | Bindings include `phase` and `checkpoint_no` (request checkpoint for PRE/FACT_CHECK, gate checkpoint for POST). POST evidence must have finished at/after gate creation (± clock skew). | `test_b1_*` |
| B2 | High | Client-controlled `max_age_seconds` up to 7 days. | Field removed; server policy `EVIDENCE_MAX_AGE_SECONDS` (bounded env); non-finite timestamps rejected; strict schemas reject unknown fields. | `test_b2_*` |
| B3 | High | Whole-DB rollback / tail truncation undetected; consumed gates replayable. | Gap-free `seq` bound into hash and HMAC; external HMAC anchor checked on every mutation and integrity pass; anchor must live in a different directory; `tools/reanchor.py` for deliberate restores. | `test_b3_*` |
| B4 | Medium | `hmac.compare_digest(str,str)` raised `TypeError` on non-ASCII → HTTP 500 (criteria, API/HITL headers, protocol hash). | `ct()` compares UTF-8 bytes everywhere; `protocol_hash` validated by regex; criteria compared with `==`. | `test_b4_*` |
| B5 | Medium | Unauthenticated O(n) `/health`, full-table load, `str(e)` leak, inconsistent snapshot. | Minimal body; single-flight TTL cache; verification in one WAL read snapshot with streaming cursor and reduced in-memory projection; details only in authenticated `/v1/audit/verify`; errors logged, not returned. | `test_b5_*` |
| B6 | Medium | Failed POST forced a new PRE (re-authorization/re-execution risk). | Gate is consumed only by a verified POST; POST retries on the same gate; `gate_checkpoint_no` recorded in the audit for exact reconstruction. | `test_b6_*` |
| B7 | Medium | Placeholder/weak secrets accepted (`<generate-…>` is 35 chars). | `validate_secret` (length, charset, distinct chars, entropy, placeholder words); `.env.example` ships empty values; `tools/generate_secrets.py`. | `test_b7_*` |
| B8 | Medium | Matcher chosen by the agent and unsigned; notary signed unchecked claims. | Matcher lives in the signed binding; client matcher rejected; notary tool validates schema and refuses to sign unless the assertion holds and `state.json` is PASS/0. | `test_b8_*` |
| L1 | Low | `/app` owned by runtime user. | Code and protocol stay root-owned; only `/data`, `/evidence`, `/anchor` are owned by `gateway`. | `test_no_legacy_artifacts_*` |
| L2 | Low | `next_action` ignored remedial/escalation blockers. | `task_guidance` returns `next_action`, `blocked_reason`, `remedial_task_id`; `pending_execution_gate` exposed. | `test_low_state_guidance_*` |
| L3 | Low | No way out of an unprovable remedial/task. | Audited, HITL-authorized `POST /v1/tasks/{id}/abort` (reconstructed by the verifier). | `test_low_abort_*` |
| L4 | Low | Connection leak / uncaught errors in verification. | All connections closed in `finally`; verifier fully wrapped; unknown audit event types fail closed. | `test_low_no_connection_leak_*` |
| L5 | Low | SQLite lock contention → 500. | `OperationalError` → 503 + `Retry-After`. | `test_low_database_busy_*` |
| L6 | Low | Evidence directory/root ownership not checked. | Root, directory and files must not be group/other writable; directory owned by trusted UID. | `test_low_evidence_directory_*` |
| L7 | Low | Stale MySQL schema/baseline files and per-version docs, host paths in baseline. | Removed; migration policy documented; docs consolidated in `CHANGELOG.md`. | `test_no_legacy_artifacts_*` |
| L8 | Low | Scattered magic numbers/versions. | Named constants, bounded env settings, single-sourced `VERSION`/`PROTOCOL_VERSION`/`MANIFEST_VERSION`. | `test_version_is_single_sourced_*`, `test_b2_bounded_*` |

## Preserved controls
Immutable contracts, hierarchy and post-order, PRE→POST action fingerprint, separate HITL key, checkpoint fencing, idempotent replay, Ed25519 notarization, request/evidence size bounds, evidence path/ownership checks, bounded remediation with original freeze, SQLite 0600, non-root/read-only Compose with dropped capabilities, loopback-only port, disabled docs/OpenAPI.

## Residual risks and assumptions
- The anchor defeats rollback only if the attacker cannot also rewrite the anchor and does not hold the audit HMAC key. Use separate storage or off-host mirroring (`docs/OPERATIONS.md` §3).
- The notary/producer is the root of trust for what evidence asserts; a compromised producer or private key defeats evidence integrity.
- A single shared HITL key authorizes all privileged actions (no per-approver identity or expiry).
- Integrity verification is O(n) in ledger size; it runs at startup, at most once per cache interval for `/health`, and on demand for `/v1/audit/verify`.
- The container image build and its digest-pinned base image were not exercised in the audit environment (no Docker available).
