# Operations Guide

## 1. Secrets
Generate (never copy placeholders; the gateway rejects them):

```bash
python tools/generate_secrets.py .env            # new 0600 file, refuses to overwrite
python tools/generate_notary_keypair.py ./notary  # private key stays on the trusted producer
```
Add `EVALUATION_GATEWAY_EVIDENCE_PUBLIC_KEY_B64=$(cat notary/notary_public.b64)` to `.env`.

Validation applied to the API key, HITL key and audit HMAC key: length >= 32; characters limited to `A-Za-z0-9_-+/=.~`; no placeholder words; at least 10 distinct characters and >= 3.5 bits/char Shannon entropy; all three pairwise different.

## 2. Tunables (all bounded; startup fails on an out-of-range value)
| Variable | Default | Range | Meaning |
|---|---|---|---|
| `EVALUATION_GATEWAY_EVIDENCE_MAX_AGE_SECONDS` | 300 | 1-86400 | Server-side evidence freshness window |
| `EVALUATION_GATEWAY_CLOCK_SKEW_SECONDS` | 30 | 0-300 | Tolerance for future timestamps and gate-ordering |
| `EVALUATION_GATEWAY_INTEGRITY_CACHE_SECONDS` | 15 | 0-300 | Max age of the cached result served by `/health` |
| `EVALUATION_GATEWAY_TRUSTED_EVIDENCE_UID` | process uid (10001 in compose) | 0-2^31-1 | Owner uid required on evidence |

Fixed limits (constants in `app/main.py`): request 1,000,000 bytes; each evidence file 2,000,000 bytes; 200 bindings per manifest; 3 local remediation failures; 3 remedial-step failures.

## 3. Volumes and the audit anchor
- `gateway_data` -> `/data` (SQLite in WAL mode: `gateway.db`, `-wal`, `-shm`).
- `gateway_anchor` -> `/anchor` (`audit.anchor`, HMAC-authenticated head + sequence). The gateway refuses to start if the anchor is not in a different directory than the database.
- The anchor only protects against rollback if an attacker who can restore the database cannot also rewrite the anchor. For real separation, back `/anchor` with a different disk/host, or mirror `audit.anchor` off-host after every deploy and compare it periodically.

## 4. Evidence producer workflow (manifest v4)
For each criterion the producer needs to know the phase and checkpoint the evidence is for:

| Gateway call | `phase` in binding | `checkpoint_no` in binding |
|---|---|---|
| `FACT_CHECK` | `FACT_CHECK` | request `checkpoint_no` |
| `PRE_EXECUTION` | `PRE_EXECUTION` | request `checkpoint_no` |
| `POST_EXECUTION` (step and task criteria) | `POST_EXECUTION` | `gate_checkpoint_no` from the READY PRE response |
| E2 `action_proof` | `PRE_EXECUTION` | request `checkpoint_no` of the PRE |

Sequence: run the real check -> write `state.json` (`task_id`, `status: PASS`, `exit_code: 0`, `finished_at`) and `stdout.log` -> write bindings JSON (each with its signed `matcher`) -> `python tools/notarize_evidence.py PRIVATE_KEY TASK_DIR BINDINGS_JSON` -> place the directory (owner = trusted UID, mode 0700) in the evidence root. The tool refuses to sign unless the matcher assertion holds against `stdout.log`.

After an interruption, `GET /v1/tasks/{id}/state` returns `pending_execution_gate.pre_checkpoint_no` (the checkpoint reference POST evidence must be bound to) and `next_action`.

## 5. Backup and restore
- Back up with SQLite's online backup (`sqlite3 gateway.db ".backup 'backup.db'"` or `VACUUM INTO`), never by copying only `gateway.db` while WAL data may be pending. Back up `audit.anchor` together with it.
- Restoring a database that is older than the anchor is (correctly) refused. After a deliberate restore, with the gateway stopped and the same environment variables:

  ```bash
  python tools/reanchor.py --confirm
  ```
  The tool verifies the full chain, HMAC and materialized state first and only then moves the anchor to the restored head. Record who ran it and why; actions executed after the restored point are not reflected in the ledger and MUST be reconciled manually.

## 6. Migration policy
There is deliberately no in-place migration from earlier releases or from the pre-hardening MySQL deployment: their audit trails lack the sequence-bound HMAC and anchor, and importing them would fabricate continuity. Start with a fresh database. Preserve the old ledger/evidence externally as provenance and reference it from new task contracts.

## 7. Health and monitoring
- `GET /health` (unauthenticated): `{"status":"PASS"}` or 503 `{"detail":"integrity check failed"}`; details are in the gateway log only.
- `GET /v1/audit/verify` (API key): forces a fresh full verification and returns version, protocol hash, record count, head hash, and chain/anchor/state status.
- Database lock contention returns 503 with `Retry-After: 1`; clients should retry with the same `event_id`.

### Audit-anchor storage failure (v3.0.1)
If any audited write returns HTTP 503 `audit anchor persistence failed`, treat the database commit outcome as **UNKNOWN** and do not replay with a new event ID. Stop the gateway, preserve DB+WAL and anchor backups, investigate/repair storage, verify chain+HMAC+materialized state offline, and only then use `python tools/reanchor.py --confirm` with explicit operator approval. Restart and verify `/health` and `/v1/audit/verify`; reconcile the original event ID. A lagging anchor is never silently advanced by health checks.
