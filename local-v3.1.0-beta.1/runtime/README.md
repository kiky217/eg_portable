# Evaluation Gateway 3.0.0 Local Orchestrator Rehardened

Clean local Evaluation Gateway for fail-closed agentic task evaluation. The package contains no runtime database, task state, live evidence, API/HITL/audit secret, or notary private key. Version is single-sourced from `VERSION`.

> **Breaking release.** Evidence manifests are now v4 (phase/checkpoint-bound, signed matchers), request bodies reject unknown fields, client-supplied freshness windows and matchers no longer exist, `/health` is minimal, and a separate audit anchor volume is required. See `docs/CHANGELOG.md`.

## Security model

- immutable protocol-bound contracts, required numeric hierarchy, canonical post-order;
- exact claim↔registered-criterion equality plus Ed25519 manifest-v4 signed bindings carrying task, step, criterion text, **phase**, **checkpoint reference** and the **matcher**;
- POST evidence must postdate its PRE gate; freshness is server policy, never client input;
- mandatory task-global acceptance verification at finalization;
- mandatory PRE before POST, immutable PRE↔POST action fingerprint, and **same-gate POST retry** (a failed verification never re-authorizes the action);
- E2 sandbox/rollback/reversibility proofs signed to the exact action intent and PRE checkpoint;
- separate HITL key for E3-E5, real-world effects and task abort;
- read-only `FACT_CHECK` and authenticated read-only reconciliation with explicit `next_action`/`blocked_reason`;
- exact checkpoint fencing and request-bound idempotency;
- SHA-256 audit chain with gap-free sequence, HMAC-SHA256 record authentication bound to the sequence, and an **external HMAC-authenticated audit anchor** that detects database rollback/truncation;
- full materialized-state reconstruction in one consistent WAL read snapshot;
- unicode-safe constant-time secret comparison (no 500 on non-ASCII input);
- secret validation (length, charset, entropy, placeholders) and strict request schemas;
- minimal unauthenticated `/health` with single-flight cached verification; detailed `/v1/audit/verify` behind the API key;
- 1 MB streamed-request limit, 2 MB per evidence file, evidence root/dir/file UID+mode+path enforcement; Swagger/ReDoc/OpenAPI disabled;
- loopback-only, non-root, read-only-rootfs Compose deployment with root-owned application code.

## Quick start

```bash
cd runtime
python tools/generate_secrets.py .env
python tools/generate_notary_keypair.py ./notary
echo "EVALUATION_GATEWAY_EVIDENCE_PUBLIC_KEY_B64=$(cat notary/notary_public.b64)" >> .env
mkdir -p evidence && chmod 755 evidence && sudo chown 10001 evidence   # trusted evidence uid
docker compose --env-file .env build
docker compose --env-file .env up -d
curl -fsS http://127.0.0.1:18765/health        # {"status":"PASS"}
```
Production/container builds use `requirements.lock` with package hashes and a digest-pinned Linux/amd64 Python base image. The service is exposed only on `127.0.0.1:18765`.

## Required configuration

| Variable | Requirement |
|---|---|
| `EVALUATION_GATEWAY_API_KEY` | validated secret (see `docs/OPERATIONS.md`) |
| `EVALUATION_GATEWAY_HITL_KEY` | validated secret, different from the API key |
| `EVALUATION_GATEWAY_AUDIT_HMAC_KEY` | validated secret, different from both; keep outside agent context and database |
| `EVALUATION_GATEWAY_EVIDENCE_PUBLIC_KEY_B64` | Base64 raw Ed25519 public key (private key stays on the producer) |
| `EVALUATION_GATEWAY_TRUSTED_EVIDENCE_UID` | owner uid of trusted evidence (default 10001 in Compose) |
| `EVALUATION_GATEWAY_ANCHOR_PATH` | set by the image to `/anchor/audit.anchor`; must be in a different directory than the database |

Optional bounded tunables: `..._EVIDENCE_MAX_AGE_SECONDS`, `..._CLOCK_SKEW_SECONDS`, `..._INTEGRITY_CACHE_SECONDS` (see `docs/OPERATIONS.md`).

Headers: ordinary requests use `X-Evaluation-Key`; HITL authorization additionally uses `X-Evaluation-HITL-Key`.

## API

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /health` | none | `PASS`/`FAIL` only |
| `GET /v1/protocol` | API key | protocol text, version, hash |
| `POST /v1/tasks/register` | API key | register immutable contract (NORMAL or REMEDIAL) |
| `POST /v1/evaluate` | API key (+HITL for E3-E5) | `PRE_EXECUTION`, `POST_EXECUTION`, `FACT_CHECK` |
| `POST /v1/tasks/{id}/abort` | API key + HITL key | audited termination |
| `GET /v1/tasks/{id}/state` | API key | read-only reconciliation (`next_action`, `blocked_reason`, `pending_execution_gate`) |
| `GET /v1/tasks/{id}` | API key | task, steps, checkpoints |
| `GET /v1/audit/verify` | API key | forced full verification + status |

## Evidence producer (manifest v4)

A trusted producer writes `state.json` and `stdout.log`, builds a bindings array, and signs it with `tools/notarize_evidence.py PRIVATE_KEY_PEM TASK_DIR BINDINGS_JSON`. The tool validates every binding schema and refuses to sign if the signed matcher does not hold against `stdout.log`. Binding schemas, the phase/checkpoint table and the full workflow are in `docs/OPERATIONS.md` and `tools/notarize_evidence.py`.

## Tests

```bash
cd runtime
python -m pip install --require-hashes -r requirements.lock && python -m pip install pytest httpx
python -m pytest -q tests
```
`tests/test_hardening.py` is the core suite; `tests/test_v3_regressions.py` contains the regression tests for each audited finding. `python tests/live_e2e.py` runs a real-process (uvicorn over loopback HTTP) end-to-end/adversarial check including restart, tamper, rollback and re-anchor scenarios.

## Clean-state guarantee and recovery

The archive excludes `gateway.db`, SQLite WAL/SHM, the audit anchor, `tests/_runtime`, local evidence bundles, `.env`, all secrets/private keys, logs and caches. There is deliberately no migration from earlier releases (`docs/OPERATIONS.md` §6). For stream/session recovery use `GET /v1/tasks/{task_id}/state`; see `../recovery/HANDOFF.md`. Test results are in `../TEST_REPORT.txt`; per-finding closure is in `docs/HARDENING_REPORT.md`.
