# Error Handling and Logging — Current Patterns and Improvement Plan

> **Status:** Source-based review and proposals; **no runtime logging or error-handling behavior is changed by this document**.
>
> **Inspected baseline:** `main@908a490157d5472019ffdb54cc329448539af021`, EG v3.1.143, 2026-10-27 UTC. Verify newer source and the actual deployment before applying recommendations. The [protocol](../../../eg/docs/EXECUTOR_PROTOCOL.md), [SKILL](../../../SKILL.md), [runbook](../../../eg/docs/PORTABLE_RUNBOOK.md), and authenticated live task state remain authoritative.

## 1. Design principle

EG prefers **fail-closed, evidence-bound execution** over best-effort task completion. A rejected request, a failed POST verification, an unknown physical effect, and an unavailable worker are **different states**. A successful HTTP response or a logged message does not prove that a physical task is complete.

The canonical order remains `REGISTER → original PRE → admitted execute-once → signed receipt → fresh independent POST → VERIFIED → task-wide SATISFIED`. This also applies in staging. A new log or telemetry pipeline must never become an authorization source or substitute for an authenticated audit record.

## 2. Existing error-handling patterns

| Layer | Current behavior observed in source | Primary evidence |
| --- | --- | --- |
| Startup and configuration | Validates admission mode, signing roots, paths and permissions. Startup raises an error if authenticated audit/materialized state is inconsistent; service does not start partially trusted. | [main.py](../../../eg/app/main.py): `require_config`, `lifespan`, `integrity_ok` |
| HTTP request boundary | Pre-parse body-size middleware returns 400 for malformed Content-Length and 413 for oversize bodies. Strict Pydantic models reject unrecognized fields. | [main.py](../../../eg/app/main.py): `BoundedRequestBodyMiddleware`, strict request schemas |
| Authentication and identity | Missing/unavailable gateway key yields 503, incorrect key 401. Separately authorized abort requires HITL and can return 403. | [main.py](../../../eg/app/main.py): `require_key`, `abort_task` |
| Task and protocol conflicts | Uses HTTP 409 for stale checkpoints, reused event IDs with different inputs, gate/action mismatch, paused/recovery-pending work, invalid signed receipts and immutable contract conflicts; 404 for unknown tasks and 428 for missing protocol bootstrap. Most rejection objects contain stable `code` values, but some paths use plain-text `detail`. | [main.py](../../../eg/app/main.py): `register`, `evaluate`, `replay`, `reconcile_task` |
| Database availability and integrity | A dedicated SQLite operational-error handler emits HTTP 503 with `Retry-After: 1`. Read and mutation integrity guards log failures and return 503. Audited mutations roll back on exceptions. | [main.py](../../../eg/app/main.py): `database_busy_handler`, `guard_anchor`, `guard_integrity_read`, `commit_audited` |
| Partially committed audit/anchor | After the DB commit, external audit-anchor persistence may fail; code logs the exception and returns 503 with an explicit reconciliation requirement. This is an **unknown commit outcome**, not a safe invitation to replay a mutation. | [main.py](../../../eg/app/main.py): `commit_audited` |
| Evidence and trust failures | Separately notarized claims, signatures, manifests, file ownership, timestamp bounds and matching criteria are verified; missing/invalid evidence leads to an unverified verdict or refusal rather than an inferred PASS. | [main.py](../../../eg/app/main.py): `verify_evidence`, `verify_claim_set` |
| Worker and execution | Worker rejects unsupported actions, unsafe paths, stale/mismatched gates, oversized data, unexpected prior-file hashes or unauthorized Unix-socket callers using `WorkerDenied`. RPC handler returns `status: DENIED` with a reason string. | [trusted_execution_worker.py](../../../eg/tools/trusted_execution_worker.py): `TrustedWriter`, `serve` |
| Repeated/unknown effects | Durable intent journal, physical readback and sealed signed receipts prevent blindly executing a write twice. Recovery classifies observed states; an unknown effect requires original-gate/journal reconciliation, not another task or automatic retry. | [trusted_execution_worker.py](../../../eg/tools/trusted_execution_worker.py), [generic_recovery.py](../../../eg/tools/generic_recovery.py), [single_agent_workflow.py](../../../eg/tools/single_agent_workflow.py) |
| Operator diagnostics | Recovery CLI validates protected local files and returns a compact JSON diagnosis with nonzero status when work is not independently verified; readiness tools emit JSON/preflight explanations rather than approving execution. | [recovery_cli.py](../../../eg/tools/recovery_cli.py), [agent_readiness.py](../../../eg/tools/agent_readiness.py) |
| Credential-bearing HTTP calls | A reusable opener denies HTTP redirects so secret-bearing authentication headers are never forwarded to a different origin by automatic redirection. | [no_redirect_http.py](../../../eg/tools/no_redirect_http.py) |

### HTTP and evaluation semantics

- `400`: malformed HTTP Content-Length; `401`: invalid API key; `403`: missing separate HITL authorization; `404`: absent task; `409`: a broad set of immutable-contract, checkpoint, gate, recovery, signature or integrity conflicts; `413`: request body too large; `422`: malformed request/query or schema validation; `428`: required protocol bootstrap; `503`: unavailable credentials, SQLite busy, or failed integrity/anchor conditions. These are **observed examples, not a guarantee that every route uses each status**.
- Application evaluations also return **domain verdicts** such as `READY_TO_EXECUTE`, `UNVERIFIED`, `VERIFIED_PASS` and `REQUIRES_HITL`. Do not treat HTTP 200 as the same thing as a verified task.
- `Retry-After: 1` on SQLite operational errors is a client-facing hint, **not** blanket permission to retry a POST that may already have committed. Reconcile event ID, original task/checkpoint and committed audit state before any new mutation.

## 3. Existing logging and audit mechanisms

| Channel | Current implementation | Limit |
| --- | --- | --- |
| Gateway operational Python logging | `LOG = logging.getLogger("evaluation_gateway")`; selected `LOG.error` for SQLite and integrity failures and `LOG.exception` for unexpected anchor/materialized-state errors. | No project-wide structured schema, explicit request/trace correlation or centralized logging policy was found in the inspected source. |
| ASGI server process | Dockerfile starts Uvicorn with `--no-access-log`; bundled `run.sh` also disables access logging. | HTTP request access records are intentionally unavailable through Uvicorn's usual access log. This may reduce sensitive data exposure but also limits troubleshooting. |
| Managed service startup | [ensure_gateway_service.py](../../../eg/tools/ensure_gateway_service.py) redirects child stdout and stderr into the operator state's `gateway.log`, setting mode `0600`. | The helper appends to the file without a built-in size cap, rotation or retention mechanism. Other service launch paths may use different output sinks. |
| CLI and worker RPC | Multiple tools print machine-readable JSON; the worker returns a `DENIED` RPC object on exception. | These do not form one correlated, cross-component observability stream. The worker's generic `type(exception) + str(exception)` reason may disclose more internal detail than a public-safe error code. |
| Authenticated task/audit ledger | Canonical SQLite audit records bind event/request/response hashes, prior hash, HMAC and an external audit anchor. Worker receipt and evidence notary signatures are separately validated. | This is **security evidence and historical state**, not a replacement for operational logs, metrics or traces. Logs must not be used to rewrite or override the ledger. |
| Signed evidence stdout | A separate [evidence notarizer](../../../eg/tools/notarize_evidence.py) reads bounded evidence `stdout.log` and binds its digest to notarized evidence. | This is evidence captured for a particular task, **not** a generic unrestricted server log. Do not include secrets or pretend stdout alone is proof of completion. |

### Current recovery decision matrix

| Observation | Safe interpretation | Next action |
| --- | --- | --- |
| Exact sealed receipt, original PRE and independently verified target | Effect has documented proof; task may still need POST | Submit original canonical POST using fresh signed evidence; do not re-execute |
| Worker-signed proof that original effect was `NOT_EXECUTED` | Original gate may be reconciled | Reconcile **that gate**, then reevaluate PRE if authorized |
| Lost response, uncertain journal/target or stale/mismatched receipt | `UNKNOWN` / `RECOVERY_PENDING` | Read original state/journal/target, escalate for independent reconciliation; **no blind retry** |
| Canonical step `VERIFIED_PASS` but task-wide acceptance absent | Step completed, task not yet SATISFIED | Verify separately signed task acceptance and audit |
| Integrity/anchor validation failure | Cannot trust mutation/admission state | Fail closed, preserve durable evidence and run authorized offline recovery |

See [recovery rules](../../../eg/docs/PORTABLE_RUNBOOK.md) and [evidence/audit component](../components/evidence-audit-context.md) before attempting operational recovery.

## 4. Verified gaps and recommended improvements

These are **proposals**, not implemented capabilities. Preserve existing stable error codes, signed receipts, historical task contracts and public API behavior unless compatibility tests and an authorized change explicitly permit migration.

| Priority | Finding | Recommended change | Acceptance evidence |
| --- | --- | --- | --- |
| **P1** | Gateway, worker RPC and CLI errors are not correlated through a common logging contract. | Add privacy-safe, structured JSON operational events with UTC timestamp, severity, component, stable event code, opaque request/correlation ID and non-secret task/step reference. Keep logs distinct from signed task evidence. | Request/worker/recovery events correlate without exposing keys, payloads or raw claims; old clients remain compatible. |
| **P1** | Worker RPC serializes arbitrary exception text into `DENIED.reason`. | Map expected `WorkerDenied` cases to a finite set of stable **public-safe reason codes**; capture an independently protected diagnostic event for unexpected internal exceptions. Avoid leaking file paths, config values or reprs. | Error-sanitization tests with secret/path canaries; all original fail-closed denials remain denials. |
| **P1** | `gateway.log` is append-only in the helper, with no built-in size or retention bounds. | Add operator-configurable, **bounded** rotation/retention or a documented external journald/logrotate policy; preserve `0600` permissions, private state placement and non-blocking failure handling. | Stress test proves bounded storage, no secret leakage and no interruption of audit/worker state. |
| **P2** | HTTP error payloads mix strings and `{"code": ...}` dictionaries. | Introduce a documented, backwards-compatible error envelope (`code`, `message`, `request_id`, `retryability`), with a transition plan; never translate a genuine unknown write into `retryable=true`. | Contract tests for each existing status/verdict; old clients still work. |
| **P2** | Limited operational metrics for recovery-pending tasks, SQLite busy events and audit-integrity outages were found in the inspected runtime. | Add low-cardinality counters/gauges and protected alerting for failure counts, unavailable worker, `RECOVERY_PENDING` age, stale leases, anchor errors and growing log storage. Do not include raw task IDs as metric labels. | Explicit alert thresholds and test-only fault-injection proof; no effect authorization from metrics. |
| **P2** | Disabling access logs reduces request troubleshooting. | Keep default access logging disabled; optionally emit minimal, redacted request summaries at a trusted boundary with method, *route template* (not raw path/query), status, duration, opaque correlation ID and bounded rate. | No credentials, authorization headers, raw bodies, query strings or personal evidence in logs. |
| **P3** | Generic exception handlers and CLI output differ in internal diagnostic detail. | Standardize severity and operator runbooks; use bounded stack traces only in protected logs for genuinely unexpected failures, stable codes for expected denials, and clear CLI exit-code semantics. | Table-driven exception/CLI tests, operator troubleshooting without exposing secrets. |

## 5. Proposed structured event contract (illustrative, not live output)

```json
{
  "time_utc": "2026-10-27T00:00:00Z",
  "level": "ERROR",
  "component": "gateway",
  "event_code": "AUDIT_ANCHOR_PERSISTENCE_FAILED",
  "request_id": "opaque-correlation-token",
  "task_reference": "pseudonymous-or-omitted",
  "checkpoint_no": 42,
  "resolution": "RECONCILE_ORIGINAL_EVENT",
  "message": "Authenticated audit-anchor persistence requires reconciliation"
}
```

**Do not log:** API/HITL keys, signed private keys, Authorization/X-Evaluation-Key headers, raw HTTP body, evidence stdout, action payload, private workspace paths, full signed envelopes, patient/customer data, unredacted tracebacks in user-facing responses, or raw event identity if it makes private task material discoverable. Prefer allowlisted fields over fragile regex-only redaction.

**Never log success as evidence:** `RECOVERY_PENDING`, `SIGNED_RECEIPT`, `VERIFIED_PASS` and `SATISFIED` have distinct canonical meanings. A new `request_id` is **diagnostic**, not a trusted task ID or evidence signature. Logging failure must not rewrite a transaction, trigger duplicate execution, grant admission or block canonical recovery.

## 6. Suggested implementation order

1. **Tests and threat model first:** secret/path canaries, no altered HTTP contracts, duplicate-ID handling, journal crash cases, replay denial, unknown-result invariants, non-root filesystem mode.
2. **Minimal sanitized event abstraction:** one shared helper invoked by gateway/worker/CLI, with explicit field allowlist and bounded output, initially opt-in; no trust-model changes.
3. **Storage and operation controls:** log rotation/quota and documented deployment sink; preserve protected ownership and consistent audit backup behavior. Do not place log buffers on the immutable archive directory.
4. **Protected observability:** metrics and correlation through request and original checkpoint, with privacy-safe labels; alert on integrity/unknown-effect conditions.
5. **Backwards-compatible error-envelope rollout:** compatibility review, source regression, isolated HTTP E2E, worker crash/recovery/receipt tests, offline archive tests and immutable exact-SHA release verification.
6. **Verify in actual target environment independently:** source CI and a portable release do **not** establish production logging permissions, retention guarantees or live task acceptance.

## 7. Test and code navigation

- [Main gateway/error handlers](../../../eg/app/main.py)
- [Bounded worker and journal](../../../eg/tools/trusted_execution_worker.py)
- [Original-step one-agent workflow](../../../eg/tools/single_agent_workflow.py)
- [Generic recovery classification](../../../eg/tools/generic_recovery.py)
- [Protected read-only recovery CLI](../../../eg/tools/recovery_cli.py)
- [Gateway service/startup logging](../../../eg/tools/ensure_gateway_service.py)
- [No-redirect HTTP](../../../eg/tools/no_redirect_http.py)
- [Core fail-closed/regression tests](../../../eg/tests/test_admission_integrity_and_resume.py)
- [Crash/no-replay tests](../../../eg/tests/test_crash_after_claim_no_replay.py)
- [Sealed receipt recovery tests](../../../eg/tests/test_worker_sealed_recovery.py)
- [Isolated E2E](../../../eg/tests/live_e2e.py)
- [General development and release workflow](development.md)

**Review conclusion:** Strongest verified properties are immutable task checkpoint/audit controls, independent signed execution/evidence proofs and conservative recovery. The most valuable next improvements are **operational observability, public-safe reason codes and bounded log storage**, implemented without changing authorization, replay or historic audit semantics.
