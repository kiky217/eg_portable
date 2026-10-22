# Governed persistent staging website

This example is a **site-specific, operator-owned staging adapter**. It closes the
gap between testing a temporary HTTP response and keeping a real local service
available after an EG worker step finishes. It does **not** deploy arbitrary
applications or make staging equivalent to production.

The nonroot owner starts the HTTP server on **127.0.0.1 only**, stores its
current and previous HTML versions in its private state directory, and exposes
a restricted Unix control socket. The separately authenticated E3 worker
cannot read or modify that state directly. Its operator-fixed action invokes
`python -m tools.staging_site_service client /operator/site.sock` with a JSON
payload from the EG-authorized action. No agent-selected executable or shell
is accepted.

The root/operator config (regular owner-only `0600` JSON, outside project
source) has fields:

| Field | Purpose |
| --- | --- |
| `state_dir` | Private nonroot site state directory, `0700` |
| `socket_path` | Unix socket under site-owned group-pinned `2710` directory |
| `controller_uid`, `controller_gid` | **Exact separate E3 worker** identity |
| `http_port` | Dedicated loopback HTTP port |

The site process refuses root and rejects the wrong Unix peer UID even if the
process can reach the socket. The agent does not own the site or E3 signer
keys. The E3 worker is onboarded through
[operator process service](OPERATOR_PROCESS_SERVICE.md), with a separately
signed capability binding and
[standing staging approval](SCOPED_STAGING_APPROVAL.md) (or independent
per-action operator HITL).

## Three physical steps

Each EG action is `E3/bounded_process_run`, with its immutable payload SHA-256,
fresh PRE, scoped HITL signature, independently signed effect receipt and
canonical POST:

1. `deploy` with an HTML document, base64 content and content SHA-256.
2. `deploy` with a revised document under a **new**, separately verified gate.
3. `rollback` with the digest of the previous stored version, again under a
   new gate. It is **not** a replay of a consumed earlier effect.

The site remains available over HTTP between steps. Verify the actual HTTP
body and digest before POST. Uncertain effects must first be reconciled by
read-only HTTP/state inspection; **never blindly replay** a used E3 grant.
The private state is durably atomically replaced, and initial unprovisioned
GETs report HTTP 503.

## Evidence

`tests/test_staging_site_service.py` starts the service under its own OS UID
and checks loopback deploy, revision, rollback, wrong digest and unauthorized
socket access.

`tests/test_staging_site_eg_integration.py` creates one EG task with three
separately signed physical effects. It uses a different nonroot E3 executor
UID, independent operator-signed registry, standing scoped policy and real
HTTP readback; every step must POST VERIFIED, the task must SATISFIED and
the EG audit chain must PASS. Both run in an isolated root-authorized CI
fixture with source copied byte-for-byte to a nonroot-accessible directory.

**Limits:** single HTML document, loopback-only, one previous version, no
persistent application subprocess management, external network exposure,
production rollout, production rollback, or generic host package installation.
