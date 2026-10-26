# EG portable — canonical active runbook

## Canonical staged execution: verify each step before continuing

**"Install EG completely as a generic system and test it end-to-end until every supported, authorized capability is operational."**

**Required for every fresh installation and upgrade (including staging):** Read the [canonical agent SKILL](../../SKILL.md) first. Install one portable gateway with durable task/audit state and the built-in read, create and replace operations. Require task registration before any work and a verified PRE, exact execution receipt where an action occurs, independently checked POST, and completion of each step before starting the next; staging is not exempt. **Do not build project-specific executor code or infer privileges from the presence of source code.**

**Mandatory verification:** REGISTER → signed PRE → admitted action → signed receipt → independently checked POST → VERIFIED → next step → SATISFIED. No work before PRE, no retrospective claims, no staging exceptions.

**Fail closed:** Without registration, current-step PRE, signed action receipt or verifiable POST, the step stays BLOCKED. A healthy gateway or passing CI never proves task completion. Operations outside EG are not governed or eligible for retroactive acceptance.

This document applies to **new deployments and active runtimes**, not to a
historical Colab session. One registry, one current evaluator, one writer.

## Reconnect / idempotent service startup

With an already initialized state, run `PYTHONPATH=eg python3.12 -m tools.ensure_gateway_service --bundle /path/to/eg-portable-3.1.133-linux-amd64 --state "$EG_STATE_DIR"`. This checks the authenticated protocol hash, **running app/tools source fingerprint**, admission mode and full capability fingerprints (including target scope, payload limit and worker public key) before reusing a live process. A new bundle with unchanged protocol documentation but different runtime code cannot silently reuse the old process. If the running catalog differs from runtime.env, it reports `RUNNING_GATEWAY_CONFIG_DRIFT_RESTART_REQUIRED` instead of falsely claiming readiness or terminating a process with unresolved effects. It starts only when no gateway responds, and refuses a foreign process occupying the port. It never provisions authority or changes capability grants. Re-run after a container restart; a Colab notebook runtime is not permanently running merely because its state is mounted.

## Read-only capability health and existing binding renewal

Run `python -m tools.inspect_live_capabilities --state "$EG_STATE_DIR" --manifest /path/to/protected/catalog/manifest.json --task-id "$EG_TASK_ID"` to verify the canonical gateway, immutable task checkpoint, audit chain, pinned operator public root, signed registry binding TTL, and fresh worker challenge for each typed E3/E4/E5 catalog entry. It never submits PRE, issues an approval, executes an effect, or marks a task verified. Listed capabilities can be **UNAVAILABLE** when their signed operator binding expires. Do not equate `MATCHED_LIVE_PRE_REQUIRED` with `VERIFIED_PASS`.

For an existing operator-authorized binding, `python -m tools.renew_operator_binding --binding /path/to/binding.json --operator-key /protected/operator.pem --registry /protected/registry --operator-public-key "$EG_PINNED_OPERATOR_PUBLIC_KEY_B64" --ttl-seconds 3600` reissues the **same** adapter, capability digest, socket, peer UID and worker key. It requires the existing protected operator key, verifies the old signature, and performs a fresh signed worker probe. No operator scope, task, or action approval is added. Renew before expiry where possible; a different signer/adapter requires separate explicit provisioning.

## Host identity neutrality

Portable gateway init.sh and run.sh support root and non-root host accounts. Explicit single-host mode is also available for a typed E3–E5 process catalog, without claiming separate OS security domains. Host identity alone does not authorize an effect: task registration, PRE, valid execution receipt, POST and independent verification remain mandatory. High-effect policy and authorization still apply. State must remain outside source with private permissions.

## Installation preflight (read-only, any supported host)

Before changing a new installation, run `PYTHONPATH=eg python3.12 -m tools.install_preflight --root /path/to/eg_portable` from the repository root. It prints JSON with explicit `SOURCE`, `PYTHON`, `EXTERNAL_STATE`, `DURABLE_STATE_EXISTS`, `HOST_IDENTITY`, `MODE`, `NOTARY_ROOT`, `EXECUTOR_ROOT` and `FULL_ADMISSION` checks. Exit 2 identifies missing prerequisites without producing keys or changing state. This is not a substitute for a protected operator bootstrap or live E0/E2/E3–E5 acceptance; a passing preflight never means capabilities are operational.

## Resolve actual state, never copied defaults

Discover from the owner's active environment: `EG_STATE_DIR` (durable external
database, evidence and anchor), `EG_RUNTIME_ENV_FILE`, `EG_LIVE_URL` (actual
loopback endpoint), `EG_TASK_ID`, task contract, source release SHA, current
checkpoint, admission mode and protected executor `output_root`. Authenticate
GET /health, /v1/audit/verify, /v1/tasks/{task_id}/state and task detail
before any plan or mutation. Never log keys or infer a fresh instance from
the previous Colab path. Missing database/signing roots are blockers.

The source evaluator's default is `EVALUATION_GATEWAY_ADMISSION_MODE=enabled`
when unset. This is **not** a worker-attestation or PRE authorization default:
read `/v1/agent/capabilities` and the real worker before claiming any effect.
Operators may select `disabled` for a separately designated audit-only
service. The generated portable `init.sh` accepts this explicit mode without an
executor public key, **but still requires** a valid independently administered
notary public key. Root and non-root host accounts are supported. It writes the audit-only setting into
the runtime env. This never enables E0/E2/E3–E5 physical effects. Full acceptance
still requires independent authorized workers and signed admission for each
supported/authorized target. See [operations](OPERATIONS.md#safe-historical-task-migration).


## Software, protocol and receipts

| Identity | Authoritative source | Rule |
| --- | --- | --- |
| Software | `eg/VERSION` | Stable tag with exact-SHA CI success |
| Protocol | SHA-256 of `docs/EXECUTOR_PROTOCOL.md`, `GET /v1/protocol` | New intake binds current digest |
| Historical task contract | Original signed TASK_INTAKE event | Never re-hash/rewrite original task |
| Evidence manifest | Signed v4 envelope | Verify original criterion bindings |
| Execution receipt | Signed, independently keyed envelope | Bind step, PRE, target, action and output |

Changing the current protocol file changes its digest for *future* tasks.
An existing registered task retains the original authenticated hash while
the current hardened evaluator remains authoritative; no legacy evaluator or
retroactive approval is enabled.

## Mandatory step-by-step lifecycle — staging is included

**REGISTER → PRE → verified authorization → independent executor → signed
receipt → POST → VERIFIED → next step**.

1. Register acceptance, dependencies and a complete hierarchy *before*
   effects. Identify the current canonical step, immutable task contract,
   current checkpoint and valid permissions.
2. PRE must verify phase-appropriate evidence, capability, target and bounds,
   exact payload SHA-256/size for new E2 writes, sandbox and rollback proof.
   No READY gate means no new action.
3. Execute exactly once through the independent registered worker and
   maintain its durable intent and receipt. On a lost response, reconcile
   the latest ledger/gate/journal/target before attempting anything again.
4. POST verifies the exact original PRE, signed executor receipt (for any
   action), and independent result evidence. UNVERIFIED means no advancement
   and no renewed effect; never replace it with a second PRE.
5. Proceed only when step is VERIFIED. Full SATISFIED additionally requires
   task-global acceptance and authenticated audit chain PASS.

No staging action is exempt from this lifecycle.

## Cutover and rollback

Current built-in worker supports bounded E0 reads, E2 new-file creation and SHA-256 compare-and-swap E2 replacement only;
real-world service cutover/E3 and shell remain BLOCKED until a separately
trusted, deployed executor adapter is admitted. The isolated disposable E3–E5
CI-only adapters are regression fixtures, not production service transports. Replan into bounded steps only
if each step actually uses a supported capability; never mislabel E3 as a
logical check to bypass admission.

A permitted cutover project separately verifies baseline, transactionally
consistent SQLite and external-anchor/evidence backups, restore rehearsal,
single-writer transition, runtime health and authenticated ledger continuity,
and documented rollback. Each mutation still needs PRE, execution receipt,
POST. Backup checksums or a self-reported owner PASS alone do not prove the
effect or mark the EG step VERIFIED. Issue #14 delivered independent archive
provenance and isolated restore rehearsal; neither proves a live production cutover.

## Timeout, pause and UNKNOWN effects

A delivery timeout is not a failed execution. Re-read the original event,
gate, task checkpoint, worker journal, signed receipt and target before any
retry. A sealed valid receipt may be recovered read-only without replay.
Keep uncertain effects in RECOVERY_PENDING.

**Implemented reconciliation (#6):** the protected worker may independently
sign `NOT_EXECUTED` only after checking the original gate, durable journal,
and actual target. Submit that proof via `/v1/tasks/{task_id}/reconcile`;
this consumes the old gate without verifying the step and permits a fresh
PRE. A sealed original receipt must instead be recovered for an executed
effect. Missing acknowledgement alone is never proof of no effect. UNKNOWN
remains BLOCKED.

## Historical examples and release verification

Historical cutover snapshots are available through Git commit history, not active release files. Neither an old report nor a prior operator decision is a current task ID, live deployment checkpoint, or permission to skip verification on another installation.

A validated GitHub release requires regressions, signed worker E2E, remedial
E2E, SHA-256 archive build, offline relocation and clean Debian startup on
its exact commit. Source release success is not evidence of live production
admission.


## Reconciled execution and independent cutover evidence

New `REGISTER` payloads MUST set `execution_required` explicitly on each
plan step. Execution-required steps MUST also declare `preconditions` distinct
from `acceptance_criteria`; immutable `invariants`, when supplied, are
checked in both PRE and POST. A physical step cannot be recast as logical by
omitting `action` at evaluation. Historical registrations are not rewritten.

When a reversible E2 write is interrupted, use the *same registered worker*
`reconcile_no_effect` operation (not the normal WRITE RPC). It checks the
canonical `RECOVERY_PENDING` gate, protected journal and target. Absent
journal/target yields a signed `NOT_EXECUTED` proof. A durable journal without
an output can be retired under the worker lock while preserving its bytes;
the proof can then be submitted to
`POST /v1/tasks/{task_id}/reconcile` with the exact action and pinned executor
public key. EG consumes the old gate in an append-only event, does NOT advance
step acceptance and requires a fresh PRE. A created target is recovered with
the original worker receipt, never replayed. Ambiguous or foreign journal /
target remains blocked; no HITL flag turns UNKNOWN into NOT_EXECUTED.

For independent cutover verification, provide an externally signed
`--cutover-attestation` and a separately provisioned
`EVALUATION_GATEWAY_CUTOVER_PUBLIC_KEY_B64`. The attestation binds report hash,
rollback archive hash, canonical checkpoint/audit head and all restored member
hashes. The verifier performs an actual isolated extraction and byte readback;
missing or changed evidence is denied. The attestor key must not be supplied
by the report or the agent controlling it. This is verification of the
reported cutover evidence; it does NOT authorize an unsupported E3 service
cutover, restore a historical Colab session, or waive the independent EG
step/capability/runtime checks for a new deployment.


## Bounded cutover archive verification

The read-only cutover checker hashes rollback archives incrementally and refuses
archives larger than `EG_CUTOVER_MAX_ARCHIVE_BYTES` (default 2 GiB, hard ceiling
8 GiB). Isolated restore rehearsal refuses more than
`EG_CUTOVER_MAX_RESTORE_BYTES` of declared or actual extracted files (default
4 GiB, ceiling 16 GiB), and more than `EG_CUTOVER_MAX_ARCHIVE_MEMBERS`
(default 10,000, ceiling 100,000). Invalid or zero budgets are rejected.
Archives are processed with bounded-size buffers and member enumeration limits,
never by loading the full archive into RAM. These budgets are **admission
limits**, not proof that real production cutover occurred. Resource control on
the isolated host (disk quotas, time limits, process isolation) must still be
supplied by the operator.

## Independently managed evidence-notary key rotation

The EG service **never** creates, stores, or mounts the notary private key.
The notary process runs in a separate signer UID/security domain. Portable
initialization requires `EG_NOTARY_PUBLIC_KEY_B64` and accepts only its public
32-byte Ed25519 root. Keep the active producer separate from the executor key.

To rotate an existing notary without rewriting old signed evidence, set the
active `EVALUATION_GATEWAY_EVIDENCE_PUBLIC_KEY_B64` to the **new** notary
public root, and supply the retired root with an explicit trusted cutoff:

```sh
EVALUATION_GATEWAY_LEGACY_NOTARY_KEYS_JSON='[{"public_b64":"RETIRED_PUBLIC_KEY_BASE64","valid_before":1780000000}]'
```

The cutoff is a Unix epoch second selected from verified rotation evidence;
the number above is illustrative and **not** an operating default. The gateway
accepts old cryptographic signatures only when their signed `finished_at`
is at or before that cutoff. Invalid, duplicate, active-key-equal, or
executor-key-equal legacy public roots are rejected at startup. Maximum eight
historical roots. A retired private key must be disabled and separately
destroyed according to owner procedure, never copied into the EG process.

**Important:** this preserves historical *verification*, not authorization
to perform a new action or to retroactively certify a past action. Historical
TASK_INTAKE, evidence bytes, audit entries, and external anchors stay unchanged.
Root rotation is a governed sensitive operation; test signed PRE/POST evidence
and audit integrity on a fresh isolated instance before deployment.

## Operator-controlled bounded source creation

A protected E2 worker can create (but never overwrite) small source files in its isolated, private, single-level output root. EG defaults to `.txt,.json` for backward compatibility. For a project that legitimately creates other source types, the operator must set the following matching policy before starting new physical tasks:

```sh
# Gateway process environment, configured by the operator
EVALUATION_GATEWAY_EXECUTOR_ALLOWED_SUFFIXES=.txt,.json,.py,.rs,.toml
```

In the independently privileged worker's private JSON configuration, set `"allowed_suffixes":[".txt",".json",".py",".rs",".toml"]`. The worker still enforces the approved root, exact precommitted payload digest and length, exclusive no-follow creation, durable journal, signed receipt, and independent readback. Nested project targets are permitted only within **pre-created, worker-UID-owned, 0700 private** subdirectories; the worker rejects symlink ancestors, missing directories and traversal. The operator must provision those directories through an independently governed process. The worker never creates directories implicitly, so this feature does not claim to govern workspace provisioning. Do **not** treat a suffix opt-in as approval to run a script, compile, overwrite, control a service, or push to GitHub; those require independently provisioned and authorized execution adapters. A mismatch between EG and worker policies must fail closed at the worker, never fall back to an ungoverned shell. Invalid suffix entries are rejected at startup.

## Governed agent entrypoint (currently E0/E2)

`tools/governed_agent_dispatcher.py` is a **library interface for a separately
trusted dispatcher**, not a general terminal or a shortcut around EG. It only
forwards the exact registered E0/E2 action to the independent Unix-socket
worker after checking current task, executable READY PRE, original action
fingerprint, and unexpired lease. The worker independently repeats its own
EG checks and signs only after real execution and readback. The dispatcher
verifies the receipt's independent executor signature.

The dispatcher returns `RECEIPT_VERIFIED_POST_REQUIRED`, **never**
`VERIFIED`. The agent must submit that exact signed receipt and fresh result
evidence via EG POST before advancing the task. When PRE is absent, the action changes, execution is paused or recovery is unknown, or no independently
provisioned external adapter matches E3–E5, the dispatcher refuses the call. HITL alone cannot add executor capability.

Provision the dispatcher itself under a protected identity with access to
the worker socket and narrow EG API credentials. Do **not** give an untrusted
agent direct access to the worker socket, signer key, EG API keys or an
unrestricted host shell. CI exercises actual signed-worker E2E across
physical registered steps, negative admissions and a separate untrusted UID
attempting to connect directly to the worker socket.

This protects **only the adopted, controlled entrypoint**. It cannot
intercept commands from an external host-root agent, a free shell or an
unconnected scheduler; such systems need their own isolation and EG adaptor
before claiming mandatory end-to-end enforcement. Staging, remediation, and
recovery remain subject to the same registered PRE/POST rules.

## Compose deployment for an independently administered adapter

Default `docker-compose.yml` deliberately does not enable external E3–E5 adapters.
For a separately deployed worker that meets the independent-identity and
signed-HITL requirements, an operator can opt in using:

```sh
docker compose -f docker-compose.yml -f docker-compose.external-adapter.yml config
docker compose -f docker-compose.yml -f docker-compose.external-adapter.yml up -d
```

The override requires `EVALUATION_GATEWAY_EXTERNAL_ADAPTER_UID`,
`EVALUATION_GATEWAY_HIGH_EFFECT_CAPABILITIES_JSON`,
`EVALUATION_GATEWAY_HITL_PUBLIC_KEY_B64`, and
`EVALUATION_GATEWAY_EXTERNAL_ADAPTER_SOCKET_DIR`. The latter must be a
dedicated, operator-controlled directory containing `effect.sock`, accessible
to the EG container UID only with the necessary permissions. The worker and
its signing key must run outside the gateway container and outside the
untrusted agent's privilege domain. This override does **not** start a worker,
create HITL signatures, guarantee availability or grant any PRE. If the worker
or keys are absent, keep E3–E5 unavailable; never mount the Docker daemon
socket or share a private signing key.

## Portable high-effect boundary
The bundled execution worker remains E0/E2-only. EG now exposes a generic,
**operator-opt-in** E3–E5 adapter admission/dispatch contract without embedding
Cargo, Git, Rust, Python or arbitrary shell permissions. For external work,
provision independent worker UID/socket/key, typed effect capability and
separate signed HITL authority; pin every original PRE, signed live
challenge, action fingerprint, scope, immutable receipt and POST. Use the unified `dispatch_action` and operator-signed worker registry; the
registry can select exactly one active matching adapter without per-task
socket/UID parameters. Explicit external-worker routing remains available for
independently provisioned policy. The reusable bounded process catalog
(`trusted_process_catalog.py`) implements **E3, E4 and E5** with the same
worker code, 1–32 pinned actions per class-bound adapter, and shared
identity/socket/journal within that adapter. Independent operator policies
select `effect_class` and `action_type`; E4 requires reversible actions and
separately authorized correction, E5 requires irreversible actions and cannot
be compensated. No provider-specific executor module is needed. No external production
permission is bundled: the CI-only disposable fixture is not eligible for
production promotion. Authentication, worker isolation,
durable journals, real effects, recovery and independent readback remain
operator-adapter obligations.

Authenticated `GET /v1/agent/capabilities` now includes the scoped E3–E5
registry's diagnostic availability. An external entry marked
`EXTERNAL_LIVE_PRE_ATTESTATION_REQUIRED` indicates **only** potential
capability: it is not an authorization, liveness proof or worker launch.
The exact PRE and worker attestation determine eligibility for execution.
