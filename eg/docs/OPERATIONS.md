# EG operations — unified canonical deployment

## Canonical installation and step verification

**"Install EG completely as a generic system and test it end-to-end until every supported, authorized capability is operational."**

**Required for every installation, including staging:** Follow [SKILL](../../SKILL.md) and the [runbook](PORTABLE_RUNBOOK.md). Register before work; verify PRE, execution receipt and POST for each action. The bundled worker supports bounded file reads, exclusive creation and verified replacement. Optional bounded process execution uses a reusable generic adapter, independently provisioned under the operator's policy.

**Mandatory acceptance:** For every admitted file operation, demonstrate **REGISTER → PRE → bounded execution → original signed receipt → fresh POST → VERIFIED → SATISFIED**, including evidence readback, denied operations and recovery. The rule applies to staging. CI, `/health`, source builds and listed capabilities do not prove a task completed.

**Fail closed:** Missing task registration, matching bounded operation, trusted signer, original PRE, valid receipt or independently verified POST means **INCOMPLETE / BLOCKED**. Do not fabricate keys or claims and do not use a direct shell to turn an unsupported operation into EG-verified work.

**One EG task registry and one active writer per durable state.** Different authorized host UIDs can run isolated EG instances concurrently with distinct state, audit anchor, evidence root, port and worker configuration.

**Actual admission default:** `eg/app/main.py` uses
`EVALUATION_GATEWAY_ADMISSION_MODE=enabled` when the variable is unset.
Preserve this default unless the operator explicitly selects an audit-only
instance. `enabled` alone is **not** physical execution readiness: the read/create/replace
worker also needs an operator-provisioned output root, distinct protected signer,
active trusted RPC transport, original READY PRE and signed POST. Without these,
`GET /v1/agent/capabilities` can correctly return `UNAVAILABLE` while
`GET /health` and authenticated `/v1/audit/verify` return `PASS` with
`admission_mode=enabled`. Do not enable an untrusted worker to change that status.


- Install or extract the Linux/amd64 offline artifact from the single eg/
  source tree. No auxiliary `portable/bin` scripts are required.
- The portable gateway accepts an authorized root or non-root host identity.
  The bundled generic worker also accepts either root or non-root. Do not reject a legitimate host UID by itself; verify the actual signer custody, scoped worker permissions, PRE and signed POST separately. If the gateway controls a root-owned worker and its key, independent signer isolation is not proven by that deployment.
  Use durable external `EG_STATE_DIR`, protected credentials, notary and
  executor public roots. Root access to a host does **not** prove signing-key
  independence; keep private signing keys outside the agent's control.
- Use the bundle's `init.sh` once and `start.sh` thereafter. Both refuse
  unsafe modes. The same code defines the API, ledgers and evaluation logic.
- Back up the SQLite database *transactionally* with its verified external
  audit anchor and sealed evidence; a WAL-only or live-file copy is not
  sufficient. Enforce integrity verification on restore and before admission.
- Deploy new code with a single-writer cutover: no concurrent EG instances
  pointing to one database/anchor. Perform immutable task-state and head
  comparison before and after. If the original task contract's protocol hash
  cannot be honored without weakening validation, fail closed instead of
  modifying historical contracts.
- All work and repair executed by agents must pass EG gate and signed POST.
  Partial/UNKNOWN effects require reconciliation, not blind replay.
- Unsupported OS, action class, missing protected worker, invalid receipt,
  inaccessible durable store, or failed audit are blockers—not success.

**Security boundary:** user-space policies cannot intercept arbitrary commands
run by a host-root agent. Secure deployment requires moving the effective
execution identity outside the agent's root privilege domain. Colab host root
is currently not a provably isolated production target.

## Safe historical task migration

Existing task contract hashes remain immutable; the single EG evaluator
checks the protocol hash originally authenticated in the TASK_INTAKE event
and applies CURRENT receipt and audit validations without dispatching any
previous evaluator. New registrations must use the current protocol hash.

For a separately designated **historical/audit-only** instance, set
`EVALUATION_GATEWAY_ADMISSION_MODE=disabled` **before** invoking the generated
portable `init.sh`. The installer now accepts an empty executor public root in
this explicit mode, while still requiring a valid independent evidence-notary
public root. Root or non-root host identity is allowed, subject to protected
state and signer boundaries. It persists `disabled` to `runtime.env`; the
service must continue to deny concrete PRE/POST effects.
The default `enabled` mode still requires a genuine independently provisioned
executor public root. Audit-only readiness is **not** full capability acceptance.
Missing authorization for a supported operation remains a blocker until it is configured and independently verified. Never invent signing keys or mark an incomplete task satisfied.


## Rehearse migration without cutover

The canonical, read-only rehearsal is `tools/rehearse_ledger_migration.py`.
Run with explicit source paths and task IDs from the administrative host:

```sh
python tools/rehearse_ledger_migration.py \
  --db "$EG_STATE_DIR/data/gateway.db" \
  --anchor "$EG_STATE_DIR/anchor/audit.anchor" \
  --evidence "$EG_STATE_DIR/evidence" \
  --runtime-env-file "$EG_STATE_DIR/runtime.env" \
  --historical-task "$HISTORICAL_TASK_ID" \
  --open-task "$MIGRATION_TASK_ID" \
  --uid "$EG_RUNTIME_UID" --gid "$EG_RUNTIME_GID" \
  --report "$REPORT_PATH"
```

The rehearsal uses a transactionally consistent SQLite copy and a copied
anchor. A temporary EG process runs under the operator-selected authorized
host identity against that COPY, using `ADMISSION_MODE=disabled`. It authenticates the
historical SATISFIED task and in-flight gate, checks audit integrity, and
proves that concrete actions without an independently protected executor
fail closed with HTTP 409. It verifies the source ledger and anchor are
unchanged, closes the temporary process, and never writes to the live EG.
The report contains no secret keys. A report path that already exists is
rejected rather than overwritten.

A successful rehearsal is **not** production cutover or approval of a
host-root-controlled signer. Never treat the staging process as a second
production EG, and never mark migration VERIFIED merely because a rehearsal
passed.

## Current operations and archived migration

For current source/runbook use [PORTABLE_RUNBOOK.md](PORTABLE_RUNBOOK.md).
Every staging and cutover mutation still requires REGISTER → PRE → independent
authorized execution → signed POST → VERIFIED. Service cutover remains outside the canonical gateway operations; direct shell is not a fallback.

Historical acceptance snapshots have been removed from the active source tree; Git commit history retains provenance. No previous cutover report or partial historical task acceptance authorizes a new deployment. Reconcile the actual target's signed task ledger.

## Read-only canonical cutover blocker check

Before a cutover or any further POST for a pending concrete action, run:

```sh
python -m tools.check_live_cutover_readiness \
  --db "$EG_STATE_DIR/data/gateway.db" \
  --task "$CANONICAL_TASK_ID" \
  --live-url "$EG_LIVE_URL" \
  --runtime-env-file "$EG_RUNTIME_ENV_FILE" \
  --cutover-report "$EG_COMPLETED_CUTOVER_REPORT_JSON" \
  --report "$READINESS_REPORT_JSON"
```

This tool makes read-only DB and authenticated GET calls, compares the live
checkpoint, gate, fingerprint and audit count, and checks the 300-second new
effect authorization lease against the original PRE timestamp. It verifies
whether the concrete target already exists, but does not replay or create it.
For a completed cutover, provide the original cutover report: its archive and
backup digests must still match and its recorded ledger head must survive at
the corresponding historical audit sequence. This checks reported historical continuity, **not** independent archive
provenance, a complete restore rehearsal, executor admission, or EG signed
POST acceptance. Issue references and closed historical reports are not a substitute for live task state.
It writes only a new report file (0600), refuses overwrites, and does not
expose secrets. A result of `BLOCKED` is not an EG task mutation.

The script **never** asserts signer isolation from a public key, a UID change
or a QEMU guest sharing the same host root. A separate, verifiable root
security domain is required. An expired PRE with no observed action requires
a new PRE after native executor admission; an effect already present instead
requires reconciliation, not re-execution or a retrospective receipt.

## Current operational scope
The canonical gateway admits bounded reads, exclusive file creation and verified replacement. Old external process bindings and catalog workers have been retired from this installation. Refer to [the portable runbook](PORTABLE_RUNBOOK.md) for ordered step verification, audit, recovery and migration.
