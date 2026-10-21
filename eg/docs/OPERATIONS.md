# EG operations — unified canonical deployment

**One EG registry, one protocol, one runtime.**

- Install or extract the Linux/amd64 offline artifact from the single eg/
  source tree. No auxiliary `portable/bin` scripts are required.
- Require a nonroot identity, durable external `EG_STATE_DIR`, owner-protected
  credentials and evidence-notary trust root, and independently protected
  trusted-executor public root. Never store private executor keys in the
  same security domain as the agent.
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

On a host with no independently administered trusted executor, set
`EVALUATION_GATEWAY_ADMISSION_MODE=disabled` and leave the executor public
key unset. The service can verify historical ledgers, but EVERY concrete
PRE/POST action is denied with
`TRUSTED_EXECUTOR_UNAVAILABLE_FAIL_CLOSED`. This is not production-ready
execution. Move signing/execution to a separate root-privilege domain before
allowing `ADMISSION_MODE=enabled`; never generate a dummy public key to
pretend a remote executor is configured.

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
anchor. A temporary nonroot EG process runs the current canonical code only
against that COPY, using `ADMISSION_MODE=disabled`. It authenticates the
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
authorized execution → signed POST → VERIFIED. Unsupported E3 cutover remains
BLOCKED without a separately verified capable worker; direct shell is not a
fallback.

The dated Colab 2026-10-15 owner-accepted cutover is documented in
[ACCEPTANCE_POST_CUTOVER_20261016.md](../artifacts/ACCEPTANCE_POST_CUTOVER_20261016.md).
That historical addendum is retained, not an order to skip new cutover steps,
and never changes its original 12/16 VERIFIED canonical task ledger.

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
POST acceptance. Issue #14 remains open pending such evidence.
It writes only a new report file (0600), refuses overwrites, and does not
expose secrets. A result of `BLOCKED` is not an EG task mutation.

The script **never** asserts signer isolation from a public key, a UID change
or a QEMU guest sharing the same host root. A separate, verifiable root
security domain is required. An expired PRE with no observed action requires
a new PRE after native executor admission; an effect already present instead
requires reconciliation, not re-execution or a retrospective receipt.

## E3–E5 operational limits
The portable package does not automatically provision production E3–E5 workers.
An operator can register multiple independent signed worker bindings using
`EVALUATION_GATEWAY_EXTERNAL_REGISTRY_DIR` and
`EVALUATION_GATEWAY_EXTERNAL_REGISTRY_OPERATOR_PUBLIC_KEY_B64`, then enable
`EVALUATION_GATEWAY_EXTERNAL_ADAPTER_MODE=enabled` with typed capabilities and
a separate HITL trust root. Canonical PRE checks each worker's live identity;
the agent dispatcher reuses active bindings without per-task socket/UID entry.
Do not treat
`EVALUATION_GATEWAY_HIGH_EFFECT_CAPABILITIES_JSON` as a liveness/privilege
attestation or set an in-process CI-only dispatcher as production transport.
Only authenticated original-gate PRE signing roots may validate subsequent
E3–E5 POST or no-effect reconciliation; absence of a trustworthy root is BLOCKED.
