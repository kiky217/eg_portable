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
passed. The live upgrade still requires independent executor trust, a
quiesced single-writer transaction, checked rollback, and authenticated
post-cutover state and anchor verification.

## Read-only canonical cutover blocker check

Before a cutover or any further POST for a pending concrete action, run:

```sh
python -m tools.check_live_cutover_readiness \
  --db "$EG_STATE_DIR/data/gateway.db" \
  --task "$CANONICAL_TASK_ID" \
  --live-url http://127.0.0.1:18765 \
  --runtime-env-file "$EG_RUNTIME_ENV_FILE" \
  --report "$READINESS_REPORT_JSON"
```

This tool makes read-only DB and authenticated GET calls, compares the live
checkpoint, gate, fingerprint and audit count, and checks the 300-second new
effect authorization lease against the original PRE timestamp. It verifies
whether the concrete target already exists, but does not replay or create it.
It writes only a new report file (0600), refuses overwrites, and does not
expose secrets. A result of `BLOCKED` is not an EG task mutation.

The script **never** asserts signer isolation from a public key, a UID change
or a QEMU guest sharing the same host root. A separate, verifiable root
security domain is required. An expired PRE with no observed action requires
a new PRE after native executor admission; an effect already present instead
requires reconciliation, not re-execution or a retrospective receipt.
