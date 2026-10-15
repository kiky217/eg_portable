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
