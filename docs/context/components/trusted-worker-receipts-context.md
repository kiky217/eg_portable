# Bounded trusted worker and signed receipts

**Source:** [trusted_execution_worker.py](../../../eg/tools/trusted_execution_worker.py), [execution_receipts.py](../../../eg/app/execution_receipts.py), [no_effect_receipts.py](../../../eg/app/no_effect_receipts.py), and [executor_policy.py](../../../eg/app/executor_policy.py). See [system design](../architecture/system-design.md).

## Purpose

Turn an exact, already authorized canonical PRE into **one** bounded physical file effect, preserve durable intent, validate the result and return an independently signed receipt. The worker is separate from the untrusted agent/controller; one AI agent can orchestrate the workflow without becoming its own signer.

## Supported operations

| Operation | Worker scope |
| --- | --- |
| `read` | Bounded existing regular file in private `output_root`; signed observed bytes |
| `write` | Exclusive creation: no overwrite, approved target/suffix and committed payload |
| `replace` | Existing worker-owned regular file; exact prior SHA-256 commitment and controlled replacement |

Max content: **512 KiB**. Default suffixes: `.txt` and validated `.json`; operator-approved language extensions require matching trusted worker and EG configuration. They **do not** grant shell execution, arbitrary path access, Git push or service control. Other effects may appear as historical/configured metadata but are not part of the canonical bundled worker.

## Key interaction and durability

1. The worker re-reads authenticated canonical task detail/state and original READY PRE; validates the exact step, action fingerprint, target path, lease and configured privileges.
2. For a new mutation, writes a durable intent journal **before** the target effect and enforces safe file/parent handling.
3. Reads back the actual result, signs an Ed25519 execution receipt binding task, step, PRE checkpoint, action fingerprint, target, output digest/size and nonce, then seals the journal.
4. If the POST response fails after the effect, a matching previously **sealed** receipt may be recovered; never dispatch a second physical write to fix a lost response.
5. Original POST evidence remains an independent input checked by the EG evaluator; receipt alone is not task verification. For confidently unexecuted effects the separate no-effect reconciliation proof follows the canonical `/reconcile` contract.

## Operating and security constraints

- Worker serving mode forbids root execution; keep worker signing keys and journal under separate, protected OS identity and Unix-socket access control.
- No service credentials, private keys, internal output data or worker sockets belong in Git.
- Duplicate, stale, symlink, mismatched payload or unknown-effect states must fail closed.
- [runbook](../../../eg/docs/PORTABLE_RUNBOOK.md) governs installation and signed recovery; [SKILL](../../../SKILL.md) governs operator/agent steps.

## Verification evidence

- [test_real_physical_pre_post_e2e.py](../../../eg/tests/test_real_physical_pre_post_e2e.py)
- [test_worker_sealed_recovery.py](../../../eg/tests/test_worker_sealed_recovery.py)
- [test_nested_workspace_bounds.py](../../../eg/tests/test_nested_workspace_bounds.py)
- [test_no_effect_reconciliation.py](../../../eg/tests/test_no_effect_reconciliation.py)

These exercise a disposable test domain; they do **not** prove an unrelated deployment is configured or authorized.
