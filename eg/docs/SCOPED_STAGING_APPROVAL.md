Operator standing approval is generic and targets a signed scope, not a provider. One standing policy can cover many already-provisioned process catalog profiles; it never permits arbitrary shell. See [Generic execution model](GENERIC_EXECUTION_MODEL.md).

# One agent, bounded standing E3 staging approval

A task does **not** need a second AI agent to supply every signed HITL envelope.
An authorized human/operator may provision a **separate, non-AI signing process**
with a short-lived, narrowly scoped standing policy. The policy is authority
granted at installation; it is *not* an agent's self-approval or a claim that a
human reviewed each action.

This optional process implements **E3 bounded_process_run in staging only**.
All of EG's requirements remain: registered task, original action-bound PRE,
a distinct admitted executor, nonce no-replay, independently signed execution
receipt, result evidence and canonical POST. The approval *never* completes
a step.

## Operator installs once

Run `python -m tools.operator_scoped_approval /private/approval.json` as a
**dedicated non-root signer UID**, distinct from the agent/controller and E3
worker. Independently create an Ed25519 signer key in a regular, owner-only
`0600` file, not inside the project tree. The operator-only policy JSON (also
`0600`) contains:

| Field | Purpose |
| --- | --- |
| `key_file` | Protected Ed25519 private signer key path |
| `ledger_dir` | Private `0700` durable SQLite grant ledger |
| `socket_path` | Unix socket under signer-owned group-pinned `2710` directory |
| `controller_uid`, `controller_group_gid` | Exact agent OS identity authorized to request grants |
| `adapter_id` | Already provisioned, separate E3 adapter |
| `target_prefix` | Only targets below a specified `/tasks/...` scope |
| `expires_at` | UTC epoch seconds, no more than 24 hours from first-run |
| `max_grants` | Hard quota of 1–100 **distinct** step/action grants |
| `max_payload_bytes` | Maximum E3 action payload, 1–524288 bytes |

The worker socket uses `0660` access only within the group-pinned directory;
every request is additionally checked with Linux `SO_PEERCRED`. The agent has
**no read access** to the signer key, approval database or worker signing key.
The signer may not run as root. After a process crash, a restart may reclaim only a stale socket owned by the signer while holding an exclusive worker-owned lock. A live listener, a symlink, an untrusted socket or a second concurrent signer is never overwritten. The durable grant ledger persists across restart; retries reuse the exact same sealed nonce.

The operator must separately provision/activate the E3 worker and register
the matching public HITL key with EG. No credentials, UID, private signing
material or admission privileges are auto-created for the agent.

For repeatable setup, the authorized root operator can create the signer identity
files, ledger, and socket directory in **one installer command** once the
independent Linux UIDs already exist. This is not run by the AI agent:

```sh
sudo python -m tools.provision_scoped_signer \
  --root /var/lib/eg/standing-generic \
  --signer-uid "$SIGNER_UID" --signer-gid "$SIGNER_GID" \
  --agent-uid "$AGENT_UID" --agent-gid "$AGENT_GID" \
  --adapter-id trusted-adapter-workflow --target-prefix /tasks/workflow
```

The installer rejects existing target directories and insecure parents. Its JSON
output contains the public root, protected config location, socket address and
separate-UID start command; **never** the private key. The operator must still
start that service under the signer UID and register its public root with EG.
Use distinct, existing OS identities—do not invent common hardcoded UIDs on
real hosts.

## Agent usage

The agent asks the Unix socket for an approval containing only
`task_id`, `step_key`, `gate_checkpoint_no`, and the *complete intended action*.
The signer independently derives the canonical action fingerprint. Only
`E3/bounded_process_run`, targets within the preapproved staging prefix,
payloads below the operator's limit and unexpired grants receive a short-lived
Ed25519 signature.

The exact same request gets the **same sealed nonce** on retries; one gate
cannot be reissued a new grant after its original grant expires. The admitted
worker still consumes that nonce durably **once**, before execution.

If a request falls outside the signed standing authority, the result is
`DENIED`, **not** a suggestion to disable admission or bypass the gateway.

Run the checks through
`tests/test_operator_scoped_approval.py` (non-root signer/agent, key denial,
identity pinning, scope and quota), and
`tests/test_process_external_e2e.py` (actual E3 café compilation/HTTP with
the same kind of grant, independent physical worker, signed PRE/POST).

**Not supported:** production approvals, unrestricted shell commands, automatic
service deployment or signed authority that has never been issued by the
operator. Issue #104 closed on local/staging engineering acceptance. Its closure does not authorize production deployment or remove the independent operator prerequisite.
