# Generic typed E3–E5 scoped standing approval

## MANDATORY FROM INSTALLATION — FULL CAPABILITY ACCEPTANCE

**"Install EG completely as a generic system and test it end-to-end until every supported, authorized capability is operational."**

**Required for every fresh installation and upgrade (including staging):** Read the [canonical agent SKILL](../../SKILL.md) first. Inventory **E0, E2, E3, E4, and E5**. Install the EG gateway and durable audit/evidence state, configure independently protected credentials and trust roots, bring the built-in E0/E2 worker online, and provision/register/activate the **generic** E3/E4/E5 process catalog workers and independently administered scoped HITL signers for every effect class and target profile the operator has actually authorized. Verify live socket/UID identity, signed operator binding, exact typed capability match, and liveness. **Do not build project-specific executor code or infer privileges from the presence of source code.**

**Mandatory acceptance for every authorized capability:** Demonstrate the original EG **REGISTER → PRE → independently authorized execution → signed receipt → POST → VERIFIED → task SATISFIED** with a real physical effect where applicable, independent result readback, and relevant denial, replay/idempotence, crash recovery, and rollback tests. High-effect signed HITL must be valid **before PRE admission**. **CI PASS, `/health: PASS`, source/build completion, and capabilities merely listed/configured are never proof of live E2E readiness.**

**Fail-closed completion rule:** Missing independent operator approval, worker/UID, signer, scoped policy, profile, credentials, registration, or live PRE/POST evidence means the requested full installation is **INCOMPLETE / BLOCKED**, not COMPLETED. Identify the exact prerequisite; never fabricate independent authority, self-approve, or bypass EG by running the effect directly. Generic means reusable implementations with **separately authorized privileges**, not an unrestricted shell.

One independently provisioned, non-AI signer can issue bounded approvals for
many already-approved process profiles under the same typed scope.
See [Generic execution model](GENERIC_EXECUTION_MODEL.md).

A task does **not** need a second AI agent to supply every signed HITL envelope.
An authorized human/operator may provision a **separate, non-AI signing process**
with a short-lived, narrowly scoped standing policy. The policy is authority
granted at installation; it is *not* an agent's self-approval or a claim that a
human reviewed each action.

This optional signer authorizes **E3 `bounded_process_run` only within the operator-pinned target scope and grant limits**. Its policy is environment-neutral; separate deployment authorization is still required for production changes.
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
the exact operator-pinned `effect_class`/`action_type` (E3, E4 or E5), targets within the preapproved target prefix,
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
`tests/test_process_external_e2e.py` (actual generic E3 HTTP and E4/E5 physical fixtures with
the same kind of grant, independent physical worker, signed PRE/POST).

**Not authorized automatically:** production changes, unrestricted shell commands,
service deployment or signing privileges outside the operator policy. A
valid scoped approval does not prove a live production executor or deployment. Issue #104 closed on local/staging engineering acceptance. Its closure does not authorize production deployment or remove the independent operator prerequisite.

## Typed E4/E5 signed policy scope

The same independent standing signer implementation accepts paired operator-provisioned `effect_class` (E3/E4/E5) and `action_type`; both are mandatory and no default effect class exists. Every requested action must exactly match both typed fields, the pinned adapter/target scope, payload digest/size, expiration and quota. E4 requires `reversible=true`. E5 requires `reversible=false`, has no compensation and must never be replayed. Signed approval remains an **operator-authorized and independently protected** boundary; an agent cannot mint signing keys or raise its own grants. Real-world irreversible operations require legitimately authorized operator policy appropriate to their risk.
