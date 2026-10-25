# Agent quickstart — provider-neutral runtime and admission

See [Generic execution model](GENERIC_EXECUTION_MODEL.md). One independently
installed typed E3–E5 process catalog can serve many approved task targets.
Each effect class needs a matching independently authorized worker/policy,
not provider-specific source code.

**First read [root SKILL.md](../../SKILL.md).** For all supported API routes, exact request/response fields, operator/agent responsibilities and receipt recovery, follow the [agent operations reference](AGENT_OPERATIONS_REFERENCE.md). This is an operational entry point, not an alternate evaluator or an override of the canonical executor contract.

## Four separate readiness questions

| Question | Evidence |
| --- | --- |
| Is the software installed? | Exact version + release SHA; not necessarily running |
| Is EG running? | Actual endpoint, process and authenticated health/audit |
| Can EG admit a concrete operation? | Current `admission_mode`, trusted executor root and valid, fresh PRE |
| Can the operation happen? | Independently deployed adapter with exact supported action, isolation, durable journal, original signed receipt and POST |

The EG source default is `EVALUATION_GATEWAY_ADMISSION_MODE=enabled`.
Do not treat this default as evidence that any effect is admitted. The live
`/v1/agent/capabilities` response can report all built-in workers `UNAVAILABLE`
when there is no executor output root or active independently verified worker.
`admission_mode=disabled` is an **explicit historical/audit-only override**,
not the generic installation default. Even when `enabled`, require fresh
capability, signer and worker attestation, exact READY PRE and signed POST.
A public key without a separately protected private signer does not prove
executor independence. The current generated `init.sh` requires both executor
and notary public keys for **fresh bootstrap** in either mode; see
[operations](OPERATIONS.md#safe-historical-task-migration) for the documented
audit-only bootstrap limitation. Never manufacture a dummy executor key.


For an independently provisioned **E3–E5-only** instance, the built-in E0/E2 executor signing key is not required if no E0/E2 output root is configured. Read-only `adapter_onboarding.inspect_onboarding()` likewise only requires the independent notary, HITL, and external worker roots when no bundled E2 root is present. The external worker still needs its own distinct signing identity, approved capability, operator binding, separately signed HITL, and exact PRE/POST. When the built-in E0/E2 output root is configured, its own separate signing key remains mandatory; missing trust still fails closed.

## Agent usability diagnostic

Run from repository root:

```sh
python eg/tools/agent_readiness.py --effect E2 --action write
python eg/tools/agent_readiness.py --effect E3 --action service_control --json
```

Without `--url`, this command **does not perform network calls, mutate state, print secrets, or authorize effects**. Use `--url https://YOUR-EG` with operator-provided `EVALUATION_GATEWAY_API_KEY` to perform authenticated **read-only** runtime discovery. The live result is `REQUIRES_LIVE_PRE`, never an action grant; it cannot verify executor identity or a specific PRE by itself. For the live decision, inspect the target system's authenticated task, health, evidence and worker status. Never copy configuration from a different instance.

After one-time operator provisioning, the E0/E2 agent can call `dispatch_action()` without repeating `worker_socket` or the public signing key on every task. Set `EVALUATION_GATEWAY_WORKER_SOCKET` to the operator-installed socket and `EVALUATION_GATEWAY_EXECUTOR_PUBLIC_KEY_B64` to the actual trusted worker public key in the controller's environment. Both remain constrained by the original EG PRE, independently signed receipt and POST; this is a routing convenience, not an admission bypass.

For an independent non-root agent/controller to call the built-in E2 worker, the operator may set `controller_uid` and `controller_group_gid` in the existing worker configuration. Put the Unix socket in a worker-owned, group-owned private directory (`2710`) and ensure the controller belongs to that approved group. EG checks the exact Linux `SO_PEERCRED` UID on each connection and makes the socket group-writable (`0660`) only for that configuration; the default remains worker-private (`0600`). This does not grant execution rights beyond fresh PRE, receipt and POST. A working example is `tests/test_e2_controller_group.py`.

An authorized administrator can generate the separate non-AI worker/signer identities and signed operator binding with the [one-time staging bootstrap](ONE_TIME_STAGING_BOOTSTRAP.md). This is not self-admission by the AI agent. For a reusable operator-pinned E3–E5 process worker, see [one-time E3 process worker onboarding](OPERATOR_PROCESS_SERVICE.md). This requires an independent OS operator, not another AI agent. For repeated staging builds/tests under one preapproved scope, a separate [non-AI standing policy signer](SCOPED_STAGING_APPROVAL.md) can provide short-lived, exact-gate E3 approvals with a protected signer identity, durable nonce reuse and operator-defined limits; this never self-admits or approves production actions.

The minimal [single-agent workflow](SINGLE_AGENT_WORKFLOW.md) reuses EG's original REGISTER → PRE → independently signed execution receipt → POST → task acceptance path without another AI agent and without blind retries.

## How to approach real development tasks

Break a real goal into registered steps only if each physical operation has an independently approved transport. Running `cargo build`, Rust source modifications, Git push, shell and service control are **not** a generic E2 write via the built-in worker. First reuse the generic E3 process catalog and independent worker already authorized for the target. For a genuinely new operation, install an operator-approved bounded profile; do not add provider-specific Python adapters to core. Until provisioned, surface a precise missing-adapter diagnostic. Do not silently downgrade to a logical step, escape to host-root shell, or use disposable CI adapters in production.

## Portable execution architecture
EG is a portable governance/evidence engine; execution capabilities belong to independently governed adapters supplied by the target environment. The agent discovers available typed operations, matches action requirements and effect class, and chooses a trusted transport. Rust, Git, build systems and service APIs are examples, **not** capability names that EG should hardcode. Built-in E0/E2 behavior is a packaged baseline, not a universal ceiling. Missing operations require approved capability onboarding with scoped permissions, attestation, durable receipts, readback, and rollback as appropriate; no untrusted self-registration grants permission. The local static preflight evaluates only this package's bundled worker and cannot conclude that all external adapters are unavailable.

## Agent lifecycle

Read latest task and checkpoint → classify effect and capability → confirm live admission and independent worker → PRE → execute once → read back + signed receipt → POST → VERIFIED → next step.

After a timeout: read original request/gate/journal/target first. Existing effect: recover receipt, never duplicate. Proved no effect: reconcile and request fresh PRE. Unknown: keep blocked and report which independent evidence is missing.

## Status vocabulary

- `SOURCE/RELEASE PASS`: repository build/test successful, no live authority implied.
- `SERVICE PASS`: process/API reachable, not execution proof.
- `ADMISSION DISABLED`: no new concrete operations.
- `ADAPTER UNPROVISIONED`: no approved worker for the effect/action.
- `PRE READY`: fresh exact-gate authorization, **not execution**.
- `RECEIPT VERIFIED / POST REQUIRED`: action evidence pending canonical verdict.
- `VERIFIED`: canonical step passed, confirmed through authenticated state.

The environment's live protocol wins over copied examples. Never create a new task merely to escape an invalid old one without owner authorization.