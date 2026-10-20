# Agent quickstart — production EG without false readiness

**First read [root SKILL.md](../../SKILL.md).** This is an operational entry point, not an alternate evaluator or an override of the canonical executor contract.

## Four separate readiness questions

| Question | Evidence |
| --- | --- |
| Is the software installed? | Exact version + release SHA; not necessarily running |
| Is EG running? | Actual endpoint, process and authenticated health/audit |
| Can EG admit a concrete operation? | Current `admission_mode`, trusted executor root and valid, fresh PRE |
| Can the operation happen? | Independently deployed adapter with exact supported action, isolation, durable journal, original signed receipt and POST |

`admission_mode=disabled` is explicitly a **historical/audit-only** mode for hosts without independently trusted execution. This is not equivalent to production execution. Enable admission only after the trust prerequisites are actually met. A public key without a separately protected private signer does not prove executor independence.

## Agent usability diagnostic

Run from repository root:

```sh
python eg/tools/agent_readiness.py --effect E2 --action write
python eg/tools/agent_readiness.py --effect E3 --action service_control --json
```

This command **does not perform network calls, mutate state, print secrets, or authorize effects**. It examines local environment presence and static built-in dispatcher support only. For the live decision, inspect the target system's authenticated task, health, evidence and worker status. Never copy configuration from a different instance.

## How to approach real development tasks

Break a real goal into registered steps only if each physical operation has an independently approved transport. Running `cargo build`, Rust source modifications, Git push, shell and service control are **not** a generic E2 write via the built-in worker. Implement and independently audit typed adapters with bounded permissions, action fingerprints, pre-execution scope, journal/idempotency, signed receipts and POST verification. Until provisioned, surface a precise missing-adapter diagnostic. Do not silently downgrade to a logical step, escape to host-root shell, or use disposable CI adapters in production.

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