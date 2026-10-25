# One-time E3–E5 typed process worker onboarding (operator-owned)

A **single AI agent** can plan a task and use EG; it does **not** need a
second AI agent. The executable performing a concrete effect is an ordinary
operating-system process under an independent worker identity. The first
installation still needs an authorized operator to provide distinct protected
signing identities and scoped execution policy. The agent **does not** create
its own trust root, approve itself, or substitute a local shell for EG.

The packaged `tools/operator_process_service.py` starts an existing, bounded
`TrustedProcessEffect` behind the generic UID-pinned Unix RPC service. It
supports **one or many operator-fixed executable/argument/target profiles**
under one independently signed identity, socket and durable journal. It does not support agent-supplied shell strings, arbitrary commands,
remote process control, or persistent server management. This worker can be
reused across tasks until the operator binding expires or is revoked.

## Provision once, before the agent starts

The independent operator must create separate non-root OS identities for the
EG controller, evidence notary, HITL signer, adapter registry and E3 worker,
with distinct protected Ed25519 private keys. Reuse the existing
[`operator_adapter_binding.py`](../tools/operator_adapter_binding.py) and
[`operator_runtime_registry.py`](../tools/operator_runtime_registry.py) signed
binding/activation contract; never register workers from an agent-selected
public key alone. The worker socket directory must be owned by the worker and
private, with an operator-approved controller group if the controller has a
different UID (`chmod 2710`; the socket itself becomes `0660`). Both Unix peer
credentials and the Ed25519 liveness challenge are checked before admission. A process restart after an abrupt interruption may recover a stale worker-owned socket only under its exclusive private lock; it must never overwrite a live listener. Existing durable nonce and signed receipt records are unaffected.

Run the worker as its dedicated non-root UID with an **operator-owned 0600**
JSON configuration file. Keys, the EG API credential, and the configuration
must each be regular owner-only files with no symlink. No secret is supplied on
the command line or stored in the Git repository:

```sh
python -m tools.operator_process_service /protected/worker.json
```

The config contains the following operator-selected values:

| Field | Meaning |
| --- | --- |
| `adapter_id`, `capability_sha256` | Exact signed typed capability identity |
| `socket_path`, `journal_dir` | Worker-private Unix RPC and durable nonce journal |
| `private_key_path`, `eg_api_key_path` | Owner-only files, not secret strings in JSON |
| `eg_url`, `hitl_public_key_b64` | Authenticated gateway and independent HITL authority |
| `controller_uid`, optional `controller_group_gid` | Allowed distinct OS controller identity |
| `executable`, `fixed_args`, `target` | Legacy single-target process policy |
| `profiles` | Alternative catalog (1–32 unique exact targets with fixed executable/args); reusable across projects |
| `profiles[].timeout`, `profiles[].max_stdout` | Bounded per-profile runtime (1–30 s) and output (max 512 KiB) |

The pinned executable and every ancestor directory must be owned by root or the independent worker, and must not be writable by unrelated users/groups. A binary under an attacker-replaceable temporary directory is rejected even when the binary itself has restrictive file permissions; inspect fixed arguments for scripts and other operator-controlled resources as well.

An E3 action then follows **registered task → fresh PRE → separately signed
HITL → active operator binding → UID-pinned worker → durable nonce claim →
fixed process effect → signed receipt → canonical POST**. Receipt delivery is
not completion. The agent reads back the current task state; the next step
remains closed until independent POST evidence passes. Crash after a durable
claim but before sealed receipt remains **UNKNOWN**, never automatically
replayed.

## What the agent can do

An agent discovers `/v1/agent/capabilities`, resolves a previously provisioned
adapter through the signed registry, and calls
[`dispatch_action()`](../tools/governed_agent_dispatcher.py) with the task's
original action and independently signed approval. With a signed operator
registry installed, omitting the adapter ID triggers authenticated read-only
typed/scope discovery: **exactly one active adapter** is selected or dispatch
fails closed without executing anything. The same dispatcher works for any independently provisioned typed external
adapter without adding project/provider branches to EG core. The bundled
process catalog implementation supports E3, E4 and E5 via operator-pinned
`effect_class`/`action_type`; it does not grant unspecified provider API writes.

If admission is disabled or no separately provisioned adapter exists, the
correct result is **NOT_ADMITTED / OPERATOR_PROVISIONING_REQUIRED**, including
which missing capability or trust is required. Do not silently set
`admission_mode=enabled` for an existing host, forge approvals or use the
CI-only disposable adapter. Source CI success does not verify any live
production worker.

## Reproducible validation

- `tests/test_operator_process_service.py`: real non-root worker process,
  independent controller UID, signed liveness, wrong UID denial and protected
  key/config denial.
- `tests/test_process_external_e2e.py`: real signed generic E3 PRE/POST,
  receipt, checkpoint and audit. Its additional generic HTTP case compiles Python,
  validates a sample object and requests a loopback endpoint under a pinned process.
- `tests/test_external_uid_roundtrip.py` and
  `tests/test_trusted_process_catalog.py`: separately authenticated generic
  process workers, reusable target catalog and negative tests.

These are isolated tests, **not a certificate of production installation**.
The local/staging engineering acceptance of [Issue #104](https://github.com/kiky217/eg_portable/issues/104) was completed and closed in v3.1.115. Production operator authorization, service cutover, rollback and destination-specific E2E remain separate prerequisites.

## Reusable catalog, no per-project executor

Use [Generic execution model](GENERIC_EXECUTION_MODEL.md). The private worker configuration accepts either legacy `target`/`executable`/`fixed_args`, or a `profiles` array, never both. Each profile is an immutable operator-pinned mapping of an exact `/tasks/...` target to an executable and fixed arguments. `operator_first_run.py` supports the same catalog for one-time independent installation. A new task uses existing compatible profiles; when a new permission is genuinely needed, the operator updates a bounded catalog and trust binding rather than the agent writing provider-specific executable code. This does not permit agent-supplied shell strings or generate HITL approval.

## Typed high-effect classes without bespoke worker implementations

The operator installer accepts the **paired optional** fields `effect_class` (`E3`, `E4`, `E5`) and `action_type` (bounded, typed lowercase name). Omit both for legacy E3 `bounded_process_run`. The same `TrustedProcessCatalog`, `TrustedProcessEffect`, `operator_process_service`, generic signed RPC and dispatcher run the selected class using 1–32 operator-fixed targets. The generated worker and separately held signer configs are bound to the **same exact class and action type**. Do not mix configurations across classes, routes, or signing domains. E4 requires action `reversible=true`; E5 requires `reversible=false` and forbids compensation. An E4 corrective action must be independently authorized with a fresh PRE and POST. Runtime authority still depends on a live independently protected worker, exact scoped signed HITL, target readback and task-global acceptance. Source availability is not auto-deployment or permission to run arbitrary shell or provider APIs.
