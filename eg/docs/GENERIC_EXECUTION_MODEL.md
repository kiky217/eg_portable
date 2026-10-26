# Generic Execution — One Worker, Many Tasks

## MANDATORY FROM INSTALLATION — FULL CAPABILITY ACCEPTANCE

**"Install EG completely as a generic system and test it end-to-end until every supported, authorized capability is operational."**

**Required for every fresh installation and upgrade (including staging):** Read the [canonical agent SKILL](../../SKILL.md) first. Inventory **E0, E2, E3, E4, and E5**. Install the EG gateway and durable audit/evidence state, configure independently protected credentials and trust roots, bring the built-in E0/E2 worker online, and provision/register/activate the **generic** E3/E4/E5 process catalog workers and independently administered scoped HITL signers for every effect class and target profile the operator has actually authorized. Verify live socket/UID identity, signed operator binding, exact typed capability match, and liveness. **Do not build project-specific executor code or infer privileges from the presence of source code.**

**Mandatory acceptance for every authorized capability:** Demonstrate the original EG **REGISTER → PRE → independently authorized execution → signed receipt → POST → VERIFIED → task SATISFIED** with a real physical effect where applicable, independent result readback, and relevant denial, replay/idempotence, crash recovery, and rollback tests. High-effect signed HITL must be valid **before PRE admission**. **CI PASS, `/health: PASS`, source/build completion, and capabilities merely listed/configured are never proof of live E2E readiness.**

**Fail-closed completion rule:** Missing independent operator approval, worker/UID, signer, scoped policy, profile, credentials, registration, or live PRE/POST evidence means the requested full installation is **INCOMPLETE / BLOCKED**, not COMPLETED. Identify the exact prerequisite; never fabricate independent authority, self-approve, or bypass EG by running the effect directly. Generic means reusable implementations with **separately authorized privileges**, not an unrestricted shell.

EG is a provider-neutral evaluation and evidence gateway, not a catalog of project executors. It owns one immutable task ledger and one PRE/POST lifecycle. The worker owns physical effects, durable nonce claims and independently signed receipts.

## One-time generic operator bootstrap

`tools.operator_first_run` provisions one worker identity, one signing domain and one bounded approval signer. It requires a typed E3/E4/E5 **profiles** catalog under one `target_prefix`. There is no new Python executor module per project. One catalog can authorize up to 32 fixed operations without modifying EG source.

Operator-only policy fragment (not an executable or a substitute for operator authority):

```json
{
  "adapter_id": "trusted-adapter-workflow",
  "effect_class": "E3",
  "action_type": "bounded_process_run",
  "target_prefix": "/tasks/workflow",
  "profiles": [
    {"target": "/tasks/workflow/inspect", "executable": "/usr/bin/cat", "fixed_args": [], "timeout": 5},
    {"target": "/tasks/workflow/check", "executable": "/usr/bin/cat", "fixed_args": [], "timeout": 5}
  ]
}
```

The complete root-owned installer policy also needs `root`, `worker_uid`, `signer_uid`, `agent_uid`, `eg_url` and `gateway_key_file`. The example illustrates routing only: `cat` does not run a service or manage a database. The operator must pin executables that actually implement approved actions, verify their OS permissions and audit their immutable script/argument dependencies.

After provisioning, `operator_process_service.py` requires an explicit typed `effect_class`, `action_type`, and private `profiles` array. Top-level executable/target fields are not accepted. Profiles have unique exact target names under `/tasks/`, fixed executable/argv, 1–30-second timeouts and bounded output. One adapter identity, socket, signer and nonce journal serve all profiles. The agent supplies neither shell command nor executable nor target-to-argv mapping.

## Generic task flow

1. Query authenticated `GET /v1/agent/capabilities` and `/v1/agent/capability-match` on the actual EG runtime; reconcile the original task and checkpoint.
2. Match `effect_class`, `action_type`, exact target and input contract to an **already admitted generic profile**. Different projects, languages and databases do not require separate adapter code.
3. If the approved profile does not exist, request an **operator-controlled policy addition**, not a bespoke provider executor. This is a privilege boundary, not a programming-language restriction. Neither EG nor an AI agent can invent absent OS permissions.
4. Obtain signed canonical PRE and independently signed HITL, call `governed_agent_dispatcher.dispatch_action()` **once**, reconcile original nonce/receipt after timeouts, perform independent physical readback, then submit the original signed receipt and evidence to POST.
5. Declare COMPLETE only after canonical step and task-wide acceptance. CI green, healthy server, provider API acknowledgement or receipt alone is insufficient.

## Universal modules

- Orchestration: `single_agent_workflow.py`, `governed_agent_dispatcher.py`
- Generic effects: `trusted_execution_worker.py`, `trusted_generic_rpc.py`, `external_adapter_dispatcher.py`
- Reusable process catalog: `operator_process_service.py`, `trusted_process_catalog.py`, `trusted_process_effect.py`
- Operator trust and admission: `operator_first_run.py`, `operator_runtime_registry.py`, `operator_adapter_binding.py`, `high_effect_admission.py`, `operator_scoped_approval.py`, `durable_hitl_ledger.py`
- Typed schemas: `typed_capability_match.py`, `typed_payload_contract.py`
- Reconciliation: `generic_recovery.py`, `recovery_inspector.py`, `recovery_cli.py`

**Generic does not mean an unrestricted remote root shell.** The purpose of EG is to separate agent intent from independently administered, narrowly approved physical effects. Existing profiles can be reused autonomously. New permissions still require legitimate operator authorization, not a new provider-specific codebase.

Verification: `cd eg && python -m pytest -q tests`. Focused: `pytest -q tests/test_trusted_process_catalog.py tests/test_process_external_e2e.py tests/test_operator_process_service.py`. Scratch E2E is not proof of production deployment.

## Reuse across hosts and time windows

The operator bootstrap accepts optional `environment`, `grant_seconds` and `max_grants`, with enforced bounds, for the one typed catalog format. Source code remains identical across hosts and projects; only the independent trust roots, filesystem privileges and preapproved catalog differ. Approval expiry/revocation still applies. This does not make runtime privileges transferable across hosts.

## Same engine, independent target domains

The same worker **implementation** applies to unrelated projects and
toolchains. Within one independently trusted host, a single E3 catalog
can route approved actions for source verification, bounded application
tests and database checking using three distinct exact targets without a
new EG adapter module. Reuse does **not** expand Linux permissions, approve
new commands, allow dynamic shell strings, or transfer a signing root to
another host. Each target remains a separately approved immutable
executable/argument profile. Missing permissions are a policy/authority
matter, not evidence that an application-specific executor is required.

A producer's evidence `source_type` is also generic: bounded `*_task`
labels remain archival-compatible, but labels do not select workers or
provide trust. Only the independently notarized manifest and original
signed gate can authorize evidence/operations. See [SKILL operational
cookbook](../../SKILL.md#provider-neutral-operational-cookbook-normative-for-new-work).

## Scope of the reusable generic E3–E5 catalog

The same `TrustedProcessCatalog` and `TrustedProcessEffect` implement bounded operator-approved processes for **E3, E4 and E5**. The operator-pinned policy selects explicit `effect_class` and `action_type` (both required; no implicit E3 mode) per signed worker identity; 1–32 exact target profiles reuse that identity, journal and socket. Different classes may use the **same source implementation** but require their own independently authorized typed capability/binding. E4 actions must be reversible; E5 actions must be marked irreversible, are not compensatable and must never be replayed. A missing privilege or capability must not be fabricated from a configured descriptor.
The **dispatcher** is generic across E0–E5; actual executable capabilities
remain whatever has been independently admitted. Do not claim a missing E4/E5
capability can be executed by an E3 profile. Moving to a new Linux host needs
appropriate OS users, protected trust roots and operator bootstrap, but does
not require writing a new project-specific executor. A root-capable AI agent
may provision OS users only if authorized; merely dropping its subprocess UID
does **not** make a signer independent from an agent that still controls host
root. PRE/HITL and receipt verification remain mandatory.
