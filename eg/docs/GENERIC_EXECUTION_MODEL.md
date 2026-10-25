# Generic Execution — One Worker, Many Tasks

EG is a provider-neutral evaluation and evidence gateway, not a catalog of project executors. It owns one immutable task ledger and one PRE/POST lifecycle. The worker owns physical effects, durable nonce claims and independently signed receipts.

## One-time generic operator bootstrap

`tools.operator_first_run` provisions one worker identity, one signing domain and one bounded approval signer. It accepts either the legacy single target or a multi-target **profiles** catalog under one `target_prefix`. There is no new Python executor module per project. One catalog can authorize up to 32 fixed operations without modifying EG source.

Operator-only policy fragment (not an executable or a substitute for operator authority):

```json
{
  "adapter_id": "trusted-adapter-workflow",
  "target_prefix": "/tasks/workflow",
  "profiles": [
    {"target": "/tasks/workflow/inspect", "executable": "/usr/bin/cat", "fixed_args": [], "timeout": 5},
    {"target": "/tasks/workflow/check", "executable": "/usr/bin/cat", "fixed_args": [], "timeout": 5}
  ]
}
```

The complete root-owned installer policy also needs `root`, `worker_uid`, `signer_uid`, `agent_uid`, `eg_url` and `gateway_key_file`. The example illustrates routing only: `cat` does not run a service or manage a database. The operator must pin executables that actually implement approved actions, verify their OS permissions and audit their immutable script/argument dependencies.

After provisioning, `operator_process_service.py` accepts a private `profiles` array **instead of** legacy `executable`, `fixed_args` and `target` keys. Profiles have unique exact target names under `/tasks/`, fixed executable/argv, 1–30-second timeouts and bounded output. One adapter identity, socket, signer and nonce journal serve all profiles. The agent supplies neither shell command nor executable nor target-to-argv mapping.

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

The operator bootstrap accepts optional `environment`, `grant_seconds` and `max_grants`, with enforced bounds, in both legacy and catalog modes. Source code remains identical across hosts and projects; only the independent trust roots, filesystem privileges and preapproved catalog differ. Approval expiry/revocation still applies. This does not make runtime privileges transferable across hosts.
