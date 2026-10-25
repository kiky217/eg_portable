# One agent drives verified work

A single agent can use `tools.single_agent_workflow.run_task` to register its
task, submit a fresh PRE for every physical action, dispatch exactly once
through an independently admitted worker, obtain separately notarized result
evidence, and require a canonical POST before advancing. This small helper
does **not** generate its own independent approvals, notary signatures or
physical receipts. It reuses EG's existing typed dispatcher and original
task acceptance requirements.

In practical terms, the agent supplies:

- `registration`: the original task plan and acceptance criteria.
- `step_provider(registered)`: ordered steps, each with the action, its
  actual payload, fresh `pre_request(checkpoint)`, and
  `post_evidence(pre, receipt)` callback that checks the physical result.
- `dispatch_once(packet)`: existing admitted E0/E2 or E3–E5 executor.
- `finalize(checkpoint)`: independently supported task-wide acceptance;
  `run_task` reads back `contract_status=SATISFIED` before claiming success.

On failed PRE there is **no physical effect**. If dispatch times out or is
ambiguous, the helper **does not retry the command**, because effects may
already have occurred. The operator/agent must reconcile the previously
issued gate and signed durable receipt through EG's existing recovery path.
No fake PASS, backdated POST, or second physical execution is permitted.

The regression `tests/test_single_agent_workflow.py` creates an actual
café HTML file via the bundled E2 `TrustedWriter`, gets a signed receipt,
independently reads back content, verifies POST, finalizes its real task and
checks authenticated audit integrity. The test also confirms that an invalid
PRE never calls the worker. Other independently typed consumers can supply
their own action/worker callbacks **without editing EG core**.

The independently signed **generic E3 process catalog** executes the exact same provider-neutral `run_step` orchestration across many approved targets, with signed scoped approvals, physical readback and task-wide SATISFIED. See `test_process_external_e2e.py` and `test_trusted_process_catalog.py`. This does not expand the authority of the AI agent.

For full independent physical E3 and generic catalog tests, see
`tests/test_process_external_e2e.py` and
`tests/test_trusted_process_catalog.py`. Those assert PRE,
signed receipts, HTTP readback, POST and rollback within a disposable
staging environment; they do not authorize deployment to an arbitrary
production host.
