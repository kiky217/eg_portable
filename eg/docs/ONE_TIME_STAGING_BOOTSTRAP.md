Operator first-run provisions reusable generic worker identity, not a project executor. A single `profiles` array (1–32 operator-pinned targets/executables) is an alternative to legacy `target` + `executable` + `fixed_args`. Other mandatory root-owned policy fields remain unchanged. See [Generic execution model](GENERIC_EXECUTION_MODEL.md).

# One-time operator staging setup for a single AI agent

This tool reduces first-use credential/worker assembly. **An independent
administrator executes it once** on a trusted Linux host, not the AI agent.
The agent then uses EG's existing discovery and dispatch paths without
repeating worker identities or approval keys for every task.

`tools/operator_first_run.py` accepts a root-owned `0600` JSON policy with
exactly the following parameters:

| Field | Source |
| --- | --- |
| `root` | New directory below a trusted, root-owned non-writable parent |
| `worker_uid`, `signer_uid`, `agent_uid` | Three existing distinct **non-root** OS identities |
| `adapter_id` | Operator-chosen ID beginning `trusted-adapter-` |
| `target_prefix`, `target` | Bounded permitted `/tasks/...` scope |
| `executable`, `fixed_args` | Absolute pinned executable and arguments approved by the administrator |
| `eg_url` | HTTPS gateway or local loopback gateway |
| `gateway_key_file` | Existing private root-owned `0600` gateway API credential file |

Operator command:

```sh
sudo python -m tools.operator_first_run /operator-protected/project-policy.json
```

No private signing material is output to the console. The installer produces
separate worker and signer Ed25519 identities, private worker configuration,
private gateway credential copy, operator-signed adapter binding, immutable
typed capability and agent-readable *public* metadata. It refuses replacing
an existing installation. The operator may choose a different typed profile
for an unrelated project without modifying EG's generic HTTP/API core.

**Do not mistake files for live admission.** The operator must separately
start the worker using `tools.operator_process_service` under its pinned
worker UID, start `tools.operator_scoped_approval` under the signer UID,
register the pinned public roots with the gateway, and activate the
signed adapter binding through `OperatorAdapterRegistry.activate` after
a successful liveness probe. These are operator-only setup actions, not
operations delegated to the AI agent.

A repository test performs this using real distinct UIDs and verifies a
worker-provided signed liveness claim, protected keys, policy non-replacement
and operator-signed binding:
`tests/test_operator_first_run.py`.

For runtime operation, follow
[Operator process service](OPERATOR_PROCESS_SERVICE.md),
[Scoped staging approval](SCOPED_STAGING_APPROVAL.md) and
[Executor protocol](EXECUTOR_PROTOCOL.md).

This currently proves **one-time staging provisioning**, not unattended
production service installation, persistent systemd management, revocation
automation, or a right for the agent to provision its own authority. Missing
administrator approval remains a legitimate fail-closed prerequisite.
