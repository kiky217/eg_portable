# Generic one-time operator bootstrap

The operator provisions **one reusable worker** for many tasks through a
protected `profiles` catalog (1–32 exact target-to-executable mappings).
Use one canonical typed `profiles` policy. See
[Generic execution model](GENERIC_EXECUTION_MODEL.md).

This tool reduces first-use credential/worker assembly. **An independent
administrator executes it once** on a trusted Linux host, not the AI agent.
The agent then uses EG's existing discovery and dispatch paths without
repeating worker identities or approval keys for every task.

`tools/operator_first_run.py` accepts a root-owned `0600` JSON policy with
a bounded policy. Required fields are:

| Field | Source |
| --- | --- |
| `root` | New directory below a trusted, root-owned non-writable parent |
| `worker_uid`, `signer_uid`, `agent_uid` | Three existing distinct **non-root** OS identities |
| `adapter_id` | Operator-chosen ID beginning `trusted-adapter-` |
| `target_prefix` | Bounded permitted `/tasks/...` scope; required in both modes |
| `effect_class`, `action_type` | **Required** explicit operator-selected E3/E4/E5 class and exact typed action |
| `profiles` | **Required** 1–32 unique exact target/executable/fixed-argument profiles with optional timeout/max_stdout |
| `eg_url` | HTTPS gateway or local loopback gateway |
| `gateway_key_file` | Existing private root-owned `0600` gateway API credential file |

Operator command:

```sh
sudo python -m tools.operator_first_run /operator-protected/worker-policy.json
```

No private signing material is output to the console. The installer produces
separate worker and signer Ed25519 identities, private worker configuration,
private gateway credential copy, operator-signed adapter binding, immutable
typed capability and agent-readable *public* metadata. It refuses replacing
an existing installation. The operator can provision multiple bounded targets together, so different
projects reuse one worker, dispatcher, journal and signing root.

**Generic activation, after independent operator setup.** The installer now creates a
root-owned, read-only `operator-public-key.b64` alongside the agent-readable
registry. The agent-controlled discovery JSON is **not** the signing trust root.

Once the **independent operator** has started both the catalog process worker
and scoped HITL signer as separate non-root identities, an authorized non-root
controller can inspect and activate its already signed catalog, without
creating credentials or expanding scope:

```sh
python -m tools.operator_activate_catalog /trusted/operator-install --mode inspect
python -m tools.operator_activate_catalog /trusted/operator-install --mode activate
python -m tools.operator_activate_catalog /trusted/operator-install --mode verify
```

The CLI checks the **root-pinned** Ed25519 operator key, binding signature,
worker UID, Unix socket liveness and signed worker challenge. Activation is
fail-closed and never grants agent-selected shell commands, unsigned approval,
or a canonical EG PRE. The operator must also register the independently
pinned roots with the EG instance and activate the scoped HITL service. A
successful registry activation reports `admission=false`: only the subsequent
original EG `REGISTER → PRE → separately signed HITL → worker effect → signed
receipt → POST → SATISFIED` can establish actual task authorization and success.

Existing installations **without** a root-pinned public key cannot be upgraded
by copying an agent-provided key into this path. An independent administrator
must authenticate and pin the existing operator identity, or use a fresh
one-time protected onboarding with separately authorized profiles. Use one
reusable implementation across projects but independently bound E3/E4/E5
identities and operator policy per effect class.

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
[Generic scoped standing approval](SCOPED_STAGING_APPROVAL.md) and
[Executor protocol](EXECUTOR_PROTOCOL.md).

This proves the **generic one-time installer and protected identities**, not
unattended production deployment, systemd management, revocation automation,
or a right for the agent to provision its own authority. Missing
administrator approval remains a legitimate fail-closed prerequisite.

## Any independently authorized environment

The same installer works for different independently trusted environments. Optional root-owned policy keys are `environment` (short ASCII label), `grant_seconds` (30–86400), and `max_grants` (1–100). Defaults preserve existing staging deployments. These fields only constrain operator-signed expiry and grant quota; they never grant a task permissions or turn an agent into the signer. One configured multi-profile worker serves many approved tasks. See [Generic execution model](GENERIC_EXECUTION_MODEL.md).

## Root host versus a non-root runtime

The root-owned installer expects three distinct, **already existing** non-root
OS user identities (controller, E3 worker, scoped approval signer). An
operator may prepare these identities using normal host administration, but
this does **not** create three AI agents. It is one AI agent interacting with
separately privileged system services. If the controlling agent has host root,
new accounts alone cannot demonstrate an independently secured production
signer: root can still access/reconfigure all local UID domains. Never claim
independent trust without a genuinely protected enforcement boundary.

### Identical bootstrap for E3, E4 and E5

A new worker does **not** need application-specific executor source. To provision high-effect operations, the operator supplies **both** `effect_class` and `action_type` in the existing protected root-owned policy; the installer pins them into the capability descriptor, worker configuration and independently owned scoped signer configuration. E4 profiles admit only reversible actions; E5 profiles admit only explicitly irreversible actions and forbid compensation. Each effect class remains a separately signed adapter and needs its own live trust domain. Use the same Python worker implementation and operator registry, not a new module per provider. No automatic admission or unreviewed OS permission is granted by installer success.

## Independent high-effect approval roots per adapter

A single EG gateway can admit multiple separately typed E3, E4 and E5 catalogs without sharing a signer. The **independent operator**, not the requesting agent, configures `EVALUATION_GATEWAY_HIGH_EFFECT_HITL_PUBLIC_KEYS_JSON` as a JSON object whose keys are exact active `trusted-adapter-*` IDs and whose values are the respective independently protected Ed25519 **public** keys. It must cover every external capability, with distinct signer roots for each adapter. Legacy single-adapter deployments can continue using `EVALUATION_GATEWAY_HITL_PUBLIC_KEY_B64`; never use the legacy shared key to defeat a class-bound signer policy. The gateway rejects missing/invalid/unmatched signer configuration at startup, and the original PRE verifies the signature using the exact adapter's pinned key. Per-action approval still requires a live separately owned signer, exact profile, registered task, independent signed HITL, PRE and POST.
