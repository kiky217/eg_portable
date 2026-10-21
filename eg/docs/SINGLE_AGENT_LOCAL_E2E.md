# Single-agent EG local website acceptance

This is an **isolated staging integration scenario**, not a production deployment workflow. One AI agent can register the task and perform every **supported E2 file creation/replacement** step through the existing separately privileged EG worker, without assigning work to another AI agent.

The runner provisions a disposable local EG instance, separate gateway/worker UIDs, distinct signing roots, and admission explicitly enabled for scoped E2. Each requested website file and revision follows **registered acceptance → signed PRE → admitted worker action → independent receipt and byte readback → signed POST**. It also serves the resulting files on a temporary loopback HTTP server for read-only smoke verification, verifies all step checkpoints and the EG audit chain, then stops the processes.

Run only in a disposable Linux environment where privileged operator-owned separate UID setup is authorized:

```sh
cd eg
sudo env PYTHONPATH=. python tools/local_project_e2e.py examples/cafe-website.json
```

The example includes HTML, CSS, JavaScript, and JSON. For a different small website, replace the manifest contents. Paths are flat file names only, allowed suffixes are `.html`, `.css`, `.js`, `.json`, and `.txt`, and each file or revision is bounded to 512 KiB. An optional `revisions` array can replace a file created earlier in the same task with an exact preimage hash; every revision is separately PRE-checked, executed once, receipted, read back and POST-verified. The script refuses unsafe paths and never modifies files in the source repository or an active deployment. Results and files remain under the generated temporary instance path; **this runner is a CI/local test fixture, not a long-running service or production bootstrap**.

## One-task E2 + E3 café integration (isolated test)

The root-run CI test [`tests/test_single_agent_full_cafe.py`](../tests/test_single_agent_full_cafe.py) registers **one immutable task** with four real steps: E2 source creation, E2 SHA-bound revision, E3 separately signed bounded build/test and loopback HTTP API, and a fresh E2 SHA-bound rollback of the source. Every step passes PRE → signed physical receipt → canonical POST; final task acceptance and authenticated audit pass. The E3 worker uses a separate non-root UID with an operator-signed adapter registry and independent HITL. E2 uses the production `TrustedWriter` implementation in an isolated test fixture; the separate-UID E2 worker is additionally verified by `test_e2_controller_group.py`.

**Staging-only:** the HTTP server starts, is queried, and stops inside a bounded worker run. This test does not deploy a persistent service, install dependencies, or prove live service rollback. It uses one AI agent with ordinary non-AI workers.

## Remaining constraints

This exercise provides worker-owned, size-bounded compare-and-swap edits, but **does not** provide arbitrary host file modification, package installation, subprocess build/test execution through EG, service management, or production cutover. These higher-effect capabilities still need a scoped, independently provisioned executor and current EG admission. Do not replace them with logical steps or describe their absence as a PASS.

This test verifies that a *single AI agent* can operate the supported EG workflow with independent **non-AI** workers. It does not establish that EG supports an entire arbitrary application development workflow out of the box.
