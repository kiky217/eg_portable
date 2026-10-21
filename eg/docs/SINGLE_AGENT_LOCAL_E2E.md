# Single-agent EG local website acceptance

This is an **isolated staging integration scenario**, not a production deployment workflow. One AI agent can register the task and perform every **supported E2 file creation** step through the existing separately privileged EG worker, without assigning work to another AI agent.

The runner provisions a disposable local EG instance, separate gateway/worker UIDs, distinct signing roots, and admission explicitly enabled for scoped E2. Each requested website file follows **registered acceptance → signed PRE → admitted worker write → independent receipt and byte readback → signed POST**. It also serves the resulting files on a temporary loopback HTTP server for read-only smoke verification, verifies all step checkpoints and the EG audit chain, then stops the processes.

Run only in a disposable Linux environment where privileged operator-owned separate UID setup is authorized:

```sh
cd eg
sudo env PYTHONPATH=. python tools/local_project_e2e.py examples/cafe-website.json
```

The example includes HTML, CSS, JavaScript, and JSON. For a different small website, replace the manifest contents. Paths are flat file names only, allowed suffixes are `.html`, `.css`, `.js`, `.json`, and `.txt`, and each file is bounded to 512 KiB. The script refuses unsafe paths and never modifies files in the source repository or an active deployment. Results and files remain under the generated temporary instance path; **this runner is a CI/local test fixture, not a long-running service or production bootstrap**.

## Remaining constraints

This exercise **does not** provide arbitrary file overwrite/edit, package installation, subprocess build/test execution through EG, service management, or production cutover. These higher-effect capabilities still need a scoped, independently provisioned executor and current EG admission. Do not replace them with logical steps or describe their absence as a PASS.

This test verifies that a *single AI agent* can operate the supported EG workflow with independent **non-AI** workers. It does not establish that EG supports an entire arbitrary application development workflow out of the box.
