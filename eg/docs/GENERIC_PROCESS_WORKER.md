# Optional generic bounded process worker

The bundled file worker remains the default for authorized read, create and
replace operations. The optional generic_process_worker module implements
bounded_process_run as a reusable, profile-pinned adapter. It is not a
project-specific executor and cannot approve itself.

A profile names one fixed action, target, executable, executable SHA-256,
fixed argument vector, private working directory, timeout and output limit.
The caller cannot choose arbitrary shell commands, executable paths, arguments
or working directories. The adapter checks the original READY PRE and a
verified HITL/adapter signer pin before executing. It persists an exclusive
intent, runs the pinned executable without a shell, enforces resource bounds,
reads the output, and signs an action- and gate-bound receipt.

An ambiguous crash leaves an UNKNOWN effect and must not execute again. Only
the previously sealed receipt can be returned idempotently. The Unix socket
supports signed, read-only liveness challenges and exact execute requests.

Illustrative profile fields for a generic process:

- adapter_id: trusted-adapter-generic-process
- action_type: bounded_process_run
- target: /tasks/build
- executable: /usr/bin/cat
- executable_sha256: operator-pinned binary SHA-256
- fixed_args: an empty array
- cwd: /tasks
- timeout_seconds: 5
- max_output_bytes: 4096
- capability_sha256: operator-signed capability digest
- effect_class: the authorization class approved by the operator

The protected JSON worker configuration contains that profile, journal_root,
private_key, eg_url, eg_api_key, socket_path, and optionally controller_uid.
It must have restrictive ownership and mode. The operator provisions an
independent private key and corresponding gateway public root, a signed
reusable adapter binding, and a separate HITL signer. The worker does not
generate or substitute those authorities.

Root and non-root host identities are supported concurrently on separate EG instances. Neither identity itself
proves signing-key independence. The pinned executable must be trusted;
process limits do not form a kernel filesystem or network sandbox. Do not
approve unknown binaries as generic profiles.

Production requires independently verified operator binding, distinct signing
keys, real PRE, the same signed receipt, and independently notarized POST.
Neither CI fixtures nor an agent-created key establish production authority.
Historical contracts and signed evidence remain unchanged.
