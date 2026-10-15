# Security and disclosure

This is a **source-only** EG portable repository. Never include runtime secrets, tokens, authentication session files, signing keys, user files, database state, live audit anchor, or evidence.

Required production safeguards:

- Generate secrets and Ed25519 keys locally for each deployment.
- Keep `EVALUATION_GATEWAY_API_KEY`, `EVALUATION_GATEWAY_HITL_KEY`, `EVALUATION_GATEWAY_AUDIT_HMAC_KEY`, and signing private keys out of commits and logs.
- Run EG with a dedicated non-root identity and only bind the API to the loopback address; isolate the audit anchor from the DB restore authority.
- Do not treat a child process's exit code alone as sufficient for `VERIFIED`.
- Do not automatically retry a failed or unknown E2 write.
- Portable hardcoding governs only callers of the canonical entrypoint; do not claim that it restricts arbitrary notebook or root shell operations.
- Protect the repository and deployment configuration, review all releases, and maintain SHA-256 manifests.

To report a vulnerability, use GitHub's private security reporting mechanism when enabled, or contact the project maintainer privately. Never place credentials or exploit secrets in a public issue.
