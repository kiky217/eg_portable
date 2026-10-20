# Production Cargo adapter — deployment contract (candidate)

This document applies to PR #49 only. It does not authorize production deployment.

## Topology

- EG protocol/notary process: owns task, signed PRE gate, criterion evidence and signed POST admission.
- High-effect adapter: separate Unix socket and OS identity, pinned Ed25519 public key and capability manifest.
- Cargo executor: runs allowlisted `cargo check/test/fmt --locked --offline` without shell interpolation, using its own `CARGO_HOME`, `RUSTUP_HOME` and `CARGO_TARGET_DIR`.
- HITL authority: a **different** trust root must sign approval tied to task, step, PRE checkpoint, adapter identity, action fingerprint, nonce and short expiry.
- GitHub promotion: separate E4 adapter, SSH/HTTPS credentials inaccessible to Cargo worker, signed HITL and remote base SHA matching. Ordinary push only; force push disallowed.

## Safe workflow

1. Provision a separate, non-root OS account and private worker directory, configure key file mode 0600 and private socket directory mode 0700. Worker credential and GitHub credential must never be exposed to EG agents or the task evidence notary.
2. Register capability entries with explicit paths, action type, effect class, public key, payload limit and `ci_only: false`. Default `HIGH_EFFECT_PRODUCTION_ENABLED=false` remains fail-closed.
3. Set dedicated Unix socket path and expected UID, then verify fresh challenge/response from the **actual** independent worker. Merely supplying a capability manifest is insufficient.
4. Independently approve the exact action with a short-lived signed HITL grant. EG PRE must validate the approval, capability and independent liveness. Verify `READY_TO_EXECUTE` checkpoint.
5. The trusted worker must fetch the canonical EG gate through an authenticated channel and validate exact scope; it consumes the grant in a durable ledger **before** applying a physical effect. An uncertain crash must never cause automatic replay.
6. Worker signs a receipt after execution/readback, independently verifies nonce/scope, then EG POST validates signature, action fingerprint, gate checkpoint and criterion evidence before marking the step verified.
7. For GitHub: resolve local HEAD and compare expected remote main SHA before pushing; verify remote commit SHA afterwards. Branch protection, token least-privilege, nonce durability and negative/race testing are prerequisites for production.
8. Keep live trading and secret keys disabled. Release requires explicit owner approval and a separate security review.

## Acceptance evidence (sandbox only)

- Unit/integration suite and portable CI.
- Sandbox REGISTER → PRE → real Cargo fmt → signed worker receipt → POST → SATISFIED.
- UID-separated Cargo test and separately signed Unix-socket liveness.
- Tampered receipt, missing gate, wrong target, wrong effect class, mismatched approval and invalid capability fail closed.

## Remaining release gates

The current candidate still lacks a production-ready authenticated **execution** RPC over the worker socket; the liveness endpoint alone supports only `attest`. The Cargo worker is exercised in tests via injected EG client callbacks and is not deployed behind that RPC. GitHub E4 worker also needs independently provisioned credentials, hardened protected-branch workflow and a full canonical PRE/execution/POST proof. Do not set production flags to claim those gates are met.

The active KNID-Solana task and gateway must not be advanced by forged or retroactive evidence. Preserve its checkpoint until independently signed runtime effects meet its immutable contract.
