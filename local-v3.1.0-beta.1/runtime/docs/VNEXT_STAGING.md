# EG v3.1.0-beta.1 — Security-hardening Staging Notes

This tree is an experimental staged successor to EG v3.0.1.
**Not deployed to the canonical Colab EG service**. Existing authenticated
audit, state, evidence, anchor, and task contracts remain unchanged.

## Changes with E2E evidence

- All mutating EG POST requests require an Ed25519 execution receipt from a
  **different** trust root than the signed claim-evidence notary. A bearer API
  credential or newly signed criterion claim is insufficient.
- Receipt includes exact task ID, step key, PRE gate, full action fingerprint,
  executor identity, target, output SHA-256, output size, nonce and timestamp.
- Trusted writer refuses pre-existing targets, arbitrary commands, unsafe
  paths, altered intents and duplicate effects. It stores intent durably
  before E2 writes and seals the immutable receipt after readback.
- Worker runs as a separate non-root UID; private key is worker-owned.
- Task PAUSED has no deadline. Resume with an outstanding PRE gate moves to
  RECOVERY_PENDING; new PRE is denied, and previously sealed worker receipts
  can be used for POST reconciliation. Audit lifecycle events are anchored.
- Existing bounded remediation supports three failed verifications before
  linked REMEDIAL. Demonstrated deterministic LOCAL_REPAIR and REPLAN with
  ten-step linked remedial tasks without changing original acceptance.

## Validated security tests (Colab staging)

- 10 pre-existing outputs => trusted worker refuses, EG POST returns 409.
- Incorrect signer => POST returns 409; 10 EG-authorized E2 writes => 10/10 VERIFIED.
- Pause after E2 write before POST; resume => no repeated write, same receipt
  accepted; all ten positive steps SATISFIED / 20 checkpoints / audit PASS.
- Two controlled diagnostic scenarios: exactly 3 failed verifications;
  10-step linked LOCAL_REPAIR and REPLAN; original task SATISFIED afterward.
- Full Python unit/regression and live-process E2E suites.

## Outstanding production blockers

1. This test worker only supports bounded E2 file creation. Other capability
   classes and arbitrary user tasks need their own trusted backends and tests.
2. Linux UID separation is not a boundary against host root. Colab root
   operators could access worker private keys; production trust roots and
   enforcement require isolation that root cannot bypass (another host/VM,
   enclave, or independently administered security domain).
3. Workspace is ephemeral. Indefinite pause over Colab runtime destruction
   requires securely backed-up DB, external audit anchor, evidence, worker
   journals, keys, and independent restore validation.
4. Self-healing is proven for controlled deterministic faults. A general
   autonomous diagnosis/planning agent, bounded execution policy, and
   unknown-design recovery suite remain necessary.
5. Build artifacts remain Linux/Colab-specific; this is not a complete
   offline one-click cross-platform portable distribution.
6. Legacy canonical task evidence remains unchanged and must not be
   automatically treated as independently executed.
7. Never copy staging test credentials, databases, private keys, receipts or
   runtime logs to GitHub.

**Promotion gate:** do not replace canonical EG or publish this as stable
until these blockers are resolved and owner acceptance is independently proven.

## October 15 post-audit continuation (Colab)

- Canonical EG task `task-eg-portable-self-audit-remediation-20261015-v1`:
  **22/24 VERIFIED**, checkpoint 44, EG audit PASS; stage `12.01` and its
  final parent are deliberately not promoted to VERIFIED (full release and
  trust-boundary acceptance outstanding).
- Each verified phase/substep received its own new EG PRE and POST with
  signed evidence tied to the checkpoint; initial `01.01` reused its original
  PRE gate without repeating the staged E2 copy.
- Trusted E2 worker now serializes operations, validates its durable intent,
  recovers an existing WRITE after a simulated crash-before-seal without
  executing twice, and rejects new effect starts after a hardcoded 300-second
  authorization lease. Task PAUSE itself has no wall-clock expiry.
- Negative 10 preexisting outputs remain rejected; worker and notary
  signer trust roots remain distinct. Unknown effects require reconciliation.
- Caveat: Colab host root remains able to bypass worker isolation. These are
  verified capabilities of the **managed beta scope**, not OS-wide hardening.

No production migration or stable release has been performed. The canonical
Colab EG 3.0.1 on 127.0.0.1:18765 remains online and has its original audit
and database. No credential or private key is included in this branch.
