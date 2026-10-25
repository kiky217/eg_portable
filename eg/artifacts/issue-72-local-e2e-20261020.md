# Issue #72 — Local live EG v3.1.71 E2E evidence (2026-10-20)

**ARCHIVED — historical source evidence only.** This document describes an
older source revision and may refer to executor modules or commands no longer
present in EG Portable. **Do not use it for current runtime or operator setup.**
For the current generic capability and worker model use
[Generic execution model](../docs/GENERIC_EXECUTION_MODEL.md) and
[Agent operations reference](../docs/AGENT_OPERATIONS_REFERENCE.md).

## Proven (local isolated runtime)
- Source: v3.1.71, GitHub main `5a77133a7925c2c27b7ed5b4ecebf0f72eb14cb6`
- CI release artifact from run `39379267780`, successful.
- Local independent EG HTTP runtime UID `65534`; real worker UID `65533`.
- Task `eg-hardening-10-2e33a644ce7a-positive`: 10/10 physical E2 steps verified; checkpoint 20; terminal `SATISFIED`; audit `PASS`.
- Lifecycle: REGISTER → signed PRE → physical isolated write → signed worker receipt → independent readback → EG POST → VERIFIED_PASS.
- Negative task `eg-hardening-10-2e33a644ce7a-negative`: preexisting writes rejected; missing/wrong-signature receipt rejected HTTP 409; socket bypass denied; no false verification.
- E0 signed read verified.
- Result JSON SHA256 `ff160735b07779a9859c161abe7d4e3f18f34b42ae8558335135b3406d8de15d`.
- Adapter sandbox E3 cross-UID regression was tested, but is not a production real-world executor.

## Explicitly NOT proven
- New production GitHub E3 worker provisioned under independently administered credential and signing authority.
- Two distinct independently protected external production adapters and generic live onboarding.
- GitHub write performed through canonical PRE → external worker → signed receipt → POST.
- Original agent's live EG canonical task accepted or terminal SATISFIED.

## Gate classification
Local EG runtime / E0-E2 physical lifecycle: **PASS**.
Independent production adapter onboarding / external GitHub effect: **NOT VERIFIED / blocked on trusted executor authority and live admission**.

Do not close issue #72 solely on local E0-E2 evidence. Preserve issue #61 and #68 for unresolved acceptance. Do not rewrite live history or retroactively attest GitHub connector calls.