# Context Engineering — Progress and Multi-Chat Handoff

**Project:** `kiky217/eg_portable` (Evaluation Gateway portable).  
**Source snapshot:** `main@5a56e9b9ddf0d74479590075d166d4293c79366f`, `v3.1.141`, 2026-10-27.  
**Workspace:** Repository `docs/context/`, with all new documents isolated in `docs/context-engineering-phase1-20261027` for review.  
**Method:** GitHub repository reading/writing only. No Desktop Commander, KNID, VPS, KNID-PC, Colab, or production state accessed.

## Complete instructions for any subsequent chat

**Mission:** Build a small, accurate, AI-readable repository context system that improves understanding of the actual code and canonical EG procedures without modifying source behavior, operational authority, licenses or existing normative documentation.

1. **First read this entire file** and [project-overview.md](project-overview.md), then the canonical [SKILL](../../SKILL.md), [protocol](../../eg/docs/EXECUTOR_PROTOCOL.md) and [runbook](../../eg/docs/PORTABLE_RUNBOOK.md).
2. Check the fresh GitHub `main` HEAD, release/tag, current PR/CI status and exact tree before resuming. If baseline changed, reconcile and update this file first; do not assume this snapshot is current.
3. Follow **maximum three phases** and finish only the currently agreed phase. After each major milestone, update this file with exact files, findings, source SHA, CI evidence, risks and next step. Confirm before proceeding to the **next** phase.
4. Preserve source truth and terminology. The canonical installed worker supports bounded read, exclusive create, verified replace; no arbitrary shell, service operation or Git push. PRE/receipt/POST applies to staging as well. Older metadata is historical, not permission.
5. **New docs first.** Never delete existing docs, reorganize an existing docs hierarchy, overwrite major existing content or change templates without separate owner confirmation and preview. Keep a rollback SHA for every branch change. Never commit credentials or private task/audit material.
6. Keep Markdown human-readable, short, focused, with relative links checked against the real tree. Treat all context files as explanatory; the protocol/SKILL/runtime remain authoritative.
7. A PR can validate documentation, but merging to `main` with an already-published `eg/VERSION` **requires immutable release planning**. Previous docs-only main commit with an unchanged release tag failed `publish_stable` (`VERSION_BUMP_REQUIRED`); do not repeat or bypass that gate. Preserve existing v3.1.141 tag/assets. Do not change the workflow to suppress a legitimate version mismatch.
8. CI PASS never proves live production acceptance. Do not access unrelated machines or claim live task state.

## Standard file organization

```text
docs/context/
├── project-overview.md                   # master AI entry and navigation
├── context-engineering-progress.md       # handoff / phase tracker
├── architecture/
│   ├── decisions/
│   │   └── adr-001-generic-gateway-bounded-worker.md
│   └── system-design.md                  # planned phase 2 (not created)
├── components/                           # planned phase 2 (not created)
└── workflows/                            # planned phase 3 (not created)
```

**Naming guidelines:** `adr-NNN-short-title.md`, `<component>-context.md`, `<workflow-name>.md`. Favor small semantic files; don't duplicate a normative manual.

## Project specification / architecture facts

- Python 3.12, FastAPI, Starlette, Pydantic, SQLite, Ed25519, SHA-256; hash-locked runtime closure and a Linux/amd64 portable archive.
- Canonical HTTP evaluator and task registry: `eg/app/main.py`; receipt checking: `eg/app/execution_receipts.py`; bounded worker: `eg/tools/trusted_execution_worker.py`; one-agent orchestration: `eg/tools/single_agent_workflow.py`.
- `REGISTER → signed PRE → exact admitted dispatch once → receipt → independent fresh POST → VERIFIED → SATISFIED`. Fail closed and reconcile UNKNOWN effects without replay.
- Active endpoint contract: `/health`, `/v1/protocol`, `/v1/agent/capabilities`, `/v1/agent/capability-match`, `/v1/tasks/register`, `/v1/evaluate`, `/v1/tasks/{task_id}/state`, pause/resume/reconcile/abort, `/v1/audit/verify`.
- Source under MIT; third parties retain individual license obligations; CI verifies packaged notices.
- Existing canonical docs must not be reorganized as part of this effort.

## Phase status (max 3)

### Phase 1 — Discovery & planning: **DOCUMENTS WRITTEN; REVIEW/PR CI PENDING**
- Inspected the complete Git tree (129 entries, untruncated) and primary README/SKILL/runbook/protocol, source API handlers, worker, dependencies, Docker and CI.
- `docs/context/` **did not exist** in the baseline tree. The addition is additive: no preexisting files are overwritten.
- New artifacts: [project-overview.md](project-overview.md), [ADR-001](architecture/decisions/adr-001-generic-gateway-bounded-worker.md), this tracker.
- Key ambiguity guarded against: generic EG does **not** authorize all process/Git/service operations; a release is **not** verified production state.
- Scope intentionally minimal: this is not a duplicate operator manual or production readiness certificate.
- Acceptance: all relative links resolve, only the 3 new Markdown files are added, review PR CI passes. Leave `main` and stable release untouched while phases are being reviewed.

### Phase 2 — Core architecture and component context: **NOT STARTED**
- After explicit confirmation, document one [system design](architecture/system-design.md) backed by code flow and minimal component notes (evaluator/task registry, trusted worker/receipts, evidence/audit), without restating authoritative manuals.
- Record additional ADRs **only if a real decision and evidence exist**. Mark unknown decisions as undecided rather than inventing history.
- Validate links and update this tracker.

### Phase 3 — Integration & workflows: **NOT STARTED**
- After explicit confirmation, add focused `workflows/development.md` for contribution, CI, immutable release/promotion and a context update checklist; optionally a short operational decision tree referencing existing SKILL/runbook rather than duplicating them.
- Verify cross-chat handoff, doc links, tests and release requirements. Present a final review before any merge that would change the protected `main`.

## Future-chat continuation prompt

> Lanjutkan context engineering EG Portable. Baca `docs/context/context-engineering-progress.md` dan `docs/context/project-overview.md` pada branch `docs/context-engineering-phase1-20261027`. Rekonsiliasi dengan HEAD `main`, cek status PR/CI, kemudian kerjakan fase berikutnya yang saya setujui. Jangan menimpa dokumentasi atau mengubah source tanpa persetujuan.

## Next checkpoint

Verify the exact three-file diff and link targets, open a review PR, inspect CI, then request confirmation for **Phase 2**. Preserve the repository's current production code and v3.1.141 immutable release. If the branch is merged later, update this tracker to point to `main` after observing merge and CI rather than claiming it in advance.
