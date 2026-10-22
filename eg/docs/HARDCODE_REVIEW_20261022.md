# Issue #104 — SHA-pinned hardcode and generic-core boundary audit

Source snapshot: `2a48f6a0fbf4cb6375d5b70c8837b6cd730ec951` (`v3.1.107`).

This review differentiates intentional security/contract constants from assumptions that incorrectly hardcode a project or deployment. Source file hashes were verified against the [full GitHub Actions audit](https://github.com/kiky217/eg_portable/actions/runs/39707087332) and the matching official source archive.

## Inventory and classification

| Coverage | Exact count |
| --- | ---: |
| Source, tests, scripts, packaging and docs verified by SHA-256 | 183 files |
| Lexical references inventoried | 4,097 |
| Python AST literal sites inventoried | 20,778 |
| HIGH literals | 372 |
| MEDIUM literals | 29 |
| LOW literals | 20,377 |
| HIGH/MEDIUM source-line triage | 401 |
| Provider-specific literals in `eg/app/` | **0** |
| Local-machine absolute path assumptions in `eg/app/` | **0** |

The HIGH/MEDIUM line-by-line source-context triage yielded: **266 SECURITY_INVARIANT**, **69 CONTRACT**, **38 APP_SPECIFIC (in separately scoped adapters)**, and **28 ENVIRONMENT_CONFIG**. Counts refer to the external review artifact for this exact SHA, not new runtime telemetry.

## Producer → consumer decisions

| Boundary | Producer → consumer | Disposition | Test / action |
| --- | --- | --- | --- |
| `eg/app/` | Generic canonical ledger / HTTP API → every client | SECURITY_INVARIANT + CONTRACT | Preserve signed receipts, nonce, HITL, PRE/POST; CI protocol and negative tests |
| `eg/tools/github_*`, `trusted_github_effect.py` | Optional provider worker → typed E4 scope | APP_SPECIFIC, permitted in adapter only | External UID GitHub PR E2E and exact signed scope |
| `eg/tools/staging_site_service.py` | Operator-fixed café staging worker → loopback HTTP | APP_SPECIFIC, permitted in adapter only | Real service deploy, revise, rollback, crash restart, wrong UID/digest tests |
| `eg/tools/operator_*`, `trusted_*worker.py` | Operator provisioning → independent OS workers | SECURITY_INVARIANT / ENVIRONMENT_CONFIG | Protected key, UID peer pinning, signed operator registry, fail-closed admission |
| `eg/tools/disposable_*`, `eg/tests/` | CI-only fixture → isolated regression | PORTABLE_DEFAULT (not production authority) | Production CI rejects disposable admission and tests no replay |
| Docker, Compose, release workflow, bundle | Operator/build environment → portable runtime | PORTABLE_DEFAULT / ENVIRONMENT_CONFIG | Immutable tags, offline relocation, Linux glibc checks, bundle SHA |
| `eg/docs/`, `README.md`, `SKILL.md` | Human/agent instructions → deployment operator | CONTRACT / documentation | Keep staging/production caveats and bootstrap requirements accurate |

A constant is **not a defect just because it is literal**. Fixed domain schema fields, terminal verdicts, explicit policy limits and signed envelope keys are retained deliberately. An application name, action or endpoint becomes problematic when a *generic* EG component requires it; the provider/core negative guard in `tests/test_generic_core_boundaries.py` makes two such regressions fail CI.

## Full AST traceability in each release

Each source-pinned release now attaches `audit/literal-disposition-matrix.jsonl` alongside `hardcode-candidates.json` in its GitHub Actions hardcode-audit artifact. The matrix covers **every Python AST literal**, not only HIGH/MEDIUM candidates: exact source SHA, file SHA-256, path, line, code context, producer, consumer, risk, risk-triage disposition and action. New project/provider strings in generic core are explicitly `UNKNOWN` and continue to fail dedicated core-boundary CI tests. LOW-risk unknown schema strings are assigned scoped producer defaults (generic core/operations → CONTRACT, optional provider adapter → APP_SPECIFIC); a known vendor term in generic core stays UNKNOWN and fails the core-provider regression. These defaults do not change source code or trust policy. Categories are reproducible risk triage, **not** independently signed semantic approval; the report continues to mark `semantic_review_complete=false` until a genuine reviewed signoff is attached.

## Limits of this evidence

The full machine inventory still marks `semantic_review_complete=false`. This report is a source-context, rule-assisted risk triage and explicitly **not** a claim that all 20,778 literals have been individually audited by an independent operator. If a previously unrecognized application-specific assumption is found, create a failing acceptance case and remediate the smallest producer/consumer boundary. Never remove signed execution and no-replay controls to reduce a line count.

A real staging HTTP acceptance proves bounded local deployment, not authorization to deploy to a user's production host. For that, operator-issued live environment scope, physical rollback and fresh canonical POST remain mandatory.
