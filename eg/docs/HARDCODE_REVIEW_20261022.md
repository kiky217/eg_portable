# Generic-core review — historical 2026-10-22 baseline and current policy

The 2026-10-22 audit applies to an older source tree. Its old hashes, candidate counts, and optional provider-adapter classifications must not be reused for current releases.

## Genericity contract

- The canonical evaluator (`eg/app/`), dispatchers and process host do not branch on project, provider, database or programming language names.
- Provider-specific executors and application demo services were retired from `eg/tools/`. The generic `TrustedProcessCatalog` now supports multiple approved actions with one signed worker, one nonce journal and one operator policy.
- Provider-specific implementation details, when unavoidable, belong to an **external independently controlled operating environment or fixed operator profile**, not the EG core library.
- Mandatory controls remain signed original PRE, scoped HITL, independent UID/identity, durable claim, signed execution receipt, readback, POST and fail-closed recovery.
- Audit current source with `tools/audit_hardcodes.py`; tests `test_generic_core_boundaries.py` and `test_trusted_process_catalog.py` guard provider-free core and exact profile routing. Lexical matches are candidates, not proof of semantic failure.
- A new project by itself must **not** require a new executor module. New privilege still needs operator-controlled admission.

See [Generic execution model](GENERIC_EXECUTION_MODEL.md) and [Agent operations reference](AGENT_OPERATIONS_REFERENCE.md).
