# EG autonomous recovery — same authoritative lifecycle

After three evidence-bound failed attempts on the same step, further local
retry is denied and a linked REMEDIAL task becomes mandatory. The linked task
has an immutable relationship to the original task registry entry and uses the
same PRE, execution receipt, POST, audit chain, checkpoint, and acceptance
mechanism. It does NOT create a second EG instance or independent ledger.

RECOVERED uses LOCAL_REPAIR, ROLLBACK, COMPENSATION or REPLAN and preserves
the original acceptance criteria. UNRESOLVED requires EXHAUSTED evidence.
Nested remedial tasks are prohibited. An agent can pause indefinitely, but
new execution leases remain bounded. Unknown writes must be reconciled
without duplication. Changes in owner baseline/acceptance require fresh
owner authority; historical VERIFIED evidence must not be overwritten.
