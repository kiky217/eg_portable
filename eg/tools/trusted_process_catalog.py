"""Reusable operator-pinned E3–E5 worker for multiple typed targets.

One signed adapter and one journal across many allowed process profiles.
No provider-specific routing branches and no agent-selected shell commands.
"""
from __future__ import annotations
from tools.trusted_process_effect import TrustedProcessEffect, ProcessDenied

PROFILE_FIELDS = {"target", "executable", "fixed_args"}
PROFILE_OPTIONAL = {"timeout", "max_stdout"}


def validate_profiles(profiles):
    if not isinstance(profiles, (tuple, list)) or not 1 <= len(profiles) <= 32:
        raise ProcessDenied("INVALID_OPERATOR_PROFILE_CATALOG")
    seen = set()
    validated = []
    for item in profiles:
        if (not isinstance(item, dict) or not PROFILE_FIELDS.issubset(item)
                or set(item) - PROFILE_FIELDS - PROFILE_OPTIONAL):
            raise ProcessDenied("INVALID_OPERATOR_PROFILE")
        target = item["target"]
        if (not isinstance(target, str) or not target.startswith("/tasks/")
                or any(x in ("", ".", "..") for x in target.split("/")[1:])
                or target in seen):
            raise ProcessDenied("UNSAFE_OR_DUPLICATE_PROFILE_TARGET")
        args = item["fixed_args"]
        if (not isinstance(args, (tuple, list)) or len(args) > 24
                or any(not isinstance(x, str) or len(x) > 1024 for x in args)):
            raise ProcessDenied("INVALID_OPERATOR_PROFILE_ARGS")
        timeout = item.get("timeout", 20)
        max_stdout = item.get("max_stdout", 262144)
        if (type(timeout) is not int or not 1 <= timeout <= 30
                or type(max_stdout) is not int or not 1 <= max_stdout <= 524288):
            raise ProcessDenied("INVALID_OPERATOR_PROFILE_BOUNDS")
        seen.add(target)
        validated.append({"target": target, "executable": item["executable"],
                          "fixed_args": tuple(args), "timeout": timeout,
                          "max_stdout": max_stdout})
    return tuple(validated)


class TrustedProcessCatalog:
    """One signer and durable nonce ledger reused by each pinned process profile."""
    def __init__(self, *, journal_dir, private_key, adapter_id, hitl_key_b64, profiles,
                 effect_class="E3", action_type="bounded_process_run"):
        self.private = private_key
        self.adapter_id = adapter_id
        self.workers = {}
        self.ledger = None
        for spec in validate_profiles(profiles):
            worker = TrustedProcessEffect(journal_dir=journal_dir,
                private_key=private_key, adapter_id=adapter_id,
                hitl_key_b64=hitl_key_b64, effect_class=effect_class,
                action_type=action_type, **spec)
            if self.ledger is None:
                self.ledger = worker.ledger
            else:
                worker.ledger = self.ledger
            self.workers[spec["target"]] = worker

    def reconcile_no_effect(self, *, task_id, step_key, action, approval, gate):
        if not isinstance(action,dict):
            raise ProcessDenied("INVALID_OPERATOR_ACTION")
        worker=self.workers.get(action.get("target"))
        if worker is None:
            raise ProcessDenied("TARGET_NOT_IN_OPERATOR_PROFILE_CATALOG")
        return worker.reconcile_no_effect(task_id=task_id,step_key=step_key,
            action=action,approval=approval,gate=gate)

    def execute(self, *, task_id, step_key, action, approval,
                gate, gate_created_at, stdin):
        if not isinstance(action, dict):
            raise ProcessDenied("INVALID_OPERATOR_ACTION")
        worker = self.workers.get(action.get("target"))
        if worker is None:
            raise ProcessDenied("TARGET_NOT_IN_OPERATOR_PROFILE_CATALOG")
        return worker.execute(task_id=task_id, step_key=step_key,
            action=action, approval=approval, gate=gate,
            gate_created_at=gate_created_at, stdin=stdin)
