"""Historical signed PRE scope is opaque; authority comes from its audited gate.

This proves that renaming new capability labels cannot silently replace an
existing action fingerprint or a pinned executor identity.
"""
import base64
import json
import sqlite3

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import HTTPException
from harness import gw


def test_historical_action_keeps_original_wire_fingerprint_and_pinned_key():
    prior_scope = "original_signed_wire_scope"
    action = gw.Action.model_validate({
        "action_type": "bounded_process_run", "target": "/tasks/example",
        "effect_class": prior_scope, "reversible": False,
        "real_world_effect": False,
    })
    assert action.effect_class == prior_scope
    original_fingerprint = gw.action_fingerprint(action)
    original_public = base64.b64encode(
        Ed25519PrivateKey.generate().public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
    ).decode()
    pin = {
        "adapter_id": "trusted-adapter-original",
        "public_key_b64": original_public,
        "action_fingerprint": original_fingerprint,
        "approval_nonce": "original-nonce",
    }
    with sqlite3.connect(":memory:") as db:
        db.row_factory = sqlite3.Row
        db.execute(
            "CREATE TABLE audit (seq INTEGER PRIMARY KEY, task_id TEXT, "
            "event_type TEXT, response_json TEXT)"
        )
        db.execute(
            "INSERT INTO audit(task_id,event_type,response_json) VALUES(?,?,?)",
            (
                "historic-task", "EVALUATION",
                json.dumps({
                    "checkpoint_no": 4, "step_key": "01.01",
                    "verdict": "READY_TO_EXECUTE", "high_effect_pin": pin,
                }),
            ),
        )
        assert gw.original_gate_has_adapter_pin(db, "historic-task", "01.01", 4)
        assert gw.pinned_high_effect_gate(
            db, "historic-task", "01.01", 4, action
        ) == pin
        altered = action.model_copy(update={"effect_class": "governed_operation"})
        assert gw.action_fingerprint(altered) != original_fingerprint
        with pytest.raises(HTTPException) as exc:
            gw.pinned_high_effect_gate(
                db, "historic-task", "01.01", 4, altered
            )
        assert exc.value.status_code == 409
