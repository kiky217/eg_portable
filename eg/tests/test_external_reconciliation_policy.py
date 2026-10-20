"""Recovery controls: independent signed NO_EFFECT and compensation restrictions."""
import base64,hashlib,json,os,time
from datetime import datetime,timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
import pytest
import tools.external_adapter_dispatcher as ext
from tools.high_effect_admission import action_fingerprint
from app.no_effect_receipts import sign_no_effect

def test_unexpected_recovery_operation_denied_without_network(monkeypatch):
    monkeypatch.setattr(ext,"_get",lambda *_:pytest.fail("network attempted"))
    with pytest.raises(ext.ExternalDispatchDenied,match="UNSUPPORTED_EXTERNAL_RECOVERY_OPERATION"):
        ext.dispatch(request={},eg_url="https://eg.invalid",api_key="secret",
            worker_socket="/tmp/x",expected_worker_uid=12345,
            adapter_id="trusted-adapter-test",pinned_public_key_b64="pub",
            hitl_public_key_b64="pub",operation="arbitrary")

def test_e5_cannot_compensate():
    # Production irreversible E5 cannot be relabeled as compensable.
    import inspect
    from tools.governed_agent_dispatcher import dispatch_action, DispatchDenied
    with pytest.raises(DispatchDenied,match="INVALID_EXTERNAL_EXECUTOR_CONFIGURATION"):
        dispatch_action({"task_id":"x","step_key":"01.01","action":{"effect_class":"E5"},
                          "data_b64":""},eg_url="https://eg.invalid",api_key="s",
            executor_public_key_b64="s",external_worker_socket="/tmp/s",
            external_worker_uid=12,external_adapter_id="trusted-adapter-x",
            external_public_key_b64="x",hitl_public_key_b64="pub",
            hitl_approval={},operation="compensate")
