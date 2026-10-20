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

def test_e5_cannot_compensate(monkeypatch):
    monkeypatch.setattr(ext,"_get",lambda *_:pytest.fail("network attempted"))
    with pytest.raises(ext.ExternalDispatchDenied,match="EFFECT_PAYLOAD_NOT_BOUND"):
        ext.dispatch(request={"task_id":"t","step_key":"01.01",
            "action":{"effect_class":"E5","reversible":False,"target":"/private/lock"},
            "approval":{"nonce":"n"},"data_b64":""},
            eg_url="https://eg.invalid",api_key="secret",worker_socket="/tmp/s",
            expected_worker_uid=os.getuid()+1,adapter_id="trusted-adapter-test",
            pinned_public_key_b64="pub",hitl_public_key_b64="pub",
            operation="compensate")
