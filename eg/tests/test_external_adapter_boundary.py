"""External high-effect adapters remain fail-closed without explicit provision."""
import base64
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from tools.high_effect_admission import AdapterCapability, AdmissionDenied
from tools.external_adapter_dispatcher import dispatch, ExternalDispatchDenied

def _cap(ci_only=False):
    key=Ed25519PrivateKey.generate()
    pub=base64.b64encode(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
    return AdapterCapability(adapter_id="trusted-adapter-demo",action_type="operate",
        effect_class="E3",target_prefix="/sandbox",maximum_payload_bytes=512,
        isolated=True,public_key_b64=pub,ci_only=ci_only)

def test_external_requires_explicit_opt_in():
    with pytest.raises(AdmissionDenied, match="HIGH_EFFECT_ADAPTER_NOT_PROVISIONED"):
        _cap().validate()
    _cap().validate(allow_external=True)

def test_ci_fixture_does_not_become_external_executor():
    # Explicit opt-in never changes a CI fixture's identity.
    x=_cap(ci_only=True)
    x.validate(allow_external=True)
    assert x.ci_only is True

def test_no_worker_connection_without_valid_scope(monkeypatch):
    called=[]
    monkeypatch.setattr("tools.external_adapter_dispatcher._get",
                        lambda *a,**k: called.append("network"))
    with pytest.raises(ExternalDispatchDenied, match="INVALID_EXTERNAL_DISPATCH_REQUEST"):
        dispatch(request={},eg_url="https://example.invalid",api_key="hidden",
                 worker_socket="/tmp/untrusted.sock",expected_worker_uid=12000,
                 adapter_id="trusted-adapter-demo",
                 pinned_public_key_b64="x",hitl_public_key_b64="y")
    assert not called

def test_rejects_untrusted_gateway_without_network(monkeypatch):
    called=[]
    monkeypatch.setattr("tools.external_adapter_dispatcher._get",
                        lambda *a,**k: called.append("network"))
    request={"task_id":"t","step_key":"01.01",
             "action":{"effect_class":"E3","action_type":"operate","target":"/sandbox/file",
                       "payload_bytes":1,"payload_sha256":"0"*64},
             "approval":{},"data_b64":"YQ=="}
    with pytest.raises(ExternalDispatchDenied, match="UNTRUSTED_GATEWAY_URL"):
        dispatch(request=request,eg_url="http://untrusted.invalid",api_key="hidden",
                 worker_socket="/tmp/untrusted.sock",expected_worker_uid=12000,
                 adapter_id="trusted-adapter-demo",
                 pinned_public_key_b64="x",hitl_public_key_b64="y")
    assert not called
