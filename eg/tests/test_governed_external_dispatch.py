"""Unified agent dispatch selects only provisioned high-effect transport."""
import pytest
from tools.governed_agent_dispatcher import dispatch_action, DispatchDenied
import tools.external_adapter_dispatcher as external

REQ={"task_id":"t","step_key":"01.01",
     "action":{"effect_class":"E3","action_type":"bounded_effect","target":"/private/output"},
     "data_b64":"YQ=="}


def test_high_effect_without_adapter_stays_blocked():
    with pytest.raises(DispatchDenied,match="HIGH_EFFECT_PRODUCTION_TRANSPORT_NOT_PROVISIONED"):
        dispatch_action(REQ,eg_url="https://eg.example",api_key="secret",
                        executor_public_key_b64="unconfigured")


def test_explicit_external_rpc_routes_once(monkeypatch):
    calls=[]
    def fake_dispatch(**kwargs):
        calls.append(kwargs)
        return {"status":"RECEIPT_VERIFIED_POST_REQUIRED"}
    monkeypatch.setattr(external,"dispatch",fake_dispatch)
    result=dispatch_action(REQ,eg_url="https://eg.example",api_key="secret",
        executor_public_key_b64="not-an-adapter-root",external_worker_socket="/private/worker.sock",
        external_worker_uid=22333,external_adapter_id="trusted-adapter-independent",
        external_public_key_b64="pinned-adapter-root",hitl_public_key_b64="independent-hitl-root",
        hitl_approval={"nonce":"signed-approval-token"})
    assert result["status"]=="RECEIPT_VERIFIED_POST_REQUIRED"
    assert len(calls)==1
    assert calls[0]["pinned_public_key_b64"]=="pinned-adapter-root"
    assert calls[0]["request"]["approval"]["nonce"]=="signed-approval-token"


def test_never_route_ci_adapter_as_external(monkeypatch):
    monkeypatch.setattr(external,"dispatch",lambda **_:pytest.fail("unsafe execution"))
    with pytest.raises(DispatchDenied,match="INVALID_EXTERNAL_EXECUTOR_CONFIGURATION"):
        dispatch_action(REQ,eg_url="https://eg.example",api_key="secret",
            executor_public_key_b64="x",external_worker_socket="/private/worker.sock",
            external_worker_uid=22333,external_adapter_id="trusted-adapter-independent",
            external_public_key_b64="pinned",hitl_public_key_b64="hitl",
            hitl_approval={"nonce":"x"},ci_only=True)
