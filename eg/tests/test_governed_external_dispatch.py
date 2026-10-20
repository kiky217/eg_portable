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


def test_operator_registry_reuses_signed_route_and_revocation_denies(tmp_path,monkeypatch):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from tools.operator_runtime_registry import OperatorAdapterRegistry
    from test_operator_runtime_registry import binding,pub,revoke
    operator,worker=Ed25519PrivateKey.generate(),Ed25519PrivateKey.generate()
    signed=binding(operator,worker)
    directory=tmp_path/'operator';directory.mkdir(mode=0o700)
    monkeypatch.setattr('tools.operator_runtime_registry.probe_unix',lambda *a,**kw: True)
    reg=OperatorAdapterRegistry(directory,pub(operator))
    reg.activate(signed,adapter_id=signed['adapter_id'],
                 capability_sha256=signed['capability_sha256'])
    calls=[]
    def fake_dispatch(**kwargs):
        calls.append(kwargs)
        return {'status':'RECEIPT_VERIFIED_POST_REQUIRED'}
    monkeypatch.setattr(external,'dispatch',fake_dispatch)
    options=dict(eg_url='https://eg.example',api_key='fixture',
        executor_public_key_b64='separate-e0-key',operator_registry=reg,
        external_adapter_id=signed['adapter_id'],
        hitl_public_key_b64='independent-hitl-root',
        hitl_approval={'nonce':'signed-scope'})
    assert dispatch_action(REQ,**options)['status']=='RECEIPT_VERIFIED_POST_REQUIRED'
    assert len(calls)==1
    assert calls[0]['worker_socket']==signed['socket_path']
    assert calls[0]['expected_worker_uid']==signed['worker_uid']
    assert calls[0]['pinned_public_key_b64']==signed['worker_public_key_b64']
    with pytest.raises(DispatchDenied,match='INVALID_OPERATOR_ROUTE_REQUEST'):
        dispatch_action(REQ,**{**options,'external_worker_socket':'/tmp/untrusted.sock'})
    reg.revoke(revoke(operator,signed),adapter_id=signed['adapter_id'])
    with pytest.raises(DispatchDenied,match='OPERATOR_ADAPTER_NOT_ACTIVE'):
        dispatch_action(REQ,**options)
    assert len(calls)==1
