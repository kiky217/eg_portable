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

def test_dispatch_automatically_reuses_operator_registry_from_environment(tmp_path,monkeypatch):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from tools.operator_runtime_registry import OperatorAdapterRegistry
    from test_operator_runtime_registry import binding,pub,revoke
    operator,worker=Ed25519PrivateKey.generate(),Ed25519PrivateKey.generate()
    record=binding(operator,worker)
    directory=tmp_path/"private";directory.mkdir(mode=0o700)
    monkeypatch.setattr("tools.operator_runtime_registry.probe_unix",lambda *a,**k: True)
    reg=OperatorAdapterRegistry(directory,pub(operator))
    reg.activate(record,adapter_id=record["adapter_id"],
                 capability_sha256=record["capability_sha256"])
    monkeypatch.setenv("EVALUATION_GATEWAY_EXTERNAL_REGISTRY_DIR",str(directory))
    monkeypatch.setenv("EVALUATION_GATEWAY_EXTERNAL_REGISTRY_OPERATOR_PUBLIC_KEY_B64",pub(operator))
    calls=[]
    monkeypatch.setattr(external,"dispatch",lambda **kwargs:
                        calls.append(kwargs) or {"status":"RECEIPT_VERIFIED_POST_REQUIRED"})
    params=dict(eg_url="https://eg.example",api_key="test",
                executor_public_key_b64="separate-root",
                external_adapter_id=record["adapter_id"],
                hitl_public_key_b64="separate-hitl",
                hitl_approval={"nonce":"signed"})
    assert dispatch_action(REQ,**params)["status"]=="RECEIPT_VERIFIED_POST_REQUIRED"
    assert calls[0]["worker_socket"]==record["socket_path"]
    assert calls[0]["expected_worker_uid"]==record["worker_uid"]
    with pytest.raises(DispatchDenied,match="INVALID_OPERATOR_ROUTE_REQUEST"):
        dispatch_action(REQ,**{**params,"external_worker_uid":12345})
    reg.revoke(revoke(operator,record),adapter_id=record["adapter_id"])
    with pytest.raises(DispatchDenied,match="OPERATOR_ADAPTER_NOT_ACTIVE"):
        dispatch_action(REQ,**params)
    assert len(calls)==1


def test_partial_auto_registry_is_fail_closed(monkeypatch):
    monkeypatch.setenv("EVALUATION_GATEWAY_EXTERNAL_REGISTRY_DIR","/tmp/incomplete")
    monkeypatch.delenv("EVALUATION_GATEWAY_EXTERNAL_REGISTRY_OPERATOR_PUBLIC_KEY_B64",raising=False)
    with pytest.raises(DispatchDenied,match="INCOMPLETE_SIGNED_OPERATOR_REGISTRY"):
        dispatch_action(REQ,eg_url="https://eg.example",api_key="secret",
                        executor_public_key_b64="separate-root",
                        external_adapter_id="trusted-adapter-one")

def test_auto_dispatch_only_reads_operator_registry(tmp_path,monkeypatch):
    import os,stat
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from tools.operator_runtime_registry import OperatorAdapterRegistry
    from test_operator_runtime_registry import binding,pub
    operator,worker=Ed25519PrivateKey.generate(),Ed25519PrivateKey.generate()
    record=binding(operator,worker)
    directory=tmp_path/"operator";directory.mkdir(mode=0o700)
    monkeypatch.setattr("tools.operator_runtime_registry.probe_unix",lambda *a,**k: True)
    registry=OperatorAdapterRegistry(directory,pub(operator))
    registry.activate(record,adapter_id=record["adapter_id"],
                      capability_sha256=record["capability_sha256"])
    os.chmod(registry.path,0o400)
    monkeypatch.setenv("EVALUATION_GATEWAY_EXTERNAL_REGISTRY_DIR",str(directory))
    monkeypatch.setenv("EVALUATION_GATEWAY_EXTERNAL_REGISTRY_OPERATOR_PUBLIC_KEY_B64",pub(operator))
    seen=[]
    monkeypatch.setattr(external,"dispatch",lambda **kw: seen.append(kw) or
                        {"status":"RECEIPT_VERIFIED_POST_REQUIRED"})
    result=dispatch_action(REQ,eg_url="https://eg.example",api_key="fixture",
        executor_public_key_b64="separate-key",external_adapter_id=record["adapter_id"],
        hitl_public_key_b64="separate-hitl",hitl_approval={"nonce":"signed"})
    assert result["status"]=="RECEIPT_VERIFIED_POST_REQUIRED"
    assert seen[0]["expected_worker_uid"]==record["worker_uid"]
    assert stat.S_IMODE(registry.path.stat().st_mode)==0o400


def test_auto_dispatch_cannot_create_missing_operator_registry(monkeypatch,tmp_path):
    directory=tmp_path/"operator";directory.mkdir(mode=0o700)
    monkeypatch.setenv("EVALUATION_GATEWAY_EXTERNAL_REGISTRY_DIR",str(directory))
    monkeypatch.setenv("EVALUATION_GATEWAY_EXTERNAL_REGISTRY_OPERATOR_PUBLIC_KEY_B64","signed-operator")
    with pytest.raises(DispatchDenied,match="INVALID_SIGNED_OPERATOR_REGISTRY"):
        dispatch_action(REQ,eg_url="https://eg.example",api_key="fixture",
                        executor_public_key_b64="separate-key",
                        external_adapter_id="trusted-adapter-missing")
    assert not (directory/"adapter-activation.sqlite3").exists()

@pytest.mark.parametrize('response,reason', [
    ({'status':'ADMISSION_DISABLED','admission':False,'candidates':[]},'NO_ACTIVE_TYPED_ADAPTER'),
    ({'status':'MATCHED_PRE_REQUIRED','admission':False,'candidates':[
        {'adapter_id':'trusted-adapter-a','status':'LIVE_PRE_ATTESTATION_REQUIRED'},
        {'adapter_id':'trusted-adapter-b','status':'LIVE_PRE_ATTESTATION_REQUIRED'}]},
     'AMBIGUOUS_OR_MISSING_OPERATOR_ADAPTER'),
    ({'status':'MATCHED_PRE_REQUIRED','admission':False,'candidates':[
        {'adapter_id':'trusted-adapter-unsigned','status':'OPERATOR_BINDING_REQUIRED'}]},
     'AMBIGUOUS_OR_MISSING_OPERATOR_ADAPTER'),
])
def test_auto_route_fail_closed_without_unique_active_binding(monkeypatch,response,reason):
    import io,json
    import tools.governed_agent_dispatcher as gw
    monkeypatch.setattr(gw,'urlopen',lambda *a,**k:io.BytesIO(json.dumps(response).encode()))
    with pytest.raises(DispatchDenied,match=reason):
        gw._unique_active_adapter('https://eg.example','api',REQ['action'])
