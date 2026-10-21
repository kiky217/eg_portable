"""Issue #20: agent entrypoint never bypasses EG or advertises POST as done."""
from datetime import datetime, timezone
import pytest
from tools.governed_agent_dispatcher import _admit, DispatchDenied, dispatch
from tools.trusted_execution_worker import fingerprint

A={"action_type":"read","effect_class":"E0","reversible":False,
   "real_world_effect":False,"target":"/worker/output.txt","proofs":[]}
REQ={"task_id":"agent-step-1","step_key":"01.01","action":A,"data_b64":""}

def state_and_detail(action=A):
    record={"checkpoint_no":1,"verdict":"READY_TO_EXECUTE",
            "created_at":datetime.now(timezone.utc).isoformat()}
    return ({"status":"IN_PROGRESS","current_step":"01.01",
             "pending_execution_gate":{"pre_checkpoint_no":1,"action_fingerprint":fingerprint(action)},
             "latest_checkpoint":{"checkpoint_no":1,"verdict":"READY_TO_EXECUTE"}},
            {"task":{"contract_status":"OPEN"},"checkpoints":[record]})

def test_no_pre_does_not_call_worker():
    st,de=state_and_detail()
    st["pending_execution_gate"]=None
    with pytest.raises(DispatchDenied,match="EG_PRE_NOT_READY"):
        _admit(REQ,st,de)

def test_wrong_action_cannot_reuse_other_gate():
    st,de=state_and_detail()
    fake={**REQ,"action":{**A,"target":"/worker/different.txt"}}
    with pytest.raises(DispatchDenied,match="EG_GATE_OR_ACTION_MISMATCH"):
        _admit(fake,st,de)

@pytest.mark.parametrize("kind,effect", [("service_cutover","E3"),("shell","E4"),("delete","E5")])
def test_unsupported_high_risk_effects_remain_blocked(kind,effect):
    st,de=state_and_detail()
    request={**REQ,"action":{**A,"action_type":kind,"effect_class":effect,
                               "real_world_effect":True}}
    with pytest.raises(DispatchDenied,match="UNSUPPORTED_EXECUTOR_CAPABILITY"):
        _admit(request,st,de)

@pytest.mark.parametrize("status",["PAUSED","RECOVERY_PENDING"])
def test_paused_or_unknown_effect_cannot_start_new_action(status):
    st,de=state_and_detail();st["status"]=status
    with pytest.raises(DispatchDenied,match="PAUSED_OR_RECOVERY"):
        _admit(REQ,st,de)

def test_expired_gate_blocks_before_worker():
    st,de=state_and_detail();de["checkpoints"][0]["created_at"]="2001-01-01T00:00:00+00:00"
    with pytest.raises(DispatchDenied,match="EXPIRED"):
        _admit(REQ,st,de)

def test_no_shell_arbitrary_agent_request():
    with pytest.raises(DispatchDenied,match="INVALID_DISPATCH_REQUEST"):
        dispatch({**REQ,"shell_command":"sh -c echo bypass"},
                 eg_url="http://127.0.0.1:1",api_key="unused",
                 worker_socket="/tmp/no-socket",executor_public_key_b64="unused")


def test_high_effect_ci_dispatch_requires_explicit_isolated_adapter():
    from tools.governed_agent_dispatcher import dispatch_disposable_ci
    with pytest.raises(DispatchDenied,match="PRODUCTION_TRANSPORT_NOT_PROVISIONED"):
        dispatch_disposable_ci(task_id="t",step_key="01.01",action={"effect_class":"E3"},
          data=b"{}",approval={},adapter=None,eg_url="http://invalid",api_key="key",
          hitl_public_key_b64="invalid",executor_public_key_b64="invalid")


def test_unified_dispatch_denies_high_effect_without_transport():
    from tools.governed_agent_dispatcher import dispatch_action
    request={**REQ,"action":{**A,"effect_class":"E3","action_type":"service_cutover"}}
    with pytest.raises(DispatchDenied,match="HIGH_EFFECT_PRODUCTION_TRANSPORT_NOT_PROVISIONED"):
        dispatch_action(request,eg_url="http://invalid",api_key="unused",
                        executor_public_key_b64="unused")

def test_unified_dispatch_denies_e0_e2_without_worker_socket():
    from tools.governed_agent_dispatcher import dispatch_action
    with pytest.raises(DispatchDenied,match="INDEPENDENT_E0_E2_WORKER_SOCKET_REQUIRED"):
        dispatch_action(REQ,eg_url="http://invalid",api_key="unused",
                        executor_public_key_b64="unused")

@pytest.mark.parametrize("reply",[b"[]\\n",b"null\\n",b"42\\n",b'"ok"\\n',b'{"status":\\n'])
def test_untrusted_builtin_worker_ack_requires_reconciliation(monkeypatch,reply):
    import tools.governed_agent_dispatcher as module
    state,detail=state_and_detail()
    monkeypatch.setattr(module,"_get",lambda url,key,task,suffix:
                        state if suffix=="/state" else detail)
    packets=[]
    class Worker:
        def __enter__(self):return self
        def __exit__(self,*args):return False
        def settimeout(self,value):pass
        def connect(self,path):pass
        def sendall(self,data):packets.append(data)
        def recv(self,size):return reply
    monkeypatch.setattr(module.socket,"socket",lambda *a,**kw:Worker())
    with pytest.raises(DispatchDenied,match="INVALID_WORKER_RESPONSE_RECONCILE"):
        dispatch(REQ,eg_url="http://127.0.0.1:1",api_key="fixture",
                 worker_socket="/tmp/signed-worker.sock",
                 executor_public_key_b64="independent-key")
    assert len(packets)==1


def test_builtin_worker_socket_timeout_after_send_is_unknown_not_retry(monkeypatch):
    import tools.governed_agent_dispatcher as module
    state,detail=state_and_detail()
    monkeypatch.setattr(module,"_get",lambda url,key,task,suffix:
                        state if suffix=="/state" else detail)
    sent=[]
    class Worker:
        def __enter__(self):return self
        def __exit__(self,*args):return False
        def settimeout(self,value):pass
        def connect(self,path):pass
        def sendall(self,data):sent.append(data)
        def recv(self,size):raise TimeoutError("ACK lost after effect")
    monkeypatch.setattr(module.socket,"socket",lambda *a,**kw:Worker())
    with pytest.raises(DispatchDenied,match="WORKER_ACK_UNKNOWN_RECONCILE"):
        dispatch(REQ,eg_url="http://127.0.0.1:1",api_key="fixture",
                 worker_socket="/tmp/signed-worker.sock",
                 executor_public_key_b64="independent-key")
    assert len(sent)==1
