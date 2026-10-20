"""Authenticated worker reads canonical EG state before scoped execution."""
import base64,hashlib,time
from datetime import datetime,timezone
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from tools import trusted_generic_rpc as rpc
from tools.signed_hitl_approval import canonical
from tools.high_effect_admission import action_fingerprint

def pub(k):
    return base64.b64encode(k.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()

def test_dispatch_canonical_pre_with_independent_receipt(monkeypatch):
    executor,human=Ed25519PrivateKey.generate(),Ed25519PrivateKey.generate()
    payload=b'{"task":"bounded"}'
    action={"action_type":"bounded_process_run","effect_class":"E3",
            "target":"/tasks/process/demo","real_world_effect":True,"reversible":True,
            "payload_sha256":hashlib.sha256(payload).hexdigest(),"payload_bytes":len(payload)}
    fp=action_fingerprint(action);nonce="operator_approved_nonce_123"
    epoch=datetime.now(timezone.utc).isoformat()
    class Adapter:
        private=executor
        adapter_id="trusted-adapter-test-process"
        calls=0
        def execute(self,**kwargs):
            self.calls+=1
            assert kwargs["stdin"]==payload
            return {"status":"EXECUTED_POST_NOT_VERIFIED",
                    "receipt":{"signed":"fixture"}}
    a=Adapter()
    gate={"task_id":"task-a","step_key":"01.01","verdict":"READY_TO_EXECUTE",
          "hitl_approved":True,"checkpoint_no":4,"action_fingerprint":fp,
          "high_effect_pin":{"adapter_id":a.adapter_id,"public_key_b64":pub(executor),
                             "action_fingerprint":fp,"approval_nonce":nonce}}
    state={"status":"IN_PROGRESS","current_step":"01.01",
           "pending_execution_gate":gate,
           "latest_checkpoint":{"checkpoint_no":4,"verdict":"READY_TO_EXECUTE"}}
    detail={"task":{"contract_status":"OPEN"},
            "checkpoints":[{"checkpoint_no":4,"created_at":epoch,"verdict":"READY_TO_EXECUTE"}]}
    monkeypatch.setattr(rpc,"_get",lambda url,key,task,suffix:state if suffix=="/state" else detail)
    now=int(time.time())
    approval_body={"version":1,"task_id":"task-a","step_key":"01.01",
        "gate_checkpoint_no":4,"action_fingerprint":fp,"adapter_id":a.adapter_id,
        "decision":"APPROVED","issued_at":now-1,"expires_at":now+120,"nonce":nonce}
    approval={**approval_body,"signature_b64":base64.b64encode(human.sign(canonical(approval_body))).decode()}
    packet={"task_id":"task-a","step_key":"01.01","action":action,
            "approval":approval,"data_b64":base64.b64encode(payload).decode(),
            "operation":"execute"}
    answer=rpc.dispatch_once(packet,adapter=a,eg_url="http://127.0.0.1:1234",
                       eg_key="test",hitl_public_key_b64=pub(human))
    assert answer["receipt"]=={"signed":"fixture"} and a.calls==1
    gate["high_effect_pin"]["public_key_b64"]=pub(Ed25519PrivateKey.generate())
    with pytest.raises(rpc.TrustedRpcDenied,match="PINNED_INDEPENDENT_WORKER_MISMATCH"):
        rpc.dispatch_once(packet,adapter=a,eg_url="http://127.0.0.1:1234",
                          eg_key="test",hitl_public_key_b64=pub(human))
    assert a.calls==1

def test_invalid_packet_is_denied_without_canonical_lookup():
    with pytest.raises(rpc.TrustedRpcDenied,match="INVALID_RPC_SCHEMA"):
        rpc.dispatch_once({"operation":"execute"},adapter=object(),eg_url="http://127.0.0.1",
                          eg_key="test",hitl_public_key_b64="x")
