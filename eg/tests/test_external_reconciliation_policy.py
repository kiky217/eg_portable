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
        ext.dispatch(request={"task_id":"t","step_key":"01.01","action":{"effect_class":"E3"},"approval":{},"data_b64":""},eg_url="https://eg.invalid",api_key="secret",
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


@pytest.mark.parametrize("wire_reply",[b"[]\n",b"null\n",b"42\n",b'"ok"\n',
                                       TimeoutError("ACK lost after effect"),
                                       BrokenPipeError("partial request send")])
def test_malformed_worker_ack_is_typed_unknown_and_never_replayed(monkeypatch,wire_reply):
    import socket,struct
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
    from tools.signed_hitl_approval import canonical
    human=Ed25519PrivateKey.generate()
    worker=Ed25519PrivateKey.generate()
    def pub(private):
        return base64.b64encode(private.public_key().public_bytes(
            Encoding.Raw,PublicFormat.Raw)).decode()
    task,step,adapter="task-demo","01.01","trusted-adapter-demo"
    payload=b"a"
    action={"effect_class":"E3","action_type":"operate","target":"/demo/result",
            "reversible":True,"real_world_effect":True,
            "payload_sha256":hashlib.sha256(payload).hexdigest(),
            "payload_bytes":len(payload)}
    fp=action_fingerprint(action)
    now=int(time.time())
    signed_doc={"version":1,"task_id":task,"step_key":step,
                "gate_checkpoint_no":4,"action_fingerprint":fp,
                "adapter_id":adapter,"decision":"APPROVED",
                "issued_at":now-1,"expires_at":now+120,
                "nonce":"signed-once-worker-ack-demo"}
    approval={**signed_doc,"signature_b64":
              base64.b64encode(human.sign(canonical(signed_doc))).decode()}
    gate={"checkpoint_no":4,"hitl_approved":True,
          "action_fingerprint":fp,
          "high_effect_pin":{"adapter_id":adapter,
                             "public_key_b64":pub(worker),
                             "action_fingerprint":fp,
                             "approval_nonce":approval["nonce"]}}
    state={"status":"IN_PROGRESS","current_step":step,
           "pending_execution_gate":gate,
           "latest_checkpoint":{"checkpoint_no":4,"verdict":"READY_TO_EXECUTE"}}
    details={"task":{"contract_status":"OPEN"},
             "checkpoints":[{"checkpoint_no":4,
                             "verdict":"READY_TO_EXECUTE",
                             "created_at":datetime.now(timezone.utc).isoformat()}]}
    monkeypatch.setattr(ext,"_get",lambda base,key,task_id,suffix:
                        state if suffix=="/state" else details)
    sent=[]
    class FakeSocket:
        def __enter__(self):return self
        def __exit__(self,*a):pass
        def settimeout(self,value):pass
        def connect(self,path):pass
        def getsockopt(self,*a):return struct.pack("3i",99999,os.getuid()+1,0)
        def sendall(self,packet):
            sent.append(packet)
            if isinstance(wire_reply,BrokenPipeError):raise wire_reply
        def recv(self,size):
            if isinstance(wire_reply,OSError):raise wire_reply
            return wire_reply
    monkeypatch.setattr(socket,"socket",lambda *a,**kw:FakeSocket())
    expected=("WORKER_ACK_UNKNOWN_RECONCILE" if isinstance(wire_reply,OSError)
              else "INVALID_WORKER_RESPONSE_RECONCILE")
    with pytest.raises(ext.ExternalDispatchDenied,match=expected):
        ext.dispatch(request={"task_id":task,"step_key":step,"action":action,
                              "approval":approval,
                              "data_b64":base64.b64encode(payload).decode()},
                     eg_url="http://127.0.0.1:8765",api_key="test",
                     worker_socket="/tmp/worker.sock",expected_worker_uid=os.getuid()+1,
                     adapter_id=adapter,pinned_public_key_b64=pub(worker),
                     hitl_public_key_b64=pub(human))
    assert len(sent)==1
