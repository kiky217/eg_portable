"""Lost socket ACK can recover original sealed receipt without duplicate effect."""
import base64,hashlib,time
from datetime import datetime,timezone
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from tools import trusted_generic_rpc as rpc
from tools.high_effect_admission import action_fingerprint
from tools.signed_hitl_approval import canonical
from tools.durable_hitl_ledger import ApprovalLedger,ApprovalClaimDenied
from app.execution_receipts import body,sign

def pub(key):
    return base64.b64encode(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()

def test_sealed_recovery_never_reexecutes(monkeypatch,tmp_path):
    private=Ed25519PrivateKey.generate();human=Ed25519PrivateKey.generate()
    content=b"bounded process input"
    action={"action_type":"bounded_process_run","effect_class":"E3",
        "target":"/tasks/receipt-recovery/item-1","real_world_effect":True,"reversible":False,
        "payload_bytes":len(content),"payload_sha256":hashlib.sha256(content).hexdigest()}
    fp=action_fingerprint(action)
    nonce="recovered_approval_nonce_123"
    adapter_id="trusted-adapter-receipt-recovery"
    task,step,cp="task-recovery","01.01",5
    now=int(time.time())
    approval_body={"version":1,"task_id":task,"step_key":step,
        "gate_checkpoint_no":cp,"action_fingerprint":fp,"adapter_id":adapter_id,
        "decision":"APPROVED","issued_at":now-1,"expires_at":now+120,"nonce":nonce}
    approval={**approval_body,"signature_b64":base64.b64encode(
              human.sign(canonical(approval_body))).decode()}
    directory=tmp_path/"journal";directory.mkdir(mode=0o700)
    ledger=ApprovalLedger(directory)
    scope=dict(task_id=task,step_key=step,gate_checkpoint_no=cp,
               action_fingerprint=fp,adapter_id=adapter_id)
    ledger.consume(approval,pub(human),**scope)
    created=datetime.now(timezone.utc).isoformat()
    receipt=sign(body(task,step,cp,fp,"trusted-worker-"+adapter_id,
                      action["target"],b"physical output",nonce),private)
    ledger.seal_receipt(nonce,receipt,**scope)
    class Adapter:
        private=private
        adapter_id=adapter_id
        ledger=ledger
        def execute(self,**kwargs):
            raise AssertionError("recovery invoked physical effect again")
    gate={"task_id":task,"step_key":step,"checkpoint_no":cp,
          "verdict":"READY_TO_EXECUTE","hitl_approved":True,
          "action_fingerprint":fp,
          "high_effect_pin":{"adapter_id":adapter_id,"public_key_b64":pub(private),
                             "action_fingerprint":fp,"approval_nonce":nonce}}
    state={"status":"IN_PROGRESS","current_step":step,
           "pending_execution_gate":gate,
           "latest_checkpoint":{"checkpoint_no":cp,"verdict":"READY_TO_EXECUTE"}}
    detail={"task":{"contract_status":"OPEN"},
            "checkpoints":[{"checkpoint_no":cp,"created_at":created,
                             "verdict":"READY_TO_EXECUTE"}]}
    monkeypatch.setattr(rpc,"_get",lambda url,key,task_id,suffix:state if suffix=="/state" else detail)
    packet={"task_id":task,"step_key":step,"action":action,
            "approval":approval,"data_b64":"","operation":"recover_receipt"}
    result=rpc.dispatch_once(packet,adapter=Adapter(),eg_url="http://127.0.0.1",
            eg_key="test",hitl_public_key_b64=pub(human))
    assert result["status"]=="RECOVERED_POST_REQUIRED"
    assert result["receipt"]==receipt
    assert ledger.read_sealed_receipt(nonce,**scope)==receipt
    with pytest.raises(ApprovalClaimDenied):
        ledger.read_sealed_receipt(nonce,**{**scope,"step_key":"02.01"})

def test_no_effect_provenance_cannot_forge_sealed_receipt(tmp_path):
    directory=tmp_path/"private";directory.mkdir(mode=0o700)
    ledger=ApprovalLedger(directory)
    assert ledger.read_sealed_receipt("unknown_nonce",task_id="task",step_key="01.01",
        gate_checkpoint_no=1,action_fingerprint="a"*64,adapter_id="trusted-adapter-test") is None
