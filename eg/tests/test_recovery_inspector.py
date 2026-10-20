"""Read-only recovery preserves scope and never fabricates effect evidence."""
import base64,hashlib,time
from datetime import datetime,timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from app.execution_receipts import body,sign
from tools.high_effect_admission import action_fingerprint
from tools.signed_hitl_approval import canonical
from tools.durable_hitl_ledger import ApprovalLedger
from tools.recovery_inspector import inspect

def pub(key):
    return base64.b64encode(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()

def test_inspector_recovers_only_original_signed_receipt(tmp_path):
    worker=Ed25519PrivateKey.generate();human=Ed25519PrivateKey.generate()
    root=tmp_path/"ledger";root.mkdir(mode=0o700)
    journal=ApprovalLedger(root)
    task,step,cp,adapter="task-inspect","01.01",4,"trusted-adapter-inspector"
    payload=b'{"work":"physical"}';nonce="independent_inspect_nonce_123"
    action={"action_type":"bounded_process_run","effect_class":"E3",
            "target":"/tasks/inspect/item","real_world_effect":True,
            "reversible":False,"payload_sha256":hashlib.sha256(payload).hexdigest(),
            "payload_bytes":len(payload)}
    fp=action_fingerprint(action)
    gate={"task_id":task,"step_key":step,"checkpoint_no":cp,
          "verdict":"READY_TO_EXECUTE","hitl_approved":True,"action_fingerprint":fp,
          "high_effect_pin":{"adapter_id":adapter,"public_key_b64":pub(worker),
                             "action_fingerprint":fp,"approval_nonce":nonce}}
    date=datetime.now(timezone.utc).isoformat()
    state={"status":"IN_PROGRESS","current_step":step,
           "pending_execution_gate":gate,
           "latest_checkpoint":{"checkpoint_no":cp,"verdict":"READY_TO_EXECUTE"}}
    detail={"task":{"contract_status":"OPEN"},
            "checkpoints":[{"checkpoint_no":cp,"verdict":"READY_TO_EXECUTE",
                            "created_at":date}]}
    kwargs=dict(task_id=task,step_key=step,action=action,
                approval_nonce=nonce,adapter_id=adapter,
                eg_state=state,eg_detail=detail,ledger=journal)
    before=inspect(**kwargs)
    assert before["status"]=="NOT_STARTED" and before["mutated"] is False
    now=int(time.time())
    approval_doc={"version":1,"task_id":task,"step_key":step,"gate_checkpoint_no":cp,
        "action_fingerprint":fp,"adapter_id":adapter,"decision":"APPROVED",
        "issued_at":now-1,"expires_at":now+120,"nonce":nonce}
    approval={**approval_doc,"signature_b64":base64.b64encode(human.sign(canonical(approval_doc))).decode()}
    scope=dict(task_id=task,step_key=step,gate_checkpoint_no=cp,
               action_fingerprint=fp,adapter_id=adapter)
    journal.consume(approval,pub(human),**scope)
    unknown=inspect(**kwargs)
    assert unknown["status"]=="CLAIMED_UNKNOWN"
    assert not unknown["allow_new_effect"] and not unknown["authorization"]
    receipt=sign(body(task,step,cp,fp,"trusted-worker-"+adapter,action["target"],b"physical output",nonce),worker)
    journal.seal_receipt(nonce,receipt,**scope)
    recovered=inspect(**kwargs)
    assert recovered["status"]=="VERIFIED_EFFECT"
    assert recovered["next_action"]=="SUBMIT_CANONICAL_POST"
    assert recovered["execution_receipt"]==receipt
    assert recovered["mutated"] is False
    # A changed task or latest checkpoint cannot recover original effect.
    stale=inspect(**{**kwargs,"eg_state":{**state,
          "latest_checkpoint":{"checkpoint_no":cp+1,"verdict":"READY_TO_EXECUTE"}}})
    assert stale["status"]=="MANUAL_REVIEW"
    assert not stale["allow_new_effect"]
