"""Real worker process crash after durable HITL claim: no effect replay."""
import base64,hashlib,os,time
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from tools.high_effect_admission import action_fingerprint
from tools.signed_hitl_approval import canonical
from tools.durable_hitl_ledger import ApprovalLedger,ApprovalClaimDenied
from tools.generic_recovery import classify_recovery

@pytest.mark.skipif(not hasattr(os,"fork"),reason="POSIX worker isolation only")
def test_fork_crash_after_durable_claim_is_unknown_no_replay(tmp_path):
    folder=tmp_path/"journal";folder.mkdir(mode=0o700)
    human=Ed25519PrivateKey.generate()
    human_pub=base64.b64encode(human.public_key().public_bytes(
        Encoding.Raw,PublicFormat.Raw)).decode()
    data=b"effect would run next"
    action={"action_type":"bounded_process_run","effect_class":"E3",
        "target":"/tasks/crash-before-effect","real_world_effect":True,"reversible":False,
        "payload_sha256":hashlib.sha256(data).hexdigest(),"payload_bytes":len(data)}
    fp=action_fingerprint(action);now=int(time.time())
    task,step,cp,adapter="task-crash-claim","01.01",5,"trusted-adapter-crash-claim"
    nonce="independent_crash_claim_nonce_123"
    document={"version":1,"task_id":task,"step_key":step,"gate_checkpoint_no":cp,
        "action_fingerprint":fp,"adapter_id":adapter,"decision":"APPROVED",
        "issued_at":now-1,"expires_at":now+120,"nonce":nonce}
    approval={**document,"signature_b64":base64.b64encode(
             human.sign(canonical(document))).decode()}
    scope={"task_id":task,"step_key":step,"gate_checkpoint_no":cp,
           "action_fingerprint":fp,"adapter_id":adapter}
    child=os.fork()
    if child==0:
        ApprovalLedger(folder).consume(approval,human_pub,**scope)
        # Test-only injected crash between durable nonce claim and effect.
        os._exit(41)
    _,code=os.waitpid(child,0)
    assert os.waitstatus_to_exitcode(code)==41
    ledger=ApprovalLedger(folder)
    assert ledger.claim_status(nonce,**scope)=="UNKNOWN"
    assert ledger.read_sealed_receipt(nonce,**scope) is None
    classification=classify_recovery(
        gate={"task_id":task,"step_key":step,"gate_checkpoint_no":cp,
              "action_fingerprint":fp},
        journal="CLAIMED_UNKNOWN",receipt_valid=False,
        effect_independently_verified=False)
    assert classification["status"]=="CLAIMED_UNKNOWN"
    assert classification["next_action"]=="INDEPENDENT_OPERATOR_RECONCILIATION"
    assert not classification["allow_new_effect"]
    with pytest.raises(ApprovalClaimDenied,match="ALREADY_CONSUMED"):
        ledger.consume(approval,human_pub,**scope)
