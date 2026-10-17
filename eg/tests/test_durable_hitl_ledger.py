"""Protected HITL ledger is once-only across restart and parallel claims."""
import base64
import concurrent.futures
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from tools.signed_hitl_approval import canonical
from tools.durable_hitl_ledger import ApprovalLedger,ApprovalClaimDenied

def test_durable_claim_replay_and_restart(tmp_path):
    key=Ed25519PrivateKey.generate()
    pub=base64.b64encode(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
    payload={"version":1,"task_id":"task","step_key":"01.01","gate_checkpoint_no":1,
             "action_fingerprint":"a"*64,"adapter_id":"trusted-adapter-isolated",
             "decision":"APPROVED","issued_at":1000,"expires_at":1100,
             "nonce":"unique-durable-approval-001"}
    signed={**payload,"signature_b64":base64.b64encode(key.sign(canonical(payload))).decode()}
    tmp_path.chmod(0o700)
    ledger=ApprovalLedger(tmp_path)
    args={"task_id":"task","step_key":"01.01","gate_checkpoint_no":1,
          "action_fingerprint":"a"*64,"adapter_id":"trusted-adapter-isolated","now":1010}
    def attempt():
        try:return ledger.consume(signed,pub,**args)["status"]
        except ApprovalClaimDenied:return "REPLAY_DENIED"
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results=list(pool.map(lambda _:attempt(),range(8)))
    assert results.count("CLAIM_DURABLE_EFFECT_NOT_AUTHORIZED")==1
    assert results.count("REPLAY_DENIED")==7
    assert ApprovalLedger(tmp_path).db.is_file()
    with pytest.raises(ApprovalClaimDenied,match="NO_REPLAY"):
        ApprovalLedger(tmp_path).consume(signed,pub,**args)

def test_nonprivate_directory_denied(tmp_path):
    tmp_path.chmod(0o755)
    with pytest.raises(ApprovalClaimDenied,match="NOT_PRIVATE"):
        ApprovalLedger(tmp_path)


def test_signed_revocation_is_durable_and_blocks_after_restart(tmp_path):
    key=Ed25519PrivateKey.generate()
    pub=base64.b64encode(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
    common={"version":1,"task_id":"task","step_key":"01.01","gate_checkpoint_no":1,
            "action_fingerprint":"b"*64,"adapter_id":"trusted-adapter-isolated",
            "issued_at":1000,"expires_at":1100,"nonce":"revocable-approval-nonce-001"}
    def signed(decision):
        body={**common,"decision":decision}
        return {**body,"signature_b64":base64.b64encode(key.sign(canonical(body))).decode()}
    tmp_path.chmod(0o700)
    args={"task_id":"task","step_key":"01.01","gate_checkpoint_no":1,
          "action_fingerprint":"b"*64,"adapter_id":"trusted-adapter-isolated","now":1010}
    ledger=ApprovalLedger(tmp_path)
    assert ledger.revoke(signed("REVOKED"),pub,**args)["status"]=="REVOCATION_DURABLE_EFFECT_DENIED"
    with pytest.raises(ApprovalClaimDenied,match="REVOKED"):
        ApprovalLedger(tmp_path).consume(signed("APPROVED"),pub,**args)

def test_revocation_after_consumption_is_too_late(tmp_path):
    key=Ed25519PrivateKey.generate()
    pub=base64.b64encode(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
    common={"version":1,"task_id":"task","step_key":"01.01","gate_checkpoint_no":2,
            "action_fingerprint":"c"*64,"adapter_id":"trusted-adapter-isolated",
            "issued_at":1000,"expires_at":1100,"nonce":"claimed-before-revoke-001"}
    def signed(decision):
        body={**common,"decision":decision}
        return {**body,"signature_b64":base64.b64encode(key.sign(canonical(body))).decode()}
    tmp_path.chmod(0o700);ledger=ApprovalLedger(tmp_path)
    args={"task_id":"task","step_key":"01.01","gate_checkpoint_no":2,
          "action_fingerprint":"c"*64,"adapter_id":"trusted-adapter-isolated","now":1010}
    ledger.consume(signed("APPROVED"),pub,**args)
    with pytest.raises(ApprovalClaimDenied,match="TOO_LATE"):
        ledger.revoke(signed("REVOKED"),pub,**args)
