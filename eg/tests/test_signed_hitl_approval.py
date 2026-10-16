"""Independent HITL authorization: positive signature and adversarial denials."""
import base64
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from tools.signed_hitl_approval import verify_approval,HitlDenied,canonical

KEY=Ed25519PrivateKey.generate()
PUB=base64.b64encode(KEY.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()

def envelope(**changes):
    base={"version":1,"task_id":"task","step_key":"01.01",
          "gate_checkpoint_no":2,"action_fingerprint":"a"*64,
          "adapter_id":"trusted-adapter-sandbox","decision":"APPROVED",
          "issued_at":1000,"expires_at":1100,"nonce":"unique-approval-1234"}
    base.update(changes)
    return {**base,"signature_b64":base64.b64encode(KEY.sign(canonical(base))).decode()}

def check(value,now=1010):
    return verify_approval(value,PUB,task_id="task",step_key="01.01",
                           gate_checkpoint_no=2,action_fingerprint="a"*64,
                           adapter_id="trusted-adapter-sandbox",now=now)

def test_authentic_signed_approval_verifies_but_does_not_execute():
    assert check(envelope())["status"]=="SIGNED_APPROVAL_VERIFIED_NOT_CONSUMED"

@pytest.mark.parametrize("change",[
    {"task_id":"other"},{"step_key":"01.02"},{"gate_checkpoint_no":3},
    {"action_fingerprint":"b"*64},{"adapter_id":"trusted-adapter-other"},
    {"decision":"DENIED"},{"expires_at":999},{"expires_at":2000},
    {"nonce":"short"}])
def test_signed_but_invalid_scope_decision_or_lifetime_denied(change):
    with pytest.raises(HitlDenied):
        check(envelope(**change))

def test_expired_valid_signature_denied():
    with pytest.raises(HitlDenied,match="EXPIRED"):
        check(envelope(),now=1100)

def test_mutation_after_signature_denied():
    approved=envelope()
    approved["expires_at"]=1200
    with pytest.raises(HitlDenied,match="SIGNATURE"):
        check(approved)

def test_wrong_authority_denied():
    wrong=base64.b64encode(Ed25519PrivateKey.generate().public_key().public_bytes(
        Encoding.Raw,PublicFormat.Raw)).decode()
    with pytest.raises(HitlDenied,match="SIGNATURE"):
        verify_approval(envelope(),wrong,task_id="task",step_key="01.01",
                        gate_checkpoint_no=2,action_fingerprint="a"*64,
                        adapter_id="trusted-adapter-sandbox",now=1010)
