import pytest
from tools.generic_recovery import classify_recovery,RecoveryDenied

GATE={"task_id":"task-1","step_key":"01.01","gate_checkpoint_no":4,
      "action_fingerprint":"a"*64}

@pytest.mark.parametrize("journal,receipt,effect,expected",[
    ("ABSENT",False,False,"NOT_STARTED"),
    ("CLAIMED_UNKNOWN",False,False,"CLAIMED_UNKNOWN"),
    ("CLAIMED_UNKNOWN",False,True,"CLAIMED_UNKNOWN"),
    ("SEALED_RECEIPT",True,False,"CLAIMED_UNKNOWN"),
    ("SEALED_RECEIPT",True,True,"VERIFIED_EFFECT"),
    ("RETIRED_NO_EFFECT",False,False,"SIGNED_NO_EFFECT"),
])
def test_recovery_classification_never_grants_replay(journal,receipt,effect,expected):
    report=classify_recovery(gate=GATE,journal=journal,receipt_valid=receipt,
                           effect_independently_verified=effect)
    assert report["status"]==expected
    assert not report["allow_new_effect"] and not report["authorization"]

def test_signed_effect_can_only_mark_post_with_independent_readback():
    report=classify_recovery(gate=GATE,journal="SEALED_RECEIPT",
        receipt_valid=True,effect_independently_verified=True,post_verified=True)
    assert report["status"]=="POST_VERIFIED"
    with pytest.raises(RecoveryDenied,match="UNSUPPORTED_VERIFIED_POST"):
        classify_recovery(gate=GATE,journal="SEALED_RECEIPT",
            receipt_valid=True,effect_independently_verified=False,post_verified=True)

def test_unsupported_unknown_state_denied():
    with pytest.raises(RecoveryDenied):
        classify_recovery(gate=GATE,journal="COMMITTED",receipt_valid=False,
                         effect_independently_verified=False)
