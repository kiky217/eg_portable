"""Issue #4: PRE and signed action proofs bind exact future write payload."""
import hashlib
from harness import gw,CLIENT,HEAD,register,raw_eval,claim,step_ref,bounded_write_action,WORKER_OUTPUT

def test_missing_payload_denied_before_pre_checkpoint():
    task,ch=register()
    a={"action_type":"write","target":str(WORKER_OUTPUT/"missing.txt"),
       "effect_class":"bounded_change","reversible":True,"real_world_effect":False,"proofs":[]}
    r=raw_eval(task,ch,0,claims=[claim(step_ref(task,"PRE_EXECUTION",0))],action=a)
    assert r.status_code==409 and r.json()["detail"]["code"]=="EXECUTION_PAYLOAD_NOT_BOUND_TO_PRE"
    assert CLIENT.get(f"/v1/tasks/{task}/state",headers=HEAD).json()["latest_checkpoint"] is None

def test_reviewed_payload_proof_does_not_apply_to_different_bytes():
    task,ch=register(physical=True)
    a=bounded_write_action(task,0,payload=b"APPROVED_A")
    b={**a,"payload_sha256":hashlib.sha256(b"UNREVIEWED_B").hexdigest(),
        "payload_bytes":len(b"UNREVIEWED_B")}
    assert gw.action_intent_fingerprint(gw.Action(**a)) != gw.action_intent_fingerprint(gw.Action(**b))
    r=raw_eval(task,ch,0,claims=[claim(step_ref(task,"PRE_EXECUTION",0))],action=b)
    assert r.status_code==200 and r.json()["verdict"]=="UNVERIFIED"
    assert CLIENT.get("/v1/audit/verify",headers=HEAD).json()["status"]=="PASS"
