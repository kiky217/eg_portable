"""#19 canonical EG PRE admission for E3-E5 requires registry + signed scoped HITL."""
import base64,hashlib,time
import pytest
import harness as H
from harness import gw,register,raw_eval,step_ref,claim
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from tools.signed_hitl_approval import canonical
from tools.high_effect_admission import action_fingerprint as tool_fp

def pub(k): return base64.b64encode(k.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
def signed(k,task,action,adapter,gate,now):
    b={"version":1,"task_id":task,"step_key":"01.01","gate_checkpoint_no":gate,
       "action_fingerprint":tool_fp(action),"adapter_id":adapter,"decision":"APPROVED",
       "issued_at":now-1,"expires_at":now+120,"nonce":"canonical-hitl-nonce-01"}
    return {**b,"signature_b64":base64.b64encode(k.sign(canonical(b))).decode()}

@pytest.mark.parametrize("effect,atype",[
 ("E3","sandbox_cutover"),("E4","sandbox_critical_update"),("E5","sandbox_irreversible_commit")])
def test_canonical_pre_requires_registered_capability_and_signed_hitl(monkeypatch,effect,atype):
    task,ch=register();human=Ed25519PrivateKey.generate();adapter=f"trusted-adapter-{effect.lower()}"
    action={"action_type":atype,"target":f"/tmp/eg-high/{effect}.json","effect_class":effect,
            "reversible":effect!="E5","real_world_effect":True,
            "payload_sha256":hashlib.sha256(b"{}").hexdigest(),"payload_bytes":2,"proofs":[]}
    cap={"adapter_id":adapter,"action_type":atype,"effect_class":effect,"target_prefix":"/tmp/eg-high/",
         "maximum_payload_bytes":524288,"isolated":True,"public_key_b64":gw.EXECUTOR_PUBLIC_KEY_B64}
    monkeypatch.setattr(gw,"HIGH_EFFECT_CAPABILITIES_JSON",__import__("json").dumps([cap]))
    monkeypatch.setattr(gw,"HITL_PUBLIC_KEY_B64",pub(human))
    ref=step_ref(task,"PRE_EXECUTION",0)
    claims=[claim(ref)]
    no=raw_eval(task,ch,0,claims=claims,phase="PRE_EXECUTION",action=action)
    assert no.status_code==200 and no.json()["verdict"]=="REQUIRES_HITL"
    # First PRE consumed checkpoint 1; fresh evidence and approval bind the next canonical gate.
    ref2=step_ref(task,"PRE_EXECUTION",1)
    approval=signed(human,task,action,adapter,2,time.time())
    yes=raw_eval(task,ch,1,claims=[claim(ref2)],phase="PRE_EXECUTION",action=action,hitl_approval=approval)
    assert yes.status_code==200 and yes.json()["verdict"]=="READY_TO_EXECUTE"
    assert yes.json()["hitl_approved"] is True and yes.json()["gate_checkpoint_no"]==2

def test_header_hitl_cannot_replace_signed_high_effect_approval(monkeypatch):
    task,ch=register();human=Ed25519PrivateKey.generate()
    action={"action_type":"sandbox_cutover","target":"/tmp/eg-high/x.json","effect_class":"E3",
            "reversible":True,"real_world_effect":True,"payload_sha256":hashlib.sha256(b"{}").hexdigest(),"payload_bytes":2,"proofs":[]}
    cap={"adapter_id":"trusted-adapter-e3","action_type":"sandbox_cutover","effect_class":"E3","target_prefix":"/tmp/eg-high/",
         "maximum_payload_bytes":524288,"isolated":True,"public_key_b64":gw.EXECUTOR_PUBLIC_KEY_B64}
    monkeypatch.setattr(gw,"HIGH_EFFECT_CAPABILITIES_JSON",__import__("json").dumps([cap]))
    monkeypatch.setattr(gw,"HITL_PUBLIC_KEY_B64",pub(human))
    ref=step_ref(task,"PRE_EXECUTION",0)
    headers={**H.HEAD,"X-Evaluation-HITL-Key":H.HITL_KEY}
    r=raw_eval(task,ch,0,claims=[claim(ref)],phase="PRE_EXECUTION",action=action,headers=headers)
    assert r.status_code==200 and r.json()["verdict"]=="REQUIRES_HITL"
