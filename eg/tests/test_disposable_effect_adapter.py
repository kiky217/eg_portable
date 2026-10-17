"""#19 disposable E3-E5 physical-effect adapter security and regression tests."""
import base64,hashlib,json,os,time
from datetime import datetime,timezone
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from app.execution_receipts import verify as verify_receipt
from tools.disposable_effect_adapter import DisposableAdapter,EffectDenied,ALLOWED
from tools.high_effect_admission import action_fingerprint
from tools.signed_hitl_approval import canonical


def pub(priv):
    return base64.b64encode(priv.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()

def approval(priv,task,step,gate,fp,adapter,now,nonce="approval-nonce-0001"):
    body={"version":1,"task_id":task,"step_key":step,"gate_checkpoint_no":gate,
          "action_fingerprint":fp,"adapter_id":adapter,"decision":"APPROVED",
          "issued_at":now-1,"expires_at":now+120,"nonce":nonce}
    return {**body,"signature_b64":base64.b64encode(priv.sign(canonical(body))).decode()}

def fixture(tmp_path,effect):
    root=tmp_path/"sandbox";ledger=tmp_path/"ledger";root.mkdir(mode=0o700);ledger.mkdir(mode=0o700)
    worker=Ed25519PrivateKey.generate();human=Ed25519PrivateKey.generate();adapter_id=f"trusted-adapter-{effect.lower()}"
    a=DisposableAdapter(root,ledger,worker,adapter_id,effect)
    data=json.dumps({"effect":effect,"value":1},sort_keys=True).encode();target=root/f"{effect}.json"
    action={"action_type":ALLOWED[effect],"effect_class":effect,"target":str(target),
            "payload_sha256":hashlib.sha256(data).hexdigest(),"payload_bytes":len(data)}
    now=time.time();gate=7;fp=action_fingerprint(action)
    ready={"task_id":"task-19","step_key":"01.01","checkpoint_no":gate,
           "verdict":"READY_TO_EXECUTE","action_fingerprint":fp}
    hitl=approval(human,"task-19","01.01",gate,fp,adapter_id,now)
    return a,worker,human,data,target,action,ready,hitl,now,gate

@pytest.mark.parametrize("effect",["E3","E4","E5"])
def test_physical_effect_signed_receipt_and_replay_denial(tmp_path,effect):
    a,worker,human,data,target,action,ready,hitl,now,gate=fixture(tmp_path,effect)
    result=a.execute(task_id="task-19",step_key="01.01",gate_checkpoint_no=gate,
        gate_created_at=datetime.fromtimestamp(now,timezone.utc).isoformat(),action=action,data=data,
        approval=hitl,hitl_public_key_b64=pub(human),ready_gate=ready,now=now)
    assert result["status"]=="EXECUTED_POST_NOT_VERIFIED" and target.read_bytes()==data
    ok,note=verify_receipt(result["receipt"],public_b64=pub(worker),task_id="task-19",step_key="01.01",
        gate_checkpoint_no=gate,action_fingerprint=action_fingerprint(action),target=str(target),
        gate_created_at=datetime.fromtimestamp(now,timezone.utc).isoformat(),time_now_ns=int(now*1e9))
    assert ok,note
    with pytest.raises(Exception):
        a.execute(task_id="task-19",step_key="01.01",gate_checkpoint_no=gate,
            gate_created_at=datetime.fromtimestamp(now,timezone.utc).isoformat(),action=action,data=data,
            approval=hitl,hitl_public_key_b64=pub(human),ready_gate=ready,now=now)

@pytest.mark.parametrize("mutation",["missing_gate","wrong_fp","expired","forged","target","payload"])
def test_fail_closed_before_effect(tmp_path,mutation):
    a,worker,human,data,target,action,ready,hitl,now,gate=fixture(tmp_path,"E4")
    if mutation=="missing_gate": ready=None
    elif mutation=="wrong_fp": ready={**ready,"action_fingerprint":"0"*64}
    elif mutation=="expired": now+=301
    elif mutation=="forged": hitl={**hitl,"signature_b64":base64.b64encode(b"0"*64).decode()}
    elif mutation=="target": action={**action,"target":str(tmp_path/"escape.json")}
    elif mutation=="payload": data=b"{}"
    with pytest.raises(Exception):
        a.execute(task_id="task-19",step_key="01.01",gate_checkpoint_no=gate,
            gate_created_at=datetime.fromtimestamp(now if mutation!="expired" else now-301,timezone.utc).isoformat(),
            action=action,data=data,approval=hitl,hitl_public_key_b64=pub(human),ready_gate=ready,now=now)
    assert not target.exists()

def test_timestamp_parser_accepts_iso8601_and_rejects_invalid(tmp_path):
    a,worker,human,data,target,action,ready,hitl,now,gate=fixture(tmp_path,"E3")
    with pytest.raises(EffectDenied,match="INVALID_PRE_TIMESTAMP"):
        a.execute(task_id="task-19",step_key="01.01",gate_checkpoint_no=gate,gate_created_at="not-a-time",
            action=action,data=data,approval=hitl,hitl_public_key_b64=pub(human),ready_gate=ready,now=now)
    assert not target.exists()
