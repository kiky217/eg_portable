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
    ino=target.stat().st_ino
    replay=a.execute(task_id="task-19",step_key="01.01",gate_checkpoint_no=gate,
        gate_created_at=datetime.fromtimestamp(now,timezone.utc).isoformat(),action=action,data=data,
        approval=hitl,hitl_public_key_b64=pub(human),ready_gate=ready,now=now)
    assert replay["status"]=="RECOVERED_EXECUTED_POST_NOT_VERIFIED"
    assert target.stat().st_ino==ino

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


@pytest.mark.parametrize("effect",["E3","E4","E5"])
def test_crash_after_claim_stays_unknown_and_never_replays(tmp_path,effect):
    a,worker,human,data,target,action,ready,hitl,now,gate=fixture(tmp_path,effect)
    def crash(point):
        if point=="after_claim": raise RuntimeError("synthetic-crash-after-claim")
    kwargs=dict(task_id="task-19",step_key="01.01",gate_checkpoint_no=gate,
        gate_created_at=datetime.fromtimestamp(now,timezone.utc).isoformat(),action=action,data=data,
        approval=hitl,hitl_public_key_b64=pub(human),ready_gate=ready,now=now)
    with pytest.raises(RuntimeError,match="after-claim"): a.execute(**kwargs,fault_hook=crash)
    assert not target.exists()
    with pytest.raises(EffectDenied,match="UNKNOWN_NO_REPLAY"): a.execute(**kwargs)
    assert not target.exists()

@pytest.mark.parametrize("effect",["E3","E4","E5"])
def test_crash_after_effect_recovers_receipt_without_duplicate_effect(tmp_path,effect):
    a,worker,human,data,target,action,ready,hitl,now,gate=fixture(tmp_path,effect)
    def crash(point):
        if point=="after_effect": raise RuntimeError("synthetic-crash-after-effect")
    kwargs=dict(task_id="task-19",step_key="01.01",gate_checkpoint_no=gate,
        gate_created_at=datetime.fromtimestamp(now,timezone.utc).isoformat(),action=action,data=data,
        approval=hitl,hitl_public_key_b64=pub(human),ready_gate=ready,now=now)
    with pytest.raises(RuntimeError,match="after-effect"): a.execute(**kwargs,fault_hook=crash)
    ino=target.stat().st_ino
    recovered=a.execute(**kwargs)
    assert recovered["status"]=="RECOVERED_EXECUTED_POST_NOT_VERIFIED"
    assert target.stat().st_ino==ino and target.read_bytes()==data
    ok,note=verify_receipt(recovered["receipt"],public_b64=pub(worker),task_id="task-19",step_key="01.01",
        gate_checkpoint_no=gate,action_fingerprint=action_fingerprint(action),target=str(target),
        gate_created_at=datetime.fromtimestamp(now,timezone.utc).isoformat(),time_now_ns=int(now*1e9))
    assert ok,note


@pytest.mark.parametrize("effect",["E3","E4"])
def test_compensation_is_separately_gated_and_removes_effect(tmp_path,effect):
    from tools.disposable_effect_adapter import COMPENSATION
    a,worker,human,data,target,action,ready,hitl,now,gate=fixture(tmp_path,effect)
    base=dict(task_id="task-19",step_key="01.01",gate_checkpoint_no=gate,
        gate_created_at=datetime.fromtimestamp(now,timezone.utc).isoformat(),action=action,data=data,
        approval=hitl,hitl_public_key_b64=pub(human),ready_gate=ready,now=now)
    a.execute(**base);assert target.exists()
    rollback_action={"action_type":COMPENSATION[effect],"effect_class":effect,"target":str(target),
                     "payload_sha256":hashlib.sha256(b'{"operation":"delete"}').hexdigest(),"payload_bytes":22}
    rfp=action_fingerprint(rollback_action);rgate=gate+1
    rready={"task_id":"task-19","step_key":"01.02","checkpoint_no":rgate,
            "verdict":"READY_TO_EXECUTE","action_fingerprint":rfp}
    rapproval=approval(human,"task-19","01.02",rgate,rfp,a.adapter_id,now,nonce="rollback-approval-nonce-01")
    result=a.compensate(task_id="task-19",step_key="01.02",gate_checkpoint_no=rgate,
        gate_created_at=datetime.fromtimestamp(now,timezone.utc).isoformat(),action=rollback_action,
        approval=rapproval,hitl_public_key_b64=pub(human),ready_gate=rready,now=now)
    assert result["status"]=="COMPENSATED_POST_NOT_VERIFIED" and not target.exists()

def test_e5_compensation_is_forbidden(tmp_path):
    a,worker,human,data,target,action,ready,hitl,now,gate=fixture(tmp_path,"E5")
    with pytest.raises(EffectDenied,match="IRREVERSIBLE"):
        a.compensate(task_id="task-19",step_key="01.02",gate_checkpoint_no=gate+1,
            gate_created_at=datetime.fromtimestamp(now,timezone.utc).isoformat(),action={},
            approval=hitl,hitl_public_key_b64=pub(human),ready_gate={},now=now)


def test_compensation_failure_is_explicit_and_fail_closed(tmp_path):
    from tools.disposable_effect_adapter import COMPENSATION
    a,worker,human,data,target,action,ready,hitl,now,gate=fixture(tmp_path,"E3")
    raction={"action_type":COMPENSATION["E3"],"effect_class":"E3","target":str(target),
             "payload_sha256":hashlib.sha256(b'{"operation":"delete"}').hexdigest(),"payload_bytes":22}
    fp=action_fingerprint(raction);rgate=gate+1
    rready={"task_id":"task-19","step_key":"01.02","checkpoint_no":rgate,
            "verdict":"READY_TO_EXECUTE","action_fingerprint":fp}
    rap=approval(human,"task-19","01.02",rgate,fp,a.adapter_id,now,nonce="rollback-failure-nonce-01")
    with pytest.raises(EffectDenied,match="TARGET_ABSENT"):
        a.compensate(task_id="task-19",step_key="01.02",gate_checkpoint_no=rgate,
            gate_created_at=datetime.fromtimestamp(now,timezone.utc).isoformat(),action=raction,
            approval=rap,hitl_public_key_b64=pub(human),ready_gate=rready,now=now)

@pytest.mark.parametrize("effect",["E3","E4"])
@pytest.mark.parametrize("crashpoint,expected",[
    ("after_claim","exists"),("after_unlink","absent"),
    ("after_fsync","absent"),("after_journal","recovered")])
def test_compensation_crash_matrix_is_fail_closed_and_durable(tmp_path,effect,crashpoint,expected):
    from tools.disposable_effect_adapter import COMPENSATION
    a,worker,human,data,target,action,ready,hitl,now,gate=fixture(tmp_path,effect)
    timestamp=datetime.fromtimestamp(now,timezone.utc).isoformat()
    a.execute(task_id="task-19",step_key="01.01",gate_checkpoint_no=gate,
              gate_created_at=timestamp,action=action,data=data,approval=hitl,
              hitl_public_key_b64=pub(human),ready_gate=ready,now=now)
    rollback_action={"action_type":COMPENSATION[effect],"effect_class":effect,"target":str(target),
                     "payload_sha256":hashlib.sha256(b'{"operation":"delete"}').hexdigest(),
                     "payload_bytes":22}
    rfp=action_fingerprint(rollback_action);rgate=gate+1
    rready={"task_id":"task-19","step_key":"01.02","checkpoint_no":rgate,
            "verdict":"READY_TO_EXECUTE","action_fingerprint":rfp}
    rap=approval(human,"task-19","01.02",rgate,rfp,a.adapter_id,now,
                 nonce=f"compensation-{effect}-{crashpoint}-nonce")
    kwargs=dict(task_id="task-19",step_key="01.02",gate_checkpoint_no=rgate,
                gate_created_at=timestamp,action=rollback_action,approval=rap,
                hitl_public_key_b64=pub(human),ready_gate=rready,now=now)
    def crash(point):
        if point==crashpoint: raise RuntimeError("injected-crash")
    with pytest.raises(RuntimeError,match="injected-crash"):
        a.compensate(**kwargs,fault_hook=crash)
    restarted=type(a)(a.root,a.ledger.directory,worker,a.adapter_id,effect)
    assert target.exists()==(expected=="exists")
    if expected=="recovered":
        recovered=restarted.compensate(**kwargs)
        assert recovered["status"]=="COMPENSATED_POST_NOT_VERIFIED"
        ok,note=verify_receipt(recovered["receipt"],public_b64=pub(worker),
           task_id="task-19",step_key="01.02",gate_checkpoint_no=rgate,
           action_fingerprint=rfp,target=str(target),gate_created_at=timestamp,
           time_now_ns=int(now*1e9))
        assert ok,note
        target.write_bytes(b'{"foreign":true}')
        with pytest.raises(EffectDenied,match="UNKNOWN_NO_REPLAY"):
            restarted.compensate(**kwargs)
    else:
        with pytest.raises(EffectDenied,match="UNKNOWN_NO_REPLAY"):
            restarted.compensate(**kwargs)

@pytest.mark.parametrize("effect",["E3","E4"])
@pytest.mark.parametrize("mutation",["wrong_digest","wrong_length","missing_digest"])
def test_compensation_payload_mismatch_denied_before_effect(tmp_path,effect,mutation):
    from tools.disposable_effect_adapter import COMPENSATION, ROLLBACK_PAYLOAD
    a,worker,human,data,target,action,ready,hitl,now,gate=fixture(tmp_path,effect)
    timestamp=datetime.fromtimestamp(now,timezone.utc).isoformat()
    a.execute(task_id="task-19",step_key="01.01",gate_checkpoint_no=gate,
              gate_created_at=timestamp,action=action,data=data,approval=hitl,
              hitl_public_key_b64=pub(human),ready_gate=ready,now=now)
    rb={"action_type":COMPENSATION[effect],"effect_class":effect,"target":str(target),
        "payload_sha256":hashlib.sha256(ROLLBACK_PAYLOAD).hexdigest(),
        "payload_bytes":len(ROLLBACK_PAYLOAD)}
    if mutation=="wrong_digest":rb["payload_sha256"]=hashlib.sha256(b"delete-other").hexdigest()
    if mutation=="wrong_length":rb["payload_bytes"]+=1
    if mutation=="missing_digest":rb.pop("payload_sha256")
    fp=action_fingerprint(rb);r_gate=gate+1
    rap=approval(human,"task-19","01.02",r_gate,fp,a.adapter_id,now,nonce="bad-comp-"+mutation+"-"+effect)
    rg={"task_id":"task-19","step_key":"01.02","checkpoint_no":r_gate,
        "verdict":"READY_TO_EXECUTE","action_fingerprint":fp}
    with pytest.raises(EffectDenied,match="COMPENSATION_PAYLOAD_NOT_BOUND"):
        a.compensate(task_id="task-19",step_key="01.02",gate_checkpoint_no=r_gate,
            gate_created_at=timestamp,action=rb,approval=rap,
            hitl_public_key_b64=pub(human),ready_gate=rg,now=now)
    assert target.exists() and a.ledger.claim_status(rap["nonce"],task_id="task-19",
           step_key="01.02",gate_checkpoint_no=r_gate,action_fingerprint=fp,adapter_id=a.adapter_id) is None
