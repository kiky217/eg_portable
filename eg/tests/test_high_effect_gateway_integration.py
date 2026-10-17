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
def signed(k,task,action,adapter,gate,now,step="01.01"):
    b={"version":1,"task_id":task,"step_key":step,"gate_checkpoint_no":gate,
       "action_fingerprint":tool_fp(action),"adapter_id":adapter,"decision":"APPROVED",
       "issued_at":now-1,"expires_at":now+120,"nonce":f"canonical-hitl-{step.replace('.','-')}-{gate}-{tool_fp(action)[:12]}"}
    return {**b,"signature_b64":base64.b64encode(k.sign(canonical(b))).decode()}


HIGH_PRE="high-effect independent baseline ready"

def register_high_effect():
    task=H.eid("physical-high")
    body={"event_id":H.eid("reg"),"task_id":task,"protocol_hash":gw.protocol_hash(),
          "agent":"ChatGPT","original_instruction":"bounded independently reviewed effect",
          "acceptance_criteria":["all steps evidenced"],
          "steps":[{"step_key":"01","title":"parent","acceptance_criteria":["parent criterion"],
                    "required":True,"execution_required":False},
                   {"step_key":"01.01","title":"physical effect",
                    "preconditions":[HIGH_PRE],
                    "acceptance_criteria":[H.CRIT],"required":True,"execution_required":True}]}
    reg=H.CLIENT.post("/v1/tasks/register",headers=H.HEAD,json=body)
    assert reg.status_code==200,reg.text
    return task,reg.json()["contract_hash"]

def high_pre_ref(task,cp,step="01.01"):
    return step_ref(task,"PRE_EXECUTION",cp,step=step,criteria=[(0,HIGH_PRE)])

def high_pre_claim(ref):
    return claim(ref,0,HIGH_PRE)

@pytest.mark.parametrize("effect,atype",[
 ("E3","sandbox_cutover"),("E4","sandbox_critical_update"),("E5","sandbox_irreversible_commit")])
def test_canonical_pre_requires_registered_capability_and_signed_hitl(monkeypatch,effect,atype):
    task,ch=register_high_effect();human=Ed25519PrivateKey.generate();adapter=f"trusted-adapter-{effect.lower()}"
    action={"action_type":atype,"target":f"/tmp/eg-high/{effect}.json","effect_class":effect,
            "reversible":effect!="E5","real_world_effect":True,
            "payload_sha256":hashlib.sha256(b"{}").hexdigest(),"payload_bytes":2,"proofs":[]}
    cap={"adapter_id":adapter,"action_type":atype,"effect_class":effect,"target_prefix":"/tmp/eg-high/",
         "maximum_payload_bytes":524288,"isolated":True,"public_key_b64":gw.EXECUTOR_PUBLIC_KEY_B64}
    monkeypatch.setattr(gw,"HIGH_EFFECT_CI_FIXTURE_ENABLED",True)
    monkeypatch.setattr(gw,"HIGH_EFFECT_CAPABILITIES_JSON",__import__("json").dumps([cap]))
    monkeypatch.setattr(gw,"HITL_PUBLIC_KEY_B64",pub(human))
    ref=high_pre_ref(task,0)
    claims=[high_pre_claim(ref)]
    no=raw_eval(task,ch,0,claims=claims,phase="PRE_EXECUTION",action=action)
    assert no.status_code==200 and no.json()["verdict"]=="REQUIRES_HITL"
    # First PRE consumed checkpoint 1; fresh evidence and approval bind the next canonical gate.
    ref2=high_pre_ref(task,1)
    approval=signed(human,task,action,adapter,2,time.time())
    yes=raw_eval(task,ch,1,claims=[high_pre_claim(ref2)],phase="PRE_EXECUTION",action=action,hitl_approval=approval)
    assert yes.status_code==200 and yes.json()["verdict"]=="READY_TO_EXECUTE"
    assert yes.json()["hitl_approved"] is True and yes.json()["gate_checkpoint_no"]==2

def test_header_hitl_cannot_replace_signed_high_effect_approval(monkeypatch):
    task,ch=register_high_effect();human=Ed25519PrivateKey.generate()
    action={"action_type":"sandbox_cutover","target":"/tmp/eg-high/x.json","effect_class":"E3",
            "reversible":True,"real_world_effect":True,"payload_sha256":hashlib.sha256(b"{}").hexdigest(),"payload_bytes":2,"proofs":[]}
    cap={"adapter_id":"trusted-adapter-e3","action_type":"sandbox_cutover","effect_class":"E3","target_prefix":"/tmp/eg-high/",
         "maximum_payload_bytes":524288,"isolated":True,"public_key_b64":gw.EXECUTOR_PUBLIC_KEY_B64}
    monkeypatch.setattr(gw,"HIGH_EFFECT_CI_FIXTURE_ENABLED",True)
    monkeypatch.setattr(gw,"HIGH_EFFECT_CAPABILITIES_JSON",__import__("json").dumps([cap]))
    monkeypatch.setattr(gw,"HITL_PUBLIC_KEY_B64",pub(human))
    ref=high_pre_ref(task,0)
    headers={**H.HEAD,"X-Evaluation-HITL-Key":H.HITL_KEY}
    r=raw_eval(task,ch,0,claims=[high_pre_claim(ref)],phase="PRE_EXECUTION",action=action,headers=headers)
    assert r.status_code==200 and r.json()["verdict"]=="REQUIRES_HITL"

@pytest.mark.parametrize("effect,atype",[("E3","sandbox_cutover"),("E4","sandbox_critical_update"),("E5","sandbox_irreversible_commit")])
def test_canonical_pre_physical_adapter_receipt_post_chain(monkeypatch,tmp_path,effect,atype):
    import json,os
    from tools.disposable_effect_adapter import DisposableAdapter
    root=tmp_path/"effects";ledger=tmp_path/"ledger";root.mkdir(mode=0o700);ledger.mkdir(mode=0o700)
    task=f"chain-{effect.lower()}-{H.eid('x')}"
    body={"event_id":H.eid("reg"),"task_id":task,"protocol_hash":gw.protocol_hash(),"agent":"ChatGPT",
          "original_instruction":"bounded high effect","acceptance_criteria":["physical effect verified"],
          "steps":[{"step_key":"01","title":"parent","acceptance_criteria":["parent criterion"],"required":True,"execution_required":False},
                   {"step_key":"01.01","title":"effect","preconditions":[HIGH_PRE],"acceptance_criteria":[H.CRIT],"required":True,"execution_required":True}]}
    reg=H.CLIENT.post("/v1/tasks/register",headers=H.HEAD,json=body);assert reg.status_code==200,reg.text
    ch=reg.json()["contract_hash"];human=Ed25519PrivateKey.generate();adapter_id=f"trusted-adapter-{effect.lower()}"
    data=json.dumps({"effect":effect,"ok":True},sort_keys=True).encode();target=root/f"{effect}.json"
    action={"action_type":atype,"target":str(target),"effect_class":effect,"reversible":effect!="E5",
            "real_world_effect":True,"payload_sha256":hashlib.sha256(data).hexdigest(),"payload_bytes":len(data),"proofs":[]}
    cap={"adapter_id":adapter_id,"action_type":atype,"effect_class":effect,"target_prefix":str(root)+"/",
         "maximum_payload_bytes":524288,"isolated":True,"public_key_b64":gw.EXECUTOR_PUBLIC_KEY_B64}
    monkeypatch.setattr(gw,"HIGH_EFFECT_CI_FIXTURE_ENABLED",True)
    monkeypatch.setattr(gw,"HIGH_EFFECT_CAPABILITIES_JSON",json.dumps([cap]));monkeypatch.setattr(gw,"HITL_PUBLIC_KEY_B64",pub(human))
    now=time.time();ap=signed(human,task,{**action},adapter_id,1,now)
    pre_ref=high_pre_ref(task,0,step="01.01")
    pre=raw_eval(task,ch,0,step="01.01",claims=[high_pre_claim(pre_ref)],phase="PRE_EXECUTION",action=action,hitl_approval=ap)
    assert pre.status_code==200 and pre.json()["verdict"]=="READY_TO_EXECUTE",pre.text
    state=H.CLIENT.get(f"/v1/tasks/{task}/state",headers=H.HEAD).json();gate=state["pending_execution_gate"]
    adapter=DisposableAdapter(root,ledger,H.EXEC_PRIV,adapter_id,effect)
    import tools.governed_agent_dispatcher as dispatcher
    def ci_get(_url,_key,_task,suffix):
        assert _task==task
        response=H.CLIENT.get(f"/v1/tasks/{task}"+suffix,headers=H.HEAD)
        assert response.status_code==200,response.text
        return response.json()
    monkeypatch.setattr(dispatcher,"_get",ci_get)
    executed=dispatcher.dispatch_disposable_ci(
        task_id=task,step_key="01.01",action=action,data=data,approval=ap,
        adapter=adapter,eg_url="ci-eg",api_key="ci-api",hitl_public_key_b64=pub(human),
        executor_public_key_b64=pub(H.EXEC_PRIV),ci_only=True)
    assert target.read_bytes()==data and executed["status"]=="RECEIPT_VERIFIED_POST_REQUIRED"
    post_ref=step_ref(task,"POST_EXECUTION",pre.json()["gate_checkpoint_no"],step="01.01")
    post=raw_eval(task,ch,pre.json()["checkpoint_no"],step="01.01",claims=[claim(post_ref)],phase="POST_EXECUTION",
        action=action,execution_receipt=executed["execution_receipt"])
    assert post.status_code==200 and post.json()["verdict"]=="VERIFIED_PASS",post.text
    ppre,_=H.do_pre(task,ch,post.json()["checkpoint_no"],step="01",criteria=[(0,"parent criterion")],stdout="PARENT=PASS",value="PARENT=PASS")
    task_ref=H.task_ref(task,ppre.json()["gate_checkpoint_no"],criterion="physical effect verified")
    ppost,_=H.do_post(task,ch,ppre,step="01",criteria=[(0,"parent criterion")],finalize=True,
        task_claims=[H.task_claim(task_ref,criterion="physical effect verified")],stdout="PARENT=PASS",value="PARENT=PASS")
    assert ppost.status_code==200 and ppost.json()["contract_status"]=="SATISFIED",ppost.text
    assert H.CLIENT.get("/v1/audit/verify",headers=H.HEAD).json()["status"]=="PASS"


@pytest.mark.parametrize("effect,atype,rollback_type",[
 ("E3","sandbox_cutover","sandbox_cutover_rollback"),
 ("E4","sandbox_critical_update","sandbox_critical_update_rollback")])
def test_canonical_compensation_has_its_own_pre_receipt_post(monkeypatch,tmp_path,effect,atype,rollback_type):
    import json
    from tools.disposable_effect_adapter import DisposableAdapter
    root=tmp_path/"effects";ledger=tmp_path/"ledger";root.mkdir(mode=0o700);ledger.mkdir(mode=0o700)
    task=f"rollback-{effect.lower()}-{H.eid('x')}"
    reg=H.CLIENT.post("/v1/tasks/register",headers=H.HEAD,json={
        "event_id":H.eid("reg"),"task_id":task,"protocol_hash":gw.protocol_hash(),"agent":"ChatGPT",
        "original_instruction":"apply then compensate","acceptance_criteria":["rollback verified"],
        "steps":[{"step_key":"01","title":"parent","acceptance_criteria":["parent"],"required":True,"execution_required":False},
                 {"step_key":"01.01","title":"apply","preconditions":[HIGH_PRE],"acceptance_criteria":[H.CRIT],"required":True,"execution_required":True},
                 {"step_key":"01.02","title":"rollback","preconditions":[HIGH_PRE],"acceptance_criteria":[H.CRIT],"required":True,"execution_required":True}]})
    assert reg.status_code==200,reg.text
    ch=reg.json()["contract_hash"];human=Ed25519PrivateKey.generate();adapter_id=f"trusted-adapter-{effect.lower()}"
    data=b'{"applied":true}';target=root/f"{effect}.json"
    apply={"action_type":atype,"target":str(target),"effect_class":effect,"reversible":True,"real_world_effect":True,
           "payload_sha256":hashlib.sha256(data).hexdigest(),"payload_bytes":len(data),"proofs":[]}
    rollback={"action_type":rollback_type,"target":str(target),"effect_class":effect,"reversible":True,"real_world_effect":True,
              "payload_sha256":hashlib.sha256(b'{"operation":"delete"}').hexdigest(),"payload_bytes":22,"proofs":[]}
    caps=[{"adapter_id":adapter_id,"action_type":x["action_type"],"effect_class":effect,"target_prefix":str(root)+"/",
           "maximum_payload_bytes":524288,"isolated":True,"public_key_b64":gw.EXECUTOR_PUBLIC_KEY_B64} for x in (apply,rollback)]
    monkeypatch.setattr(gw,"HIGH_EFFECT_CI_FIXTURE_ENABLED",True)
    monkeypatch.setattr(gw,"HIGH_EFFECT_CAPABILITIES_JSON",json.dumps(caps));monkeypatch.setattr(gw,"HITL_PUBLIC_KEY_B64",pub(human))
    adapter=DisposableAdapter(root,ledger,H.EXEC_PRIV,adapter_id,effect);now=time.time()
    ap=signed(human,task,apply,adapter_id,1,now)
    pre=raw_eval(task,ch,0,step="01.01",claims=[high_pre_claim(high_pre_ref(task,0,step="01.01"))],
                 phase="PRE_EXECUTION",action=apply,hitl_approval=ap)
    assert pre.status_code==200 and pre.json()["verdict"]=="READY_TO_EXECUTE",pre.text
    gate=H.CLIENT.get(f"/v1/tasks/{task}/state",headers=H.HEAD).json()["pending_execution_gate"]
    done=adapter.execute(task_id=task,step_key="01.01",gate_checkpoint_no=pre.json()["gate_checkpoint_no"],
        gate_created_at=gate["created_at"],action=apply,data=data,approval=ap,hitl_public_key_b64=pub(human),ready_gate=gate,now=time.time())
    post=raw_eval(task,ch,pre.json()["checkpoint_no"],step="01.01",
        claims=[claim(step_ref(task,"POST_EXECUTION",pre.json()["gate_checkpoint_no"],step="01.01"))],
        phase="POST_EXECUTION",action=apply,execution_receipt=done["receipt"])
    assert post.status_code==200 and post.json()["verdict"]=="VERIFIED_PASS",post.text
    rgate_no=post.json()["checkpoint_no"]+1;rap=signed(human,task,rollback,adapter_id,rgate_no,time.time(),step="01.02")
    rpre=raw_eval(task,ch,post.json()["checkpoint_no"],step="01.02",
        claims=[high_pre_claim(high_pre_ref(task,post.json()["checkpoint_no"],step="01.02"))],
        phase="PRE_EXECUTION",action=rollback,hitl_approval=rap)
    assert rpre.status_code==200 and rpre.json()["verdict"]=="READY_TO_EXECUTE",rpre.text
    rgate=H.CLIENT.get(f"/v1/tasks/{task}/state",headers=H.HEAD).json()["pending_execution_gate"]
    import tools.governed_agent_dispatcher as dispatcher
    def ci_get(_url,_key,_task,suffix):
        assert _task==task
        response=H.CLIENT.get(f"/v1/tasks/{task}"+suffix,headers=H.HEAD)
        assert response.status_code==200,response.text
        return response.json()
    monkeypatch.setattr(dispatcher,"_get",ci_get)
    undone=dispatcher.dispatch_disposable_ci(
        task_id=task,step_key="01.02",action=rollback,data=b"",approval=rap,
        adapter=adapter,eg_url="ci-eg",api_key="ci-api",hitl_public_key_b64=pub(human),
        executor_public_key_b64=pub(H.EXEC_PRIV),operation="compensate",ci_only=True)
    assert not target.exists()
    rpost=raw_eval(task,ch,rpre.json()["checkpoint_no"],step="01.02",
        claims=[claim(step_ref(task,"POST_EXECUTION",rpre.json()["gate_checkpoint_no"],step="01.02"))],
        phase="POST_EXECUTION",action=rollback,execution_receipt=undone["execution_receipt"])
    assert rpost.status_code==200 and rpost.json()["verdict"]=="VERIFIED_PASS",rpost.text
    assert H.CLIENT.get("/v1/audit/verify",headers=H.HEAD).json()["status"]=="PASS"

@pytest.mark.parametrize("effect,atype",[("E3","sandbox_cutover"),("E4","sandbox_critical_update"),("E5","sandbox_irreversible_commit")])
def test_canonical_post_uses_pinned_per_adapter_key_not_global(monkeypatch,effect,atype):
    import json
    from app.execution_receipts import body,sign
    task,ch=register_high_effect(); human=Ed25519PrivateKey.generate()
    worker=Ed25519PrivateKey.generate()
    adapter="trusted-adapter-independent-"+effect.lower()
    data=b'{"ok":true}'
    action={"action_type":atype,"target":"/tmp/eg-high/"+effect+".json",
            "effect_class":effect,"reversible":effect!="E5","real_world_effect":True,
            "payload_sha256":hashlib.sha256(data).hexdigest(),"payload_bytes":len(data),"proofs":[]}
    cap={"adapter_id":adapter,"action_type":atype,"effect_class":effect,
         "target_prefix":"/tmp/eg-high/","maximum_payload_bytes":524288,
         "isolated":True,"public_key_b64":pub(worker)}
    monkeypatch.setattr(gw,"HIGH_EFFECT_CI_FIXTURE_ENABLED",True)
    monkeypatch.setattr(gw,"HIGH_EFFECT_CAPABILITIES_JSON",json.dumps([cap]))
    monkeypatch.setattr(gw,"HITL_PUBLIC_KEY_B64",pub(human))
    ap=signed(human,task,action,adapter,1,time.time())
    pre=raw_eval(task,ch,0,claims=[high_pre_claim(high_pre_ref(task,0))],action=action,hitl_approval=ap)
    assert pre.status_code==200 and pre.json()["verdict"]=="READY_TO_EXECUTE",pre.text
    pin=pre.json()["high_effect_pin"]
    assert pin["public_key_b64"]==pub(worker) and pin["adapter_id"]==adapter
    gate=H.CLIENT.get(f"/v1/tasks/{task}/state",headers=H.HEAD).json()["pending_execution_gate"]
    receipt=sign(body(task,"01.01",1,tool_fp(action),"trusted-worker-"+adapter,action["target"],
                      data,ap["nonce"]),worker)
    # Rotating the configured registry cannot rotate the original audited PRE key.
    monkeypatch.setattr(gw,"HIGH_EFFECT_CI_FIXTURE_ENABLED",True)
    monkeypatch.setattr(gw,"HIGH_EFFECT_CAPABILITIES_JSON",json.dumps([{**cap,"public_key_b64":gw.EXECUTOR_PUBLIC_KEY_B64}]))
    post=raw_eval(task,ch,1,claims=[claim(step_ref(task,"POST_EXECUTION",1))],
                  phase="POST_EXECUTION",action=action,execution_receipt=receipt)
    assert post.status_code==200 and post.json()["verdict"]=="VERIFIED_PASS",post.text
    assert H.CLIENT.get("/v1/audit/verify",headers=H.HEAD).json()["status"]=="PASS"

@pytest.mark.parametrize("effect,atype",[("E3","sandbox_cutover"),("E4","sandbox_critical_update"),("E5","sandbox_irreversible_commit")])
def test_high_effect_independent_no_effect_reconciliation(monkeypatch,tmp_path,effect,atype):
    import json
    from tools.disposable_effect_adapter import DisposableAdapter,EffectDenied
    from app.no_effect_receipts import verify_no_effect
    from tools.durable_hitl_ledger import ApprovalClaimDenied
    root=tmp_path/"root";journal=tmp_path/"ledger";root.mkdir(mode=0o700);journal.mkdir(mode=0o700)
    task,ch=register_high_effect(); human=Ed25519PrivateKey.generate(); worker=Ed25519PrivateKey.generate()
    adapter_id="trusted-adapter-"+effect.lower();target=root/(effect+".json");data=b'{"ok":true}'
    action={"action_type":atype,"effect_class":effect,"target":str(target),
        "reversible":effect!="E5","real_world_effect":True,
        "payload_sha256":hashlib.sha256(data).hexdigest(),"payload_bytes":len(data),"proofs":[]}
    cap={"adapter_id":adapter_id,"action_type":atype,"effect_class":effect,
         "target_prefix":str(root)+"/","maximum_payload_bytes":524288,
         "isolated":True,"public_key_b64":pub(worker)}
    monkeypatch.setattr(gw,"HIGH_EFFECT_CI_FIXTURE_ENABLED",True)
    monkeypatch.setattr(gw,"HIGH_EFFECT_CAPABILITIES_JSON",json.dumps([cap]))
    monkeypatch.setattr(gw,"HITL_PUBLIC_KEY_B64",pub(human))
    ap=signed(human,task,action,adapter_id,1,time.time())
    pre=raw_eval(task,ch,0,claims=[high_pre_claim(high_pre_ref(task,0))],action=action,hitl_approval=ap)
    assert pre.status_code==200 and pre.json()["verdict"]=="READY_TO_EXECUTE",pre.text
    cp=pre.json()["checkpoint_no"]
    base={"contract_hash":ch,"protocol_hash":gw.protocol_hash(),"checkpoint_no":cp,"reason":"worker never called"}
    assert H.CLIENT.post(f"/v1/tasks/{task}/pause",headers=H.HEAD,json={"event_id":H.eid("pause"),**base}).status_code==200
    assert H.CLIENT.post(f"/v1/tasks/{task}/resume",headers=H.HEAD,json={"event_id":H.eid("resume"),**base}).json()["status"]=="RECOVERY_PENDING"
    gate=H.CLIENT.get(f"/v1/tasks/{task}/state",headers=H.HEAD).json()["pending_execution_gate"]
    a=DisposableAdapter(root,journal,worker,adapter_id,effect)
    proof=a.reconcile_no_effect(task_id=task,step_key="01.01",
         gate_checkpoint_no=cp,action=action,approval=ap,ready_gate=gate,
         hitl_public_key_b64=pub(human))
    assert verify_no_effect(proof,public_b64=pub(worker),task_id=task,step_key="01.01",
         gate_checkpoint_no=cp,action_fingerprint=tool_fp(action),target=str(target),
         gate_created_at=gate["created_at"])
    with pytest.raises(ApprovalClaimDenied,match="RETIRED"):
        a.execute(task_id=task,step_key="01.01",gate_checkpoint_no=cp,
            gate_created_at=gate["created_at"],action=action,data=data,approval=ap,
            hitl_public_key_b64=pub(human),ready_gate=gate,now=time.time())
    req={"event_id":H.eid("reconcile"),"contract_hash":ch,
         "protocol_hash":gw.protocol_hash(),"checkpoint_no":cp,
         "step_key":"01.01","action":action,"proof":proof,
         "executor_public_key_b64":pub(worker)}
    result=H.CLIENT.post(f"/v1/tasks/{task}/reconcile",headers=H.HEAD,json=req)
    assert result.status_code==200 and result.json()["reconciled_effect"]=="NOT_EXECUTED",result.text
    assert H.CLIENT.get("/v1/audit/verify",headers=H.HEAD).json()["status"]=="PASS"

def test_configured_high_effect_without_independent_transport_cannot_be_ready(monkeypatch):
    import json
    task,ch=register();human=Ed25519PrivateKey.generate()
    action={"action_type":"sandbox_cutover","target":"/tmp/eg-high/inert.json",
        "effect_class":"E3","reversible":True,"real_world_effect":True,
        "payload_sha256":hashlib.sha256(b"{}").hexdigest(),"payload_bytes":2,"proofs":[]}
    worker=Ed25519PrivateKey.generate();adapter="trusted-adapter-inert"
    cap={"adapter_id":adapter,"action_type":"sandbox_cutover","effect_class":"E3",
         "target_prefix":"/tmp/eg-high/","maximum_payload_bytes":524288,
         "isolated":True,"public_key_b64":pub(worker)}
    monkeypatch.setattr(gw,"HIGH_EFFECT_CI_FIXTURE_ENABLED",False)
    monkeypatch.setattr(gw,"HIGH_EFFECT_CAPABILITIES_JSON",json.dumps([cap]))
    monkeypatch.setattr(gw,"HITL_PUBLIC_KEY_B64",pub(human))
    ap=signed(human,task,action,adapter,1,time.time())
    denied=raw_eval(task,ch,0,claims=[claim(step_ref(task,"PRE_EXECUTION",0))],
                    action=action,hitl_approval=ap)
    assert denied.status_code==409,denied.text
    assert denied.json()["detail"]["code"]=="UNSUPPORTED_ACTION_CAPABILITY_FAIL_CLOSED"
    p=H.CLIENT.get("/v1/protocol",headers=H.HEAD).json()
    assert p["high_effect_execution_mode"]=="UNPROVISIONED_FAIL_CLOSED"
    assert p["high_effect_capability_catalog"][0]["availability"]=="UNPROVISIONED"
    assert all(x["effect_class"] not in ("E3","E4","E5") for x in p["executor_capabilities"])
