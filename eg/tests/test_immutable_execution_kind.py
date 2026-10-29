"""Execution-required steps cannot be converted to logical checks after intake."""
from harness import CLIENT, HEAD, gw, eid, raw_eval, step_ref, claim

def test_immutable_action_required_rejects_null_before_checkpoint():
    task=eid("physical-step")
    body={
        "event_id":eid("reg"),"task_id":task,"protocol_hash":gw.protocol_hash(),
        "agent":"ChatGPT","original_instruction":"create an output via admitted executor",
        "acceptance_criteria":["output was created by executor"],
        "steps":[
            {"step_key":"01","title":"Parent", "acceptance_criteria":["parent verification"],"execution_required":False},
            {"step_key":"01.01","title":"Verify physical work",
             "preconditions":["ready to create output"],
             "acceptance_criteria":["output is created"],"execution_required":True}
        ],
    }
    registered=CLIENT.post("/v1/tasks/register",headers=HEAD,json=body)
    assert registered.status_code==200,registered.text
    contract=registered.json()["contract_hash"]
    ref=step_ref(task,"PRE_EXECUTION",0,step="01.01",criteria=[(0,"output is created")])
    for phase in ("PRE_EXECUTION","POST_EXECUTION"):
        response=raw_eval(task,contract,0,step="01.01",phase=phase,
                          claims=[claim(ref,0,"output is created")],action=None)
        assert response.status_code==409,response.text
        assert response.json()["detail"]["code"]=="IMMUTABLE_STEP_REQUIRES_ACTION"
    state=CLIENT.get("/v1/tasks/"+task+"/state",headers=HEAD).json()
    assert state["latest_checkpoint"] is None
    assert CLIENT.get("/v1/audit/verify",headers=HEAD).json()["status"]=="PASS"

def test_action_step_cannot_register_without_independent_preconditions():
    task=eid("physical-missing-pre")
    body={"event_id":eid("reg"),"task_id":task,"protocol_hash":gw.protocol_hash(),
          "agent":"ChatGPT","original_instruction":"create an output",
          "acceptance_criteria":["output verified"],
          "steps":[{"step_key":"01","title":"Parent","acceptance_criteria":["parent"],"execution_required":False},
                   {"step_key":"01.01","title":"Physical action",
                    "acceptance_criteria":["output exists"],"execution_required":True}]}
    response=CLIENT.post("/v1/tasks/register",headers=HEAD,json=body)
    assert response.status_code==422,response.text
    assert CLIENT.get("/v1/audit/verify",headers=HEAD).json()["status"]=="PASS"

def test_preexisting_physical_effect_cannot_be_laundered_by_null_action(tmp_path,monkeypatch):
    target=tmp_path/"preexisting.txt"
    target.write_text("OK")
    task=eid("retrospective-physical")
    body={"event_id":eid("reg"),"task_id":task,"protocol_hash":gw.protocol_hash(),
          "agent":"ChatGPT","original_instruction":"create an output with trusted executor",
          "acceptance_criteria":["executor-receipted output"],
          "steps":[
              {"step_key":"01","title":"Parent","execution_required":False,
               "acceptance_criteria":["parent verified"]},
              {"step_key":"01.01","title":"Physical work",
               "execution_required":True,
               "preconditions":["baseline reviewed"],
               "acceptance_criteria":["output exists"]}]}
    reg=CLIENT.post("/v1/tasks/register",headers=HEAD,json=body)
    assert reg.status_code==200,reg.text
    ch=reg.json()["contract_hash"]
    pre_ref=step_ref(task,"PRE_EXECUTION",0,step="01.01",
                     criteria=[(0,"baseline reviewed")])
    request={"claims":[claim(pre_ref,0,"baseline reviewed")],
             "action":None}
    first=raw_eval(task,ch,0,step="01.01",**request)
    assert first.status_code==409
    assert first.json()["detail"]["code"]=="IMMUTABLE_STEP_REQUIRES_ACTION"
    monkeypatch.setattr(gw,"ADMISSION_MODE","disabled")
    monkeypatch.setattr(gw,"EXECUTOR_PUBLIC_KEY_B64","")
    again=raw_eval(task,ch,0,step="01.01",**request)
    assert again.status_code==409
    assert again.json()["detail"]["code"]=="IMMUTABLE_STEP_REQUIRES_ACTION"
    assert CLIENT.get("/v1/tasks/"+task+"/state",headers=HEAD).json()["latest_checkpoint"] is None
    assert target.read_text()=="OK"
    assert CLIENT.get("/v1/audit/verify",headers=HEAD).json()["status"]=="PASS"


def test_new_step_registration_without_explicit_classification_is_rejected():
    task=eid("implicit-logical-forbidden")
    body={"event_id":eid("reg"),"task_id":task,"protocol_hash":gw.protocol_hash(),
          "agent":"ChatGPT","original_instruction":"work",
          "acceptance_criteria":["finished"],
          "steps":[{"step_key":"01","title":"Parent",
                    "acceptance_criteria":["parent"]},
                   {"step_key":"01.01","title":"Child",
                    "acceptance_criteria":["child"]}]}
    result=CLIENT.post("/v1/tasks/register",headers=HEAD,json=body)
    assert result.status_code==422,result.text

def test_new_logical_high_effect_cannot_get_actionable_pre(monkeypatch):
    import hashlib,base64,json,time
    from harness import register,raw_eval,claim,step_ref,CLIENT,HEAD,gw
    from tools.signed_hitl_approval import canonical
    from tools.high_effect_admission import action_fingerprint
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
    task,ch=register()
    human=Ed25519PrivateKey.generate()
    key=base64.b64encode(human.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
    action={"action_type":"sandbox_cutover","effect_class":"governed_operation","target":"/sandbox/fixture.json",
            "reversible":True,"real_world_effect":True,"payload_sha256":hashlib.sha256(b"{}").hexdigest(),
            "payload_bytes":2,"proofs":[]}
    cap={"adapter_id":"trusted-adapter-fixture","action_type":"sandbox_cutover","effect_class":"governed_operation",
        "target_prefix":"/sandbox/","maximum_payload_bytes":524288,
        "isolated":True,"public_key_b64":gw.EXECUTOR_PUBLIC_KEY_B64}
    monkeypatch.setattr(gw,"HIGH_EFFECT_CI_FIXTURE_ENABLED",True)
    monkeypatch.setattr(gw,"HIGH_EFFECT_CAPABILITIES_JSON",json.dumps([cap]))
    monkeypatch.setattr(gw,"HITL_PUBLIC_KEY_B64",key)
    now=time.time();payload={"version":1,"task_id":task,"step_key":"01.01","gate_checkpoint_no":1,
        "action_fingerprint":action_fingerprint(action),"adapter_id":"trusted-adapter-fixture",
        "decision":"APPROVED","issued_at":now-1,"expires_at":now+120,"nonce":"logical-step-high-effect-001"}
    approval={**payload,"signature_b64":base64.b64encode(human.sign(canonical(payload))).decode()}
    ref=step_ref(task,"PRE_EXECUTION",0)
    r=raw_eval(task,ch,0,action=action,claims=[claim(ref)],hitl_approval=approval)
    assert r.status_code==409 and r.json()["detail"]["code"]=="IMMUTABLE_LOGICAL_STEP_FORBIDS_ACTION"
    assert CLIENT.get(f"/v1/tasks/{task}/state",headers=HEAD).json()["latest_checkpoint"] is None
    assert CLIENT.get("/v1/audit/verify",headers=HEAD).json()["status"]=="PASS"

def test_immutable_logical_step_denies_concrete_read_and_write_pre():
    import harness as H
    for klass in ("observation","bounded_change"):
        task,ch=H.register()
        if klass=="observation":
            action={"action_type":"read","effect_class":"observation",
                "target":str(H.WORKER_OUTPUT/"logical-read.txt"),"reversible":False,
                "real_world_effect":False,"proofs":[]}
        else:
            action=H.bounded_write_action(task,0)
        pre_ref=H.step_ref(task,"PRE_EXECUTION",0)
        result=H.raw_eval(task,ch,0,action=action,claims=[H.claim(pre_ref)])
        assert result.status_code==409,result.text
        assert result.json()["detail"]["code"]=="IMMUTABLE_LOGICAL_STEP_FORBIDS_ACTION"
        state=H.CLIENT.get(f"/v1/tasks/{task}/state",headers=H.HEAD).json()
        assert state["latest_checkpoint"] is None
    assert H.CLIENT.get("/v1/audit/verify",headers=H.HEAD).json()["status"]=="PASS"
