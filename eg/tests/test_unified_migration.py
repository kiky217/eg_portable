"""Migration compatibility: old immutable task protocol, one stricter runtime.

All tests use ONE EG instance and local isolated test fixture DB. Historical
contract hashes never select an older evaluator implementation or bypass
independent executor receipt verification.
"""
from harness import gw,CLIENT,HEAD,register,raw_eval,claim,step_ref,eid


def test_registered_legacy_hash_still_uses_same_new_evaluator(monkeypatch):
    old='8'*64
    new=gw.protocol_hash
    monkeypatch.setattr(gw,'protocol_hash',lambda:old)
    task,ch=register()
    monkeypatch.setattr(gw,'protocol_hash',new)
    ref=step_ref(task,'PRE_EXECUTION',0)
    request={'event_id':eid('old-proto'),'task_id':task,'contract_hash':ch,
        'protocol_hash':old,'checkpoint_no':0,'step_key':'01.01',
        'agent':'ChatGPT','phase':'PRE_EXECUTION','action':None,
        'claims':[claim(ref)],'task_claims':[]}
    result=CLIENT.post('/v1/evaluate',headers=HEAD,json=request)
    assert result.status_code==200 and result.json()['verdict']=='READY_TO_EXECUTE'
    assert gw._registered_protocol_hash(gw.conn(),task)==old
    assert CLIENT.get('/v1/audit/verify',headers=HEAD).json()['status']=='PASS'


def test_wrong_hash_cannot_hijack_existing_task():
    task,ch=register()
    ref=step_ref(task,'PRE_EXECUTION',0)
    request={'event_id':eid('bad-proto'),'task_id':task,'contract_hash':ch,
       'protocol_hash':'9'*64,'checkpoint_no':0,'step_key':'01.01',
       'agent':'ChatGPT','phase':'PRE_EXECUTION','action':None,
       'claims':[claim(ref)],'task_claims':[]}
    response=CLIENT.post('/v1/evaluate',headers=HEAD,json=request)
    assert response.status_code==428 and response.json()['detail']['code']=='IMMUTABLE_TASK_PROTOCOL_MISMATCH'


def test_disabled_admission_refuses_all_concrete_actions(monkeypatch):
    task,ch=register()
    monkeypatch.setattr(gw,'ADMISSION_MODE','disabled')
    monkeypatch.setattr(gw,'EXECUTOR_PUBLIC_KEY_B64','')
    gw.require_config()
    action={'action_type':'read','target':'bounded-test.txt',
            'effect_class':'observation','reversible':False,'real_world_effect':False,'proofs':[]}
    ref=step_ref(task,'PRE_EXECUTION',0)
    response=raw_eval(task,ch,0,claims=[claim(ref)],action=action)
    assert response.status_code==409
    assert response.json()['detail']['code']=='TRUSTED_EXECUTOR_UNAVAILABLE_FAIL_CLOSED'
    s=CLIENT.get('/v1/tasks/'+task+'/state',headers=HEAD).json()
    assert s['latest_checkpoint'] is None
    assert CLIENT.get('/v1/audit/verify',headers=HEAD).json()['status']=='PASS'


def test_enabled_mode_requires_real_executor_trust(monkeypatch):
    monkeypatch.setattr(gw,'ADMISSION_MODE','enabled')
    monkeypatch.setattr(gw,'EXECUTOR_PUBLIC_KEY_B64','')
    import pytest
    with pytest.raises(RuntimeError,match='executor public key missing'):
        gw.require_config()
