"""Independent execution receipt security regressions for EG vNext."""
import base64,time,datetime,secrets
import pytest
import harness as H
from harness import gw,CLIENT,HEAD,register,do_pre,do_post,e2_action,claim,step_ref,raw_eval
from app.execution_receipts import body,sign,verify

def receipt(task,pre,action,key='01.01',signer=None,offset_ns=0,target=None):
    data=body(task,key,pre['gate_checkpoint_no'],
              gw.action_fingerprint(gw.Action(**action)),'trusted-worker-fixture',
              action['target'] if target is None else target,
              b'AUTHORIZED_RUNTIME',secrets.token_urlsafe(24),
              completed_ns=time.time_ns()+offset_ns)
    return sign(data,H.EXEC_PRIV if signer is None else signer)

def post_req(task,ch,pre,action,extra=None):
    j=pre.json()
    return raw_eval(task,ch,j['checkpoint_no'],claims=[
        claim(step_ref(task,'POST_EXECUTION',j['gate_checkpoint_no']))],
        phase='POST_EXECUTION',action=action,**(extra or {}))

def test_mutating_post_without_receipt_rejected_even_with_signed_evidence():
    task,ch=register();action=e2_action(task,0)
    pre,_=do_pre(task,ch,0,action=action)
    r=post_req(task,ch,pre,action)
    assert r.status_code==409
    assert r.json()['detail']['code']=='EXECUTION_RECEIPT_MISSING_OR_INVALID_SCHEMA'
    state=CLIENT.get(f'/v1/tasks/{task}/state',headers=HEAD).json()
    assert state['latest_checkpoint']['checkpoint_no']==1
    assert state['pending_execution_gate']

def test_notary_key_cannot_impersonate_execution_worker():
    task,ch=register();action=e2_action(task,0)
    pre,_=do_pre(task,ch,0,action=action);j=pre.json()
    forged=receipt(task,j,action,signer=H.PRIV)
    r=post_req(task,ch,pre,action,{'execution_receipt':forged})
    assert r.status_code==409
    assert r.json()['detail']['code']=='EXECUTION_RECEIPT_INVALID_SIGNATURE'

def test_cross_step_and_action_bound_and_gate_nonce():
    task,ch=register();action=e2_action(task,0)
    pre,_=do_pre(task,ch,0,action=action);j=pre.json()
    foreign=receipt(task,j,action,key='01.02')
    r=post_req(task,ch,pre,action,{'execution_receipt':foreign})
    assert r.status_code==409
    assert r.json()['detail']['code']=='EXECUTION_RECEIPT_GATE_OR_ACTION_MISMATCH'
    wrong_target=receipt(task,j,action,target='an-injected-target')
    r=post_req(task,ch,pre,action,{'execution_receipt':wrong_target})
    assert r.status_code==409

def test_prior_timestamp_rejected_without_consuming_gate():
    task,ch=register();action=e2_action(task,0)
    pre,_=do_pre(task,ch,0,action=action);j=pre.json()
    old=receipt(task,j,action,offset_ns=-int(5e9))
    r=post_req(task,ch,pre,action,{'execution_receipt':old})
    assert r.status_code==409
    assert r.json()['detail']['code']=='EXECUTION_RECEIPT_PREDATES_GATE'
    fresh=receipt(task,j,action)
    good=post_req(task,ch,pre,action,{'execution_receipt':fresh})
    assert good.status_code==200 and good.json()['verdict']=='VERIFIED_PASS'
    assert CLIENT.get('/v1/audit/verify',headers=HEAD).json()['status']=='PASS'

def test_future_timestamp_and_tampered_output_denied():
    task,ch=register();action=e2_action(task,0)
    pre,_=do_pre(task,ch,0,action=action);j=pre.json()
    future=receipt(task,j,action,offset_ns=int(65e9))
    x=post_req(task,ch,pre,action,{'execution_receipt':future})
    assert x.status_code==409
    assert x.json()['detail']['code']=='EXECUTION_RECEIPT_FUTURE_TIMESTAMP'
    modified=receipt(task,j,action);modified['output_sha256']='f'*64
    x=post_req(task,ch,pre,action,{'execution_receipt':modified})
    assert x.status_code==409
    assert x.json()['detail']['code']=='EXECUTION_RECEIPT_INVALID_SIGNATURE'

def test_worker_and_notary_trust_roots_must_differ(monkeypatch):
    monkeypatch.setattr(gw,'EXECUTOR_PUBLIC_KEY_B64',gw.NOTARY_PUBLIC_KEY_B64)
    with pytest.raises(RuntimeError,match='independent executor trust root'):
        gw.require_config()

def test_nonmutating_action_disallows_unrelated_receipt():
    task,ch=register();pre,_=do_pre(task,ch,0)
    j=pre.json()
    action={'action_type':'read','target':'test','effect_class':'E0',
            'reversible':False,'real_world_effect':False,'proofs':[]}
    extra=receipt(task,j,action)
    r=post_req(task,ch,pre,None,{'execution_receipt':extra})
    assert r.status_code==409
    assert r.json()['detail']['code']=='EXECUTION_RECEIPT_FOR_LOGICAL_STEP_WITHOUT_ACTION'


def test_E0_concrete_read_requires_same_independent_execution_receipt():
    task,ch=register()
    action={'action_type':'read','target':'bounded-test-file.txt','effect_class':'E0',
            'reversible':False,'real_world_effect':False,'proofs':[]}
    pre,_=do_pre(task,ch,0,action=action)
    denied=post_req(task,ch,pre,action)
    assert denied.status_code==409
    assert denied.json()['detail']['code']=='EXECUTION_RECEIPT_MISSING_OR_INVALID_SCHEMA'
    verified,_=do_post(task,ch,pre,action=action)
    assert verified.status_code==200 and verified.json()['verdict']=='VERIFIED_PASS'
