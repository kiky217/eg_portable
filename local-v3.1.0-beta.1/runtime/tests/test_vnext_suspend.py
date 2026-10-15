"""New EG vNext regression tests: indefinite PAUSED/RESUMING and safe recovery."""
import pytest
import harness as H
from harness import gw,CLIENT,HEAD,register,do_pre,do_post,raw_eval,claim,step_ref,eid

def req(task,ch,cp,phase,event=None):
    return CLIENT.post(f'/v1/tasks/{task}/{phase}',headers=HEAD,json={
        'event_id':event or eid(phase),'contract_hash':ch,
        'protocol_hash':gw.protocol_hash(),'checkpoint_no':cp,
        'reason':'Operator rest or agent exhausted tokens; no deadline'})

def test_pause_before_pre_blocks_unsafe_execution_then_resume():
    task,ch=register()
    p=req(task,ch,0,'pause')
    assert p.status_code==200 and p.json()['status']=='PAUSED' and p.json()['indefinite']
    s=CLIENT.get(f'/v1/tasks/{task}/state',headers=HEAD).json()
    assert s['next_action']=='RESUME_AFTER_RECONCILIATION'
    assert raw_eval(task,ch,0,claims=[claim(step_ref(task,'PRE_EXECUTION',0))]).status_code==409
    r=req(task,ch,0,'resume')
    assert r.status_code==200 and r.json()['status']=='IN_PROGRESS'
    pre,_=do_pre(task,ch,0)
    assert pre.json()['verdict']=='READY_TO_EXECUTE'
    post,_=do_post(task,ch,pre)
    assert post.json()['step_verified']
    assert CLIENT.get('/v1/audit/verify',headers=HEAD).json()['status']=='PASS'

def test_pause_after_pre_resumes_recovery_pending_and_pre_is_denied():
    task,ch=register()
    pre,_=do_pre(task,ch,0)
    assert pre.json()['verdict']=='READY_TO_EXECUTE'
    assert req(task,ch,1,'pause').json()['status']=='PAUSED'
    r=req(task,ch,1,'resume')
    assert r.status_code==200 and r.json()['status']=='RECOVERY_PENDING'
    state=CLIENT.get(f'/v1/tasks/{task}/state',headers=HEAD).json()
    assert state['next_action']=='RECONCILE_EXISTING_EXECUTION'
    assert state['pending_execution_gate']['pre_checkpoint_no']==1
    forbidden=raw_eval(task,ch,1,claims=[claim(step_ref(task,'PRE_EXECUTION',1))])
    assert forbidden.status_code==409
    assert forbidden.json()['detail']['code']=='RECOVERY_PENDING_NO_NEW_EXECUTION'
    post,_=do_post(task,ch,pre)
    assert post.status_code==200 and post.json()['step_verified']
    state=CLIENT.get(f'/v1/tasks/{task}/state',headers=HEAD).json()
    assert state['status']=='IN_PROGRESS'
    assert CLIENT.get('/v1/audit/verify',headers=HEAD).json()['status']=='PASS'

def test_pause_idempotent_and_stale_checkpoint_rejected():
    task,ch=register()
    event=eid('paused')
    p=req(task,ch,0,'pause',event=event)
    assert p.status_code==200
    q=req(task,ch,0,'pause',event=event)
    assert q.status_code==200 and q.json()['idempotent_replay'] is True
    stale=req(task,ch,1,'resume')
    assert stale.status_code==409
    good=req(task,ch,0,'resume')
    assert good.status_code==200
    dup=req(task,ch,0,'resume')
    assert dup.status_code==409

def test_no_cross_task_suspend_or_wrong_contract():
    task,ch=register();other,otherch=register()
    bad=CLIENT.post(f'/v1/tasks/{task}/pause',headers=HEAD,json={
        'event_id':eid('wrong'),'contract_hash':otherch,'protocol_hash':gw.protocol_hash(),
        'checkpoint_no':0,'reason':'cross task'})
    assert bad.status_code==409
    assert CLIENT.get('/v1/audit/verify',headers=HEAD).json()['status']=='PASS'
