#!/usr/bin/env python3
"""Autonomous bounded diagnosis / self-repair / revisioned replanning, E2E with EG.

Real code/config artifact is physically created by trusted separated-UID worker
after the 02.01 PRE gate. Only schema-preserving versioned REPLAN is automatic.
Arbitrary project debugging still requires a connected reasoning agent.
"""
import json,time,sys
from urllib.error import HTTPError
import run_trusted_e2e as X

ORDER=['01.01','01.02','01.03','01','02.01','02.02','02','03.01','03.02','03']
TITLES={
  '01':'Diagnose causal state',
  '01.01':'Confirm blocker and trigger step',
  '01.02':'Identify causal step and last-known-good state',
  '01.03':'Determine recoverability and recovery strategy',
  '02':'Recover',
  '02.01':'Execute recovery action or establish it cannot be safely completed',
  '02.02':'Verify recovered state or confirm no verified recovery state exists',
  '03':'Resume decision',
  '03.01':'Verify original trigger step can proceed or confirm it remains impossible',
  '03.02':'Final remedial outcome'
}
def reg_original(kind):
    task=X.PROJECT+'-'+kind+'-original'
    criterion='Readback repaired configuration is valid'
    steps=[{'step_key':'01','title':'Finalize repaired config',
            'acceptance_criteria':['Every step repaired and proven'],'required':True,"execution_required":False},
           {'step_key':'01.01','title':'Validate configuration parser',
            'acceptance_criteria':[criterion],'required':True,"execution_required":False}]
    registered=X.eg_req('POST','/v1/tasks/register',{
      'event_id':X.id('register'),'task_id':task,'task_kind':'NORMAL',
      'protocol_hash':X.PH,'agent':'EGHardeningE2ETest',
      'original_instruction':'Recover actual malformed configuration without relaxing acceptance',
      'acceptance_criteria':[X.GLOBAL],'steps':steps})
    return task,registered['contract_hash'],criterion
def manual_post_failure(task,ch,crit,cp,gate):
    expected='CONFIG_VALIDATED=YES'
    ev=X.notarize([X.binding(task,'01.01',crit,'POST_EXECUTION',gate,expected)],
                  'CONFIG_VALIDATED=NO; malformed JSON')
    body={'event_id':X.id('fail'),'task_id':task,'contract_hash':ch,
         'protocol_hash':X.PH,'checkpoint_no':cp,'step_key':'01.01',
         'agent':'EGHardeningE2ETest','phase':'POST_EXECUTION','action':None,
         'finalize_task':False,'claims':[{'criterion_index':0,'claim':crit,'evidence':[ev]}],
         'task_claims':[]}
    return X.eg_req('POST','/v1/evaluate',body)
def remediate(original,origin_cp,strategy,revision):
    task=X.PROJECT+'-'+strategy.lower()+'-remedial'
    X.PRE_CRIT['02.01']='Independent readiness to perform a bounded remedial repair'
    steps=[{'step_key':k,'title':TITLES[k],
            'acceptance_criteria':[k+' evidenced'],'required':True,
            'execution_required':k=='02.01',
            **({'preconditions':[X.PRE_CRIT['02.01']]} if k=='02.01' else {})}
           for k in ['01','01.01','01.02','01.03','02','02.01','02.02',
                     '03','03.01','03.02']]
    result=X.eg_req('POST','/v1/tasks/register',{
      'event_id':X.id('register'),'task_id':task,'protocol_hash':X.PH,
      'agent':'EGHardeningE2ETest','task_kind':'REMEDIAL',
      'remedial_for_task_id':original,'remedial_trigger_step_key':'01.01',
      'remedial_origin_checkpoint_no':origin_cp,'remedial_attempt':1,
      'original_instruction':'Repair only within original acceptance and immutable baseline',
      'acceptance_criteria':[X.GLOBAL],'steps':steps})
    ch=result['contract_hash'];cp=0;repair_file=None
    for index,key in enumerate(ORDER,1):
        crit=key+' evidenced'
        target=None;action=None;corrected=None
        if key=='02.01':
            target=X.target(task,key)
            # Produce and validate the immutable repair artifact BEFORE PRE.
            manifest={'design_version':revision,'recovery_strategy':strategy,
                      'original_task':original,
                      'acceptance_preserved':'Readback repaired configuration is valid',
                      'configuration':{'mode':'strict','enabled':True}}
            corrected=(json.dumps(manifest,sort_keys=True)+'\n').encode()
            json.loads(corrected)
            action=X.e2_action(task,key,cp,target,payload=corrected)
        pre=X.eval_step(task,ch,key,crit,'PRE_EXECUTION',cp,cp,action)
        assert pre['verdict']=='READY_TO_EXECUTE',(key,pre)
        proof=None
        if key=='02.01':
            signed=X.worker(task,key,action,corrected)
            assert signed['status']=='PASS',signed
            proof=signed['receipt']
            repair_file=target
            assert json.loads(target.read_bytes())['configuration']['enabled'] is True
        extra=({'remedial_outcome':'RECOVERED',
                'recovery_strategy':strategy} if key=='03' else None)
        post=X.eval_step(task,ch,key,crit,'POST_EXECUTION',
             pre['checkpoint_no'],pre['gate_checkpoint_no'],
             action,final=(key=='03'),receipt=proof,extra=extra)
        assert post['verdict']=='VERIFIED_PASS' and post['step_verified'],(key,post)
        cp=post['checkpoint_no']
    state=X.eg_req('GET','/v1/tasks/'+task+'/state')
    assert state['terminal'] and state['contract_status']=='SATISFIED'
    return task,repair_file,cp
def scenario(strategy,revision):
    kind='autofix' if strategy=='LOCAL_REPAIR' else 'adaptive-replan'
    original,ch,criterion=reg_original(kind)
    # Real design defect: invalid JSON cannot satisfy original parser criterion.
    broken='{bad unclosed json'
    try: json.loads(broken)
    except json.JSONDecodeError:diagnosed=True
    else:diagnosed=False
    assert diagnosed
    pre=X.eval_step(original,ch,'01.01',criterion,'PRE_EXECUTION',0,0,None)
    assert pre['verdict']=='READY_TO_EXECUTE'
    cp=pre['checkpoint_no']
    for attempt in range(3):
        failed=manual_post_failure(original,ch,criterion,cp,pre['gate_checkpoint_no'])
        assert failed['verdict']=='UNVERIFIED',failed
        cp=failed['checkpoint_no']
    state=X.eg_req('GET','/v1/tasks/'+original+'/state')
    assert state['next_action']=='REGISTER_REMEDIAL',state
    rem,repaired,rem_cp=remediate(original,cp,strategy,revision)
    resumed=X.eg_req('GET','/v1/tasks/'+original+'/state')
    assert resumed['next_action']=='OBTAIN_PRE',resumed
    # Verify physical worker file is actually repaired and acceptance is unchanged.
    manifest=json.loads(repaired.read_text())
    assert manifest['configuration']['enabled'] and manifest['design_version']==revision
    original_pre=X.eval_step(original,ch,'01.01',criterion,'PRE_EXECUTION',cp,cp,None)
    assert original_pre['verdict']=='READY_TO_EXECUTE',original_pre
    original_post=X.eval_step(original,ch,'01.01',criterion,'POST_EXECUTION',
        original_pre['checkpoint_no'],original_pre['gate_checkpoint_no'],None)
    assert original_post['step_verified']
    parent_pre=X.eval_step(original,ch,'01','Every step repaired and proven',
        'PRE_EXECUTION',original_post['checkpoint_no'],original_post['checkpoint_no'],None)
    parent_post=X.eval_step(original,ch,'01','Every step repaired and proven',
        'POST_EXECUTION',parent_pre['checkpoint_no'],parent_pre['gate_checkpoint_no'],
        None,final=True)
    assert parent_post['contract_status']=='SATISFIED'
    assert X.eg_req('GET','/v1/tasks/'+original+'/state')['terminal'] is True
    return {'original_task':original,'remedial_task':rem,'repair_strategy':strategy,
      'malformed_design_detected':diagnosed,'bounded_failure_count':3,
      'remedial_verified_steps':10,'remedial_checkpoint':rem_cp,
      'original_satisfied_after_repair':True,'acceptance_preserved':True,
      'immutable_revision':revision}
def main():
    X.start()
    a=scenario('LOCAL_REPAIR',1)
    b=scenario('REPLAN',2)
    audit=X.eg_req('GET','/v1/audit/verify')
    report={'auto_repair':a,'adaptive_replan':b,'audit_status':audit['status'],
            'pass':audit['status']=='PASS'}
    path=X.SESSION/'selfrepair_replan_report.json'
    path.write_text(json.dumps(report,indent=2))
    print(json.dumps({'status':'VERIFIED' if report['pass'] else 'FAILED',
         'repair_steps':a['remedial_verified_steps'],
         'replan_steps':b['remedial_verified_steps'],
         'audit':audit['status'],'report':str(path),
         'originals':[a['original_task'],b['original_task']]}))
    return 0 if report['pass'] else 1
if __name__=='__main__':
    try:sys.exit(main())
    finally:X.close()
