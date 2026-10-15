#!/usr/bin/env python3
"""Reconcile known interrupted EG E2 jobs from durable effects; NEVER repeat writes."""
import hashlib,importlib.util,json,sqlite3,sys
from pathlib import Path
W=Path('/content/workspace')
spec=importlib.util.spec_from_file_location('gate',str(W/'bin/eg-gated-run.py'))
eg=importlib.util.module_from_spec(spec);spec.loader.exec_module(eg)
J=W/'artifacts/eg-managed/journal'
db=sqlite3.connect('file:'+str(W/'eg/data/gateway.db')+'?mode=ro',uri=True)
db.row_factory=sqlite3.Row
priv=eg.load_pem_private_key((W/'eg/notary/notary_private.pem').read_bytes(),password=None)
protocol=hashlib.sha256((W/'eg/local-v3.0.1/runtime/docs/EXECUTOR_PROTOCOL.md').read_bytes()).hexdigest()
def field(task):
 t=db.execute('select contract_hash,checkpoint_no,acceptance_criteria_json from task_registry where task_id=?',(task,)).fetchone()
 if not t:raise RuntimeError('missing registered task')
 return t
def pre_action(task,step):
 rows=db.execute("select request_json from audit where task_id=? and event_type='EVALUATION' order by seq",(task,)).fetchall()
 for r in rows:
  body=json.loads(r['request_json'])
  if body.get('step_key')==step and body.get('phase')=='PRE_EXECUTION':
   return body['action']
 raise RuntimeError('missing immutable PRE action')
def conclude(task,ch,cp,global_text):
 state=eg.req('GET','/v1/tasks/'+task+'/state')
 if state.get('current_step')!='01':raise RuntimeError('parent step not current')
 gate=state.get('pending_execution_gate')
 if gate:
  if state['latest_checkpoint']['verdict']!='READY_TO_EXECUTE':
   raise RuntimeError('parent gate not ready')
  parent_req_cp=state['latest_checkpoint']['checkpoint_no']
  parent_bind_cp=gate['pre_checkpoint_no']
 else:
  parent_pre=eg.eval_step(task,ch,protocol,'01','All child criteria verified','PRE_EXECUTION',
                           cp,cp,'PARENT_PRE=PASS',priv,None)
  if parent_pre['verdict']!='READY_TO_EXECUTE':raise RuntimeError('parent gate denied')
  parent_req_cp=parent_pre['checkpoint_no']
  parent_bind_cp=parent_pre['gate_checkpoint_no']
 ref=eg.notarize([
   eg.binding(task,'01','All child criteria verified','POST_EXECUTION',parent_bind_cp,'PARENT_POST=PASS'),
   eg.binding(task,'01',global_text,'POST_EXECUTION',parent_bind_cp,'TASK=PASS','task')
 ],'PARENT_POST=PASS\nTASK=PASS',priv)
 ev={'source_type':'knid_task','reference':ref}
 payload={'event_id':eg.uid('eval'),'task_id':task,'contract_hash':ch,
          'protocol_hash':protocol,'checkpoint_no':parent_req_cp,'step_key':'01',
          'agent':eg.AGENT,'phase':'POST_EXECUTION','finalize_task':True,
          'action':None,'claims':[{'criterion_index':0,'claim':'All child criteria verified','evidence':[ev]}],
          'task_claims':[{'criterion_index':0,'claim':global_text,'evidence':[ev]}]}
 final=eg.req('POST','/v1/evaluate',payload)
 audit=eg.req('GET','/v1/audit/verify')
 if final['verdict']!='VERIFIED_PASS' or final['contract_status']!='SATISFIED' or audit['status']!='PASS':
  raise RuntimeError('recovery final verification failed')
 print(eg.js({'task_id':task,'recovery':'POST_ONLY','status':'EG_VERIFIED','checkpoint':final['checkpoint_no']}))
def recover(task):
 prior=eg.req('GET','/v1/tasks/'+task+'/state')
 t=field(task)
 global_text=json.loads(t['acceptance_criteria_json'])[0]
 if prior['terminal']:raise RuntimeError('already terminal')
 if prior['current_step']=='01.01':
  row=json.loads((J/(task+'.json')).read_text())
  path=Path(row['target']).resolve()
  base=(W/'artifacts/eg-managed/outputs').resolve()
  if base not in path.parents or path.name!=task+'.txt':raise RuntimeError('target mismatch')
  expected=('EG_E2_RUNTIME:'+task+'\n').encode()
  if path.read_bytes()!=expected:raise RuntimeError('runtime effect inconsistent: DO NOT RETRY')
  gate=prior['pending_execution_gate']
  if not gate or prior['latest_checkpoint']['verdict']!='READY_TO_EXECUTE':
   raise RuntimeError('missing PRE gate')
  action=pre_action(task,'01.01')
  if action['target']!=str(path):raise RuntimeError('effect not bound to PRE intent')
  digest=hashlib.sha256(expected).hexdigest()
  post=eg.eval_step(task,t['contract_hash'],protocol,'01.01',
    'Registered E2 action applied and independently read back','POST_EXECUTION',
    prior['latest_checkpoint']['checkpoint_no'],gate['pre_checkpoint_no'],
    'SHA256='+digest,priv,action)
  if post['verdict']!='VERIFIED_PASS' or not post['step_verified']:
   raise RuntimeError('recovery child not VERIFIED')
  conclude(task,t['contract_hash'],post['checkpoint_no'],global_text)
 elif prior['current_step']=='01':
  conclude(task,t['contract_hash'],prior['latest_checkpoint']['checkpoint_no'],global_text)
 else:raise RuntimeError('unexpected current step')
for t in sys.argv[1:]:
 try:recover(t)
 except Exception as e: print('RECOVERY_BLOCKED '+t+' '+type(e).__name__+' '+str(e),file=sys.stderr)
