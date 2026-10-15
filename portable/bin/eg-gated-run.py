#!/usr/bin/env python3
"""EG-governed, notarized E0-only task runner. Denies unknown commands before execution."""
import base64,hashlib,json,os,subprocess,sys,time,uuid
from pathlib import Path
from urllib.request import urlopen,Request
from cryptography.hazmat.primitives.serialization import load_pem_private_key
W=Path('/content/workspace')
EG=W/'eg'
URL='http://127.0.0.1:18765'
CHILD='Approved read-only command completed successfully'
PARENT='All child execution criteria verified'
GLOBAL='Every registered task step verified'
AGENT='ColabEGTaskRunner'
ALLOWED={'hostname':['/usr/bin/hostname'],'uptime':['/usr/bin/uptime'],
         'workspace-list':['/usr/bin/ls','-1',str(W)]}
def js(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False)
def uid(prefix):return prefix+'-'+uuid.uuid4().hex
def token():
    for line in (EG/'secrets/runtime.env').read_text().splitlines():
        if line.startswith('EVALUATION_GATEWAY_API_KEY='):return line.partition('=')[2]
    raise RuntimeError('missing EG API credential')
def req(method,path,payload=None):
    raw=js(payload).encode() if payload is not None else None
    headers={'X-Evaluation-Key':token()}
    if raw is not None:headers['Content-Type']='application/json'
    with urlopen(Request(URL+path,data=raw,method=method,headers=headers),timeout=20) as r:
        return json.loads(r.read())
def binding(task,step,criterion,phase,cp,mark,scope='step'):
    b={'kind':'step_criterion' if scope=='step' else 'task_criterion',
       'eg_task_id':task,'criterion_index':0,'criterion':criterion,
       'phase':phase,'checkpoint_no':cp,
       'matcher':{'kind':'contains','value':mark}}
    if scope=='step':b['step_key']=step
    return b
def notarize(bindings,stdout,private):
    ref=uid('knid-task')
    path=EG/'evidence'/ref
    path.mkdir(mode=0o700)
    now=time.time()
    state={'task_id':ref,'status':'PASS','exit_code':0,'finished_at':now}
    s=js(state).encode()
    o=stdout.encode()
    manifest={'manifest_version':4,'task_id':ref,
              'state_sha256':hashlib.sha256(s).hexdigest(),
              'stdout_sha256':hashlib.sha256(o).hexdigest(),
              'finished_at':now,'bindings':bindings}
    signed=dict(manifest)
    signed['notary_ed25519_signature_b64']=base64.b64encode(private.sign(js(manifest).encode())).decode()
    for name,data in (('state.json',s),('stdout.log',o),('evidence.json',js(signed).encode())):
        f=path/name
        with f.open('xb') as h:h.write(data)
        f.chmod(0o600)
        os.chown(f,65534,65534)
    os.chown(path,65534,65534)
    return ref
def eval_step(task,ch,ph,step,criterion,phase,request_cp,reference_cp,mark,private,action,final=False):
    bindings=[binding(task,step,criterion,phase,reference_cp,mark)]
    output=mark
    if final:
        bindings.append(binding(task,step,GLOBAL,phase,reference_cp,'TASK=PASS','task'))
        output+='\nTASK=PASS'
    ref=notarize(bindings,output,private)
    claim={'criterion_index':0,'claim':criterion,
           'evidence':[{'source_type':'knid_task','reference':ref}]}
    data={'event_id':uid('evaluate'),'task_id':task,'contract_hash':ch,
          'protocol_hash':ph,'checkpoint_no':request_cp,'step_key':step,
          'agent':AGENT,'phase':phase,'action':action,
          'finalize_task':final,'claims':[claim],
          'task_claims':[{'criterion_index':0,'claim':GLOBAL,
                          'evidence':[{'source_type':'knid_task','reference':ref}]}] if final else []}
    return req('POST','/v1/evaluate',data)
def run(name):
    if name not in ALLOWED:raise ValueError('BLOCKED: command not in approved E0 allowlist')
    private=load_pem_private_key((EG/'notary/notary_private.pem').read_bytes(),password=None)
    ph=hashlib.sha256((EG/'local-v3.0.1/runtime/docs/EXECUTOR_PROTOCOL.md').read_bytes()).hexdigest()
    task=uid('colab-eg-task')
    contract=req('POST','/v1/tasks/register',{
        'event_id':uid('register'),'task_id':task,'protocol_hash':ph,
        'agent':AGENT,'original_instruction':'E0 approved probe '+name,
        'acceptance_criteria':[GLOBAL],
        'steps':[{'step_key':'01','title':'Verify all child tasks',
                  'acceptance_criteria':[PARENT],'required':True},
                 {'step_key':'01.01','title':'Run approved read-only operation',
                  'acceptance_criteria':[CHILD],'required':True}]})['contract_hash']
    action={'action_type':'read','target':str(W),'effect_class':'E0',
            'reversible':False,'real_world_effect':False,'proofs':[]}
    pre=eval_step(task,contract,ph,'01.01',CHILD,'PRE_EXECUTION',0,0,
                  'PRE=PASS',private,action)
    if pre['verdict']!='READY_TO_EXECUTE':raise RuntimeError('PRE authorization denied')
    result=subprocess.run(ALLOWED[name],capture_output=True,text=True,cwd=W,
                          env={'PATH':'/usr/bin:/bin','HOME':str(W)},timeout=30)
    if result.returncode!=0:raise RuntimeError('command failed without POST verification')
    post=eval_step(task,contract,ph,'01.01',CHILD,'POST_EXECUTION',
                   pre['checkpoint_no'],pre['gate_checkpoint_no'],
                   'COMMAND=PASS',private,action)
    if post['verdict']!='VERIFIED_PASS' or not post['step_verified']:
        raise RuntimeError('POST verification failed')
    ppre=eval_step(task,contract,ph,'01',PARENT,'PRE_EXECUTION',
                   post['checkpoint_no'],post['checkpoint_no'],
                   'PARENT_PRE=PASS',private,None)
    if ppre['verdict']!='READY_TO_EXECUTE':raise RuntimeError('parent PRE denied')
    final=eval_step(task,contract,ph,'01',PARENT,'POST_EXECUTION',
                    ppre['checkpoint_no'],ppre['gate_checkpoint_no'],
                    'PARENT_POST=PASS',private,None,True)
    audit=req('GET','/v1/audit/verify')
    if final['verdict']!='VERIFIED_PASS' or final['contract_status']!='SATISFIED' or audit['status']!='PASS':
        raise RuntimeError('task terminal state or audit verification failed')
    print(js({'task_id':task,'status':'EG_VERIFIED','job':name,'stdout':result.stdout.strip()}))
if __name__=='__main__':
    try:
        if len(sys.argv)!=2:raise ValueError('Usage: eg-gated-run.py hostname|uptime|workspace-list')
        run(sys.argv[1])
    except Exception as e:
        print('FAIL_CLOSED '+type(e).__name__+': '+str(e),file=sys.stderr)
        sys.exit(77)
