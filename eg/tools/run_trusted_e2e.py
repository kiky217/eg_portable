#!/usr/bin/env python3
"""Separate-UID, real-HTTP adversarial 10-step EG execution receipt integration test.

Canonical EG service is NEVER modified. Ephemeral EG and worker Unix socket
run with different UIDs and distinct Ed25519 private keys. No test secrets logged.
"""
import base64,hashlib,json,os,secrets,socket,subprocess,sys,time,uuid,tempfile
from pathlib import Path
from urllib.request import Request,urlopen
from urllib.error import HTTPError,URLError
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption,PublicFormat
from app.execution_receipts import body as receipt_body,sign as receipt_sign

# Integration test uses THIS EG core, not a second runtime version.
STAGE=Path(__file__).resolve().parents[1]
BASE=Path(os.environ.get('EG_E2E_INSTANCE_DIR',str(Path(tempfile.mkdtemp(prefix='eg-unified-e2e-'))))).resolve()
BASE.mkdir(parents=True,exist_ok=True)
BASE.chmod(0o755)
EG_USER=65534
WORK_USER=65533
EG_PORT=int(os.getenv('EG_E2E_PORT','18766'))
EG_URL=f'http://127.0.0.1:{EG_PORT}'
PROJECT='eg-hardening-10-'+uuid.uuid4().hex[:12]
SESSION=BASE/PROJECT
SESSION.mkdir(parents=True,mode=0o755)
EGROOT=SESSION/'eg'
WORK=SESSION/'worker'
for p,uid,mode in ((EGROOT,EG_USER,0o755),(WORK,WORK_USER,0o755)):
    p.mkdir(mode=mode)
    os.chown(p,uid,uid)
for child in ('evidence','data','anchor'):
    p=EGROOT/child;p.mkdir(mode=0o700);os.chown(p,EG_USER,EG_USER)
for child in ('outputs','journals'):
    p=WORK/child;p.mkdir(mode=0o700);os.chown(p,WORK_USER,WORK_USER)
EG_API=secrets.token_urlsafe(48)
EG_HITL=secrets.token_urlsafe(48)
EG_AUDIT=secrets.token_urlsafe(48)
EG_NOTARY=Ed25519PrivateKey.generate()
EXEC_NOTARY=Ed25519PrivateKey.generate()
def raw_pub(private):
    return base64.b64encode(private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
def priv_bytes(private):
    return private.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption())
executor_key=WORK/'executor-private.pem'
executor_key.write_bytes(priv_bytes(EXEC_NOTARY))
os.chmod(executor_key,0o600);os.chown(executor_key,WORK_USER,WORK_USER)
worker_config=WORK/'worker.json'
sock=WORK/'worker.sock'
worker_config.write_text(json.dumps({'output_root':str(WORK/'outputs'),
   'journal_root':str(WORK/'journals'),'private_key':str(executor_key),
   'eg_url':EG_URL,'eg_api_key':EG_API,
   'executor_id':'trusted-worker-isolated-uid65533','socket_path':str(sock)}))
os.chmod(worker_config,0o600);os.chown(worker_config,WORK_USER,WORK_USER)
environ={**os.environ,
 'EVALUATION_GATEWAY_API_KEY':EG_API,
 'EVALUATION_GATEWAY_HITL_KEY':EG_HITL,
 'EVALUATION_GATEWAY_AUDIT_HMAC_KEY':EG_AUDIT,
 'EVALUATION_GATEWAY_EVIDENCE_PUBLIC_KEY_B64':raw_pub(EG_NOTARY),
 'EVALUATION_GATEWAY_EXECUTOR_PUBLIC_KEY_B64':raw_pub(EXEC_NOTARY),
 'EVALUATION_GATEWAY_EVIDENCE_ROOT':str(EGROOT/'evidence'),
 'EVALUATION_GATEWAY_DB_PATH':str(EGROOT/'data/gateway.db'),
 'EVALUATION_GATEWAY_ANCHOR_PATH':str(EGROOT/'anchor/audit.anchor'),
 'EVALUATION_GATEWAY_TRUSTED_EVIDENCE_UID':str(EG_USER),
 'EVALUATION_GATEWAY_INTEGRITY_CACHE_SECONDS':'0',
 'EVALUATION_GATEWAY_EXECUTOR_OUTPUT_ROOT':str(WORK/'outputs'),
 'PYTHONPATH':str(STAGE)}
def as_uid(uid):
    def switch():
        os.setgroups([]);os.setgid(uid);os.setuid(uid)
    return switch
ep=None;wp=None
def start():
    global ep,wp
    # Suppress sensitive subprocess logs; diagnostics can be read from protected files.
    eglog=open(SESSION/'eg-process.log','ab',buffering=0)
    wlog=open(SESSION/'worker-process.log','ab',buffering=0)
    ep=subprocess.Popen([sys.executable,'-m','uvicorn','app.main:app','--app-dir',str(STAGE),
                         '--host','127.0.0.1','--port',str(EG_PORT),'--no-access-log'],
                        cwd=STAGE,env=environ,preexec_fn=as_uid(EG_USER),
                        stdout=eglog,stderr=subprocess.STDOUT)
    for _ in range(110):
        try:
            if json.loads(urlopen(EG_URL+'/health',timeout=0.4).read()).get('status')=='PASS':break
        except Exception:pass
        if ep.poll() is not None:
            diagnostics=(SESSION/'eg-process.log').read_text(errors='replace')[-2200:]
            for sensitive in (EG_API,EG_HITL,EG_AUDIT,raw_pub(EG_NOTARY),raw_pub(EXEC_NOTARY)):
                diagnostics=diagnostics.replace(sensitive,'[REDACTED]')
            raise RuntimeError('EG_STAGING_FAILED_TO_START: '+diagnostics)
        time.sleep(0.1)
    else:raise RuntimeError('EG_STAGING_HEALTH_TIMEOUT')
    wp=subprocess.Popen([sys.executable,str(STAGE/'tools/trusted_execution_worker.py'),str(worker_config)],
                        cwd=STAGE,env=environ,preexec_fn=as_uid(WORK_USER),
                        stdout=wlog,stderr=subprocess.STDOUT)
    for _ in range(70):
        if sock.exists():break
        if wp.poll() is not None:raise RuntimeError('WORKER_FAILED_TO_START')
        time.sleep(0.1)
    else:raise RuntimeError('WORKER_SOCKET_TIMEOUT')
def denied_direct_agent_socket_access():
    """A separate agent/EG UID cannot bypass the dispatcher to the worker."""
    result=subprocess.run([sys.executable,'-c',
        'import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])',
        str(sock)],preexec_fn=as_uid(EG_USER),capture_output=True,timeout=6)
    if result.returncode==0:
        raise AssertionError('UNTRUSTED_AGENT_CAN_CONNECT_TO_WORKER_SOCKET')
    if b'PermissionError' not in result.stderr:
        raise AssertionError('WORKER_SOCKET_DENIAL_NOT_PROVEN')
    return True

def close():
    for p in (wp,ep):
        if p and p.poll() is None:
            p.terminate()
            try:p.wait(timeout=5)
            except subprocess.TimeoutExpired:p.kill()
def canon(data):return json.dumps(data,sort_keys=True,separators=(',',':'),ensure_ascii=False)
def sha(data):return hashlib.sha256(data).hexdigest()
def id(prefix):return prefix+'-'+uuid.uuid4().hex
def eg_req(method,path,data=None):
    b=canon(data).encode() if data is not None else None
    headers={'X-Evaluation-Key':EG_API}
    if b is not None:headers['Content-Type']='application/json'
    with urlopen(Request(EG_URL+path,data=b,method=method,headers=headers),timeout=15) as r:
        return json.loads(r.read())
def notarize(bindings,text):
    ref=id('knid-task')
    directory=EGROOT/'evidence'/ref
    directory.mkdir(mode=0o700);os.chown(directory,EG_USER,EG_USER)
    now=time.time()
    state=canon({'task_id':ref,'status':'PASS','exit_code':0,'finished_at':now}).encode()
    out=text.encode()
    payload={'manifest_version':4,'task_id':ref,'state_sha256':sha(state),
             'stdout_sha256':sha(out),'finished_at':now,'bindings':bindings}
    signed={**payload,'notary_ed25519_signature_b64':
            base64.b64encode(EG_NOTARY.sign(canon(payload).encode())).decode()}
    for name,raw in (('state.json',state),('stdout.log',out),('evidence.json',canon(signed).encode())):
        p=directory/name;p.write_bytes(raw);os.chown(p,EG_USER,EG_USER);os.chmod(p,0o600)
    return {'source_type':'knid_task','reference':ref}
def binding(task,key,criterion,phase,cp,mark,scope='step'):
    data={'kind':'step_criterion' if scope=='step' else 'task_criterion',
          'eg_task_id':task,'criterion_index':0,'criterion':criterion,
          'phase':phase,'checkpoint_no':cp,'matcher':{'kind':'contains','value':mark}}
    if scope=='step':data['step_key']=key
    return data
def e2_action(task,key,cp,target,payload=None):
    actual=data(task,key) if payload is None else payload
    skeleton={'action_type':'write','target':str(target),'effect_class':'E2',
              'reversible':True,'real_world_effect':False,
              'payload_sha256':hashlib.sha256(actual).hexdigest(),
              'payload_bytes':len(actual),'proofs':[]}
    intent={field:skeleton[field] for field in
       ('action_type','target','effect_class','reversible','real_world_effect',
        'payload_sha256','payload_bytes')}
    fp=sha(canon(intent).encode())
    values={'sandbox_pass':'SANDBOX=PASS','rollback_ready':'ROLLBACK=READY',
            'reversible':'REVERSIBLE=YES'}
    bindings=[{'kind':'action_proof','eg_task_id':task,'step_key':key,
               'purpose':purpose,'action_intent_fingerprint':fp,'phase':'PRE_EXECUTION',
               'checkpoint_no':cp,'matcher':{'kind':'contains','value':mark}}
              for purpose,mark in values.items()]
    ev=notarize(bindings,'\n'.join(values.values()))
    return {**skeleton,'proofs':[{'purpose':purpose,'evidence':ev} for purpose in values]}
def eval_step(task,contract,key,criterion,phase,cp,refcp,action,final=False,receipt=None,extra=None):
    marker=('PRE_'+key+'=PASS' if phase=='PRE_EXECUTION' else 'POST_'+key+'=PASS')
    phase_criterion=(PRE_CRIT[key] if phase=='PRE_EXECUTION' and action is not None else criterion)
    bindings=[binding(task,key,phase_criterion,phase,refcp,marker)]
    if final:bindings.append(binding(task,key,GLOBAL,phase,refcp,'TASK=PASS','task'))
    ev=notarize(bindings,marker+('\nTASK=PASS' if final else ''))
    claims=[{'criterion_index':0,'claim':phase_criterion,'evidence':[ev]}]
    payload={'event_id':id('eval'),'task_id':task,'contract_hash':contract,
       'protocol_hash':PH,'checkpoint_no':cp,'step_key':key,
       'agent':'EGHardeningE2ETest','phase':phase,'action':action,
       'claims':claims,'finalize_task':final,
       'task_claims':[{'criterion_index':0,'claim':GLOBAL,'evidence':[ev]}] if final else []}
    if receipt is not None:payload['execution_receipt']=receipt
    if extra:payload.update(extra)
    return eg_req('POST','/v1/evaluate',payload)
def worker(task,key,action,content):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
        client.settimeout(20);client.connect(str(sock))
        query={'task_id':task,'step_key':key,'action':action,
               'data_b64':base64.b64encode(content).decode()}
        client.sendall(canon(query).encode()+b'\n')
        answer=b''
        while not answer.endswith(b'\n'):
            data=client.recv(8192)
            if not data:break
            answer+=data
    return json.loads(answer)
PH=sha((STAGE/'docs/EXECUTOR_PROTOCOL.md').read_bytes())
GLOBAL='Every canonical step independently and non-retroactively executed and verified'
KEYS=[f'01.{i:02d}' for i in range(1,10)]+['01']
CRIT={k:'Physical runtime evidence for step '+k for k in KEYS}
PRE_CRIT={k:'Independent readiness evidence before physical step '+k for k in KEYS}
def register(label):
    task=PROJECT+'-'+label
    steps=[{'step_key':'01','title':'Final physical step','required':True,'acceptance_criteria':[CRIT['01']], 'preconditions':[PRE_CRIT['01']], "execution_required":True}]
    steps.extend({'step_key':k,'title':'Physical step '+k,'required':True,'acceptance_criteria':[CRIT[k]],'preconditions':[PRE_CRIT[k]],"execution_required":True}
                 for k in KEYS[:-1])
    result=eg_req('POST','/v1/tasks/register',{
        'event_id':id('register'),'task_id':task,'agent':'EGHardeningE2ETest',
        'original_instruction':PROJECT+' '+label,'protocol_hash':PH,
        'acceptance_criteria':[GLOBAL],'steps':steps})
    return task,result['contract_hash']
def target(task,key):
    # Exercise structured JSON artefacts inside the same protected worker root.
    suffix = '.json' if key == '01.05' else '.txt'
    return WORK/'outputs'/(task+'-'+key+suffix)
def data(task,key):
    if key == '01.05':
        return canon({'result':'TRUSTED_WORK_EXECUTED_AFTER_PRE',
                      'task_id':task,'step_key':key}).encode()
    return ('TRUSTED_WORK_EXECUTED_AFTER_PRE '+task+' '+key+'\n').encode()
def negative():
    task,contract=register('negative')
    # 10 physical writes have already happened before any EG PRE.
    for key in KEYS:
        target(task,key).write_bytes(data(task,key))
    cp=0;key='01.01';act=e2_action(task,key,cp,target(task,key))
    pre=eval_step(task,contract,key,CRIT[key],'PRE_EXECUTION',cp,cp,act)
    assert pre['verdict']=='READY_TO_EXECUTE',pre
    attempted=worker(task,key,act,data(task,key))
    assert attempted['status']=='DENIED' and 'PREEXISTING_EFFECT' in attempted['reason'],attempted
    results={}
    try:
        eval_step(task,contract,key,CRIT[key],'POST_EXECUTION',
                  pre['checkpoint_no'],pre['gate_checkpoint_no'],act)
        results['post_missing']='UNEXPECTED_ACCEPT'
    except HTTPError as exc:
        results['post_missing']=exc.code
    forged=receipt_sign(receipt_body(task,key,pre['gate_checkpoint_no'],
          pre['action_fingerprint'],'trusted-worker-forged',str(target(task,key)),
          data(task,key),secrets.token_urlsafe(24)),EG_NOTARY)
    try:
        eval_step(task,contract,key,CRIT[key],'POST_EXECUTION',
                  pre['checkpoint_no'],pre['gate_checkpoint_no'],act,receipt=forged)
        results['post_wrong_signer']='UNEXPECTED_ACCEPT'
    except HTTPError as exc:
        results['post_wrong_signer']=exc.code
    state=eg_req('GET','/v1/tasks/'+task+'/state')
    ok=results=={'post_missing':409,'post_wrong_signer':409} and not state['terminal']
    return {'task_id':task,'all_10_preexisting':True,
            'worker_rejected_existing':attempted['status']=='DENIED',
            'missing_receipt_http':results['post_missing'],
            'wrong_signer_http':results['post_wrong_signer'],
            'verified':0,'status':state['contract_status'],'pass':ok}
def positive():
    task,contract=register('positive')
    trail=[];cp=0
    for i,key in enumerate(KEYS,1):
        file=target(task,key)
        assert not file.exists()
        action=e2_action(task,key,cp,file)
        pre=eval_step(task,contract,key,CRIT[key],'PRE_EXECUTION',cp,cp,action)
        assert pre['verdict']=='READY_TO_EXECUTE',pre
        if i==1:
            # A review of payload A must never authorize payload B.
            denied=worker(task,key,action,b'UNREVIEWED_PAYLOAD_B')
            assert denied['status']=='DENIED' and 'PAYLOAD_NOT_AUTHORIZED' in denied['reason'],denied
            assert not file.exists()
            assert not (WORK/'journals'/(task+'-'+key+'.json')).exists()
        if i==2:
            # Real controlled agent dispatcher → canonical EG PRE → isolated worker →
            # verified independent receipt → EG POST. Never claims VERIFIED itself.
            from tools.governed_agent_dispatcher import dispatch
            guarded=dispatch({'task_id':task,'step_key':key,'action':action,
                              'data_b64':base64.b64encode(data(task,key)).decode()},
                             eg_url=EG_URL,api_key=EG_API,worker_socket=str(sock),
                             executor_public_key_b64=raw_pub(EXEC_NOTARY))
            assert guarded['status']=='RECEIPT_VERIFIED_POST_REQUIRED'
            attested={'status':'PASS','receipt':guarded['execution_receipt']}
        else:
            attested=worker(task,key,action,data(task,key))
        assert attested['status']=='PASS',attested
        receipt=attested['receipt']
        if i==5:
            # Fault injection: emulate crash after output write but BEFORE
            # durable receipt sealing. The trusted worker must reconcile,
            # independently verify the file and NEVER write it again.
            journal=WORK/'journals'/(task+'-'+key+'.json')
            signed_intent=json.loads(journal.read_text())
            assert signed_intent['stage']=='RECEIPT_SEALED'
            signed_intent.pop('receipt')
            signed_intent['stage']='INTENT_DURABLE'
            journal.write_text(canon(signed_intent))
            os.chown(journal,WORK_USER,WORK_USER)
            os.chmod(journal,0o600)
            output_mtime=file.stat().st_mtime_ns
            resealed=worker(task,key,action,data(task,key))
            assert resealed['status']=='PASS',resealed
            assert file.stat().st_mtime_ns==output_mtime
            receipt=resealed['receipt']
            # Worker has executed but EG POST has not yet arrived. This is the
            # high-risk interrupted execution, not a safe blind retry.
            pause=eg_req('POST','/v1/tasks/'+task+'/pause',{
                'event_id':id('pause'),'contract_hash':contract,
                'protocol_hash':PH,'checkpoint_no':pre['checkpoint_no'],
                'reason':'Agent exhausted limit after physical effect'})
            assert pause['status']=='PAUSED'
            paused_attempt=worker(task,key,action,data(task,key))
            assert paused_attempt['status']=='DENIED'
            resume=eg_req('POST','/v1/tasks/'+task+'/resume',{
                'event_id':id('resume'),'contract_hash':contract,
                'protocol_hash':PH,'checkpoint_no':pre['checkpoint_no'],
                'reason':'Resume with durable worker receipt'})
            assert resume['status']=='RECOVERY_PENDING'
            reconciled=worker(task,key,action,data(task,key))
            assert reconciled['status']=='PASS'
            assert reconciled['receipt']==receipt
            assert file.stat().st_mtime_ns==output_mtime,'WRITE duplicated!'
        post=eval_step(task,contract,key,CRIT[key],'POST_EXECUTION',
             pre['checkpoint_no'],pre['gate_checkpoint_no'],action,
             final=(key=='01'),receipt=receipt)
        assert post['verdict']=='VERIFIED_PASS' and post['step_verified'],post
        assert file.read_bytes()==data(task,key)
        cp=post['checkpoint_no']
        trail.append({'step':key,'pre':pre['checkpoint_no'],
                      'post':post['checkpoint_no'],'receipt_executor':receipt['executor_id'],
                      'readback_sha256':sha(file.read_bytes())})
    final=eg_req('GET','/v1/tasks/'+task+'/state')
    details=eg_req('GET','/v1/tasks/'+task)
    verified=sum(int(s['verified']) for s in details['steps'])
    return {'task_id':task,'verified':verified,'checkpoint':cp,
            'terminal':final['terminal'],'status':final['contract_status'],
            'pass':(verified==10 and cp==20 and final['terminal'] is True
                    and final['contract_status']=='SATISFIED'),'trail':trail}
def verified_read(previous_task):
    task=PROJECT+'-trusted-read'
    reg=eg_req('POST','/v1/tasks/register',{
      'event_id':id('register'),'task_id':task,'agent':'EGHardeningE2ETest',
      'original_instruction':'EG-managed E0 read by SAME trusted worker',
      'protocol_hash':PH,'acceptance_criteria':[GLOBAL],
      'steps':[{'step_key':'01','title':'Finalize E0 read','required':True,
                'acceptance_criteria':[CRIT['01']],"execution_required":False},
               {'step_key':'01.01','title':'Read previously verified E2 output',
                'required':True,'acceptance_criteria':[CRIT['01.01']],'preconditions':[PRE_CRIT['01.01']],"execution_required":True}]})
    contract=reg['contract_hash']
    source=target(previous_task,'01.01')
    assert source.exists() and source.is_file()
    action={'action_type':'read','target':str(source),'effect_class':'E0',
            'reversible':False,'real_world_effect':False,'proofs':[]}
    pre=eval_step(task,contract,'01.01',CRIT['01.01'],'PRE_EXECUTION',0,0,action)
    assert pre['verdict']=='READY_TO_EXECUTE'
    response=worker(task,'01.01',action,b'')
    assert response['status']=='PASS',response
    receipt=response['receipt']
    assert receipt['output_sha256']==sha(source.read_bytes())
    post=eval_step(task,contract,'01.01',CRIT['01.01'],'POST_EXECUTION',
                   pre['checkpoint_no'],pre['gate_checkpoint_no'],
                   action,receipt=receipt)
    assert post['verdict']=='VERIFIED_PASS'
    parent_pre=eval_step(task,contract,'01',CRIT['01'],'PRE_EXECUTION',
                        post['checkpoint_no'],post['checkpoint_no'],None)
    parent_post=eval_step(task,contract,'01',CRIT['01'],'POST_EXECUTION',
                         parent_pre['checkpoint_no'],parent_pre['gate_checkpoint_no'],
                         None,final=True)
    assert parent_post['contract_status']=='SATISFIED'
    assert eg_req('GET','/v1/tasks/'+task+'/state')['terminal']
    return {'task_id':task,'verified_read':True,'read_receipt_signed':True}

def main():
    start()
    socket_denied=denied_direct_agent_socket_access()
    neg=negative();pos=positive();read_result=verified_read(pos['task_id'])
    audit=eg_req('GET','/v1/audit/verify')
    result={'scenario':'real-HTTP separate-UID E2 receipt adversarial 10-step',
       'project':PROJECT,'negative':neg,'positive':pos,'read':read_result,'audit':audit['status'],
       'EG_UID':EG_USER,'EXECUTOR_UID':WORK_USER,
       'direct_agent_socket_bypass_denied':socket_denied,
       'distinct_signing_keys':raw_pub(EG_NOTARY)!=raw_pub(EXEC_NOTARY),
       'overall_pass':socket_denied and neg['pass'] and pos['pass'] and audit['status']=='PASS'}
    path=SESSION/'audit_result.json';path.write_text(json.dumps(result,indent=2))
    os.chmod(path,0o600)
    print(json.dumps({'overall_pass':result['overall_pass'],
      'negative':{k:v for k,v in neg.items() if k not in ('trail',)},
      'positive':{k:v for k,v in pos.items() if k not in ('trail',)},
      'audit':audit['status'],'report':str(path)}),flush=True)
    return 0 if result['overall_pass'] else 1
if __name__=='__main__':
    try:sys.exit(main())
    finally:close()
