"""One EG task: create, amend, compile, test, and serve cafe API under signed E2/E3."""
import base64, hashlib, json, os, time, threading, tempfile, shutil
from pathlib import Path
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import pytest
import harness as H
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from tools import trusted_execution_worker as W
from tools.high_effect_admission import AdapterCapability
from tools.adapter_liveness import canon
from tools.typed_payload_contract import canonical as schema_canon
from tools.trusted_process_effect import TrustedProcessEffect
from tools.trusted_generic_rpc import serve
from tools.operator_adapter_binding import canonical as bind_canon
from tools.operator_runtime_registry import OperatorAdapterRegistry
from tools.governed_agent_dispatcher import dispatch_action
from test_high_effect_gateway_integration import pub, signed, high_pre_claim, high_pre_ref

pytestmark=pytest.mark.skipif(os.getuid()!=0,reason='OS UID isolation requires root test fixture')


def _e2_action(task,step,cp,target,new,old=None):
    base={'action_type':'replace' if old is not None else 'write',
          'effect_class':'E2','reversible':True,'real_world_effect':False,
          'target':str(target),'payload_sha256':hashlib.sha256(new).hexdigest(),
          'payload_bytes':len(new)}
    if old is not None:base['previous_sha256']=hashlib.sha256(old).hexdigest()
    vals={'sandbox_pass':'SANDBOX=PASS','rollback_ready':'ROLLBACK=READY','reversible':'REVERSIBLE=YES'}
    ref=H.notarized(H.eid('e2-proofs'),stdout='\n'.join(vals.values()),
        bindings=[H.pb(task,step,purpose,base,cp,marker) for purpose,marker in vals.items()])
    return {**base,'proofs':[{'purpose':k,'evidence':H.evp(ref)} for k in vals]}


def _as(uid):
    os.setgroups([]);os.setgid(uid);os.setuid(uid)


def verified_file_step(task,contract,cp,step,target,data,old,worker):
    action=_e2_action(task,step,cp,target,data,old)
    pre,_=H.do_pre(task,contract,cp,step=step,action=action)
    assert pre.json()['verdict']=='READY_TO_EXECUTE',pre.text
    packet={'task_id':task,'step_key':step,'action':action,
            'data_b64':base64.b64encode(data).decode()}
    receipt=worker.execute(packet)
    assert target.read_bytes()==data
    post,_=H.do_post(task,contract,pre,step=step,action=action,execution_receipt=receipt)
    assert post.status_code==200 and post.json()['verdict']=='VERIFIED_PASS',post.text
    return post.json()['checkpoint_no']


def test_single_task_cafe_create_edit_build_http_and_source_rollback(monkeypatch,tmp_path):
    initial=b'def menu(): return [{"name":"Espresso","price":19000}]\n'
    revised=b'def menu(): return [{"name":"Espresso","price":20000}]\n'
    output=tmp_path/'outputs';journal=tmp_path/'e2-journal'
    output.mkdir(mode=0o700);journal.mkdir(mode=0o700)
    target=output/'cafe_api.py'
    monkeypatch.setenv('EVALUATION_GATEWAY_EXECUTOR_ALLOWED_SUFFIXES','.txt,.json,.py')
    monkeypatch.setattr(H.gw,'EXECUTOR_OUTPUT_ROOT',str(output))
    key=tmp_path/'e2-key.pem'
    key.write_bytes(H.EXEC_PRIV.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
    key.chmod(0o600)
    def current(_url,_key,task):
        a=H.CLIENT.get('/v1/tasks/'+task+'/state',headers=H.HEAD)
        b=H.CLIENT.get('/v1/tasks/'+task,headers=H.HEAD)
        assert a.status_code==200 and b.status_code==200
        return a.json(),b.json()
    monkeypatch.setattr(W,'api',current)
    worker=W.TrustedWriter(output,journal,key,'http://127.0.0.1:18766','fixture','trusted-worker-cafe',['.txt','.json','.py'])
    task=H.eid('cafe-one-agent')
    body={'event_id':H.eid('reg'),'task_id':task,'protocol_hash':H.gw.protocol_hash(),
          'agent':'ChatGPT','original_instruction':'Build and validate cafe API in staging',
          'acceptance_criteria':['all steps evidenced'],
          'steps':[{'step_key':'01','title':'Cafe app acceptance',
                    'acceptance_criteria':['parent criterion'],'required':True,'execution_required':False},
                   {'step_key':'01.01','title':'Create source','preconditions':[H.CRIT],
                    'acceptance_criteria':[H.CRIT],'required':True,'execution_required':True},
                   {'step_key':'01.02','title':'Revise source','preconditions':[H.CRIT],
                    'acceptance_criteria':[H.CRIT],'required':True,'execution_required':True},
                   {'step_key':'01.03','title':'Build, test, serve cafe API',
                    'preconditions':['high-effect independent baseline ready'],
                    'acceptance_criteria':[H.CRIT],'required':True,'execution_required':True},
                   {'step_key':'01.04','title':'Restore previous source version',
                    'preconditions':[H.CRIT],'acceptance_criteria':[H.CRIT],
                    'required':True,'execution_required':True}]}
    reg=H.CLIENT.post('/v1/tasks/register',headers=H.HEAD,json=body)
    assert reg.status_code==200,reg.text
    contract=reg.json()['contract_hash']
    cp=0
    for step,data,old in [('01.01',initial,None),('01.02',revised,initial)]:
        cp=verified_file_step(task,contract,cp,step,target,data,old,worker)
    # The isolated E3 worker is a different OS UID and performs a real compilation,
    # Python integration check and loopback HTTP request on the exact revised code.
    base=Path(tempfile.mkdtemp(prefix='eg-cafe-e3-',dir='/tmp'));base.chmod(0o755)
    uid=65532
    sockdir=base/'socket';sockdir.mkdir(mode=0o700)
    e3journal=base/'journal';e3journal.mkdir(mode=0o700)
    for folder in (sockdir,e3journal):os.chown(folder,uid,uid)
    checker=base/'cafe_build.py'
    checker.write_text('''import json,sys,threading,urllib.request
from http.server import BaseHTTPRequestHandler,HTTPServer
value=json.loads(sys.stdin.buffer.read())
code=compile(value['message'],'cafe_api.py','exec')
namespace={}
exec(code,namespace)
menu=namespace['menu']()
assert menu==[{'name':'Espresso','price':20000}]
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  raw=json.dumps(menu).encode()
  self.send_response(200 if self.path=='/menu' else 404)
  self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
 def log_message(self,*args): pass
server=HTTPServer(('127.0.0.1',0),Handler)
thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
try:
 with urllib.request.urlopen('http://127.0.0.1:%d/menu'%server.server_port,timeout=2) as response:
  assert response.status==200 and json.loads(response.read())==menu
finally:
 server.shutdown();server.server_close();thread.join(timeout=2)
sys.stdout.write(json.dumps(value))
''')
    os.chown(checker,uid,uid);checker.chmod(0o644)
    operator,e3key,human=[Ed25519PrivateKey.generate() for _ in range(3)]
    adapter='trusted-adapter-cafe-validation'
    cap=AdapterCapability(adapter_id=adapter,effect_class='E3',action_type='bounded_process_run',
         target_prefix='/tasks/cafe/',maximum_payload_bytes=4096,isolated=True,
         public_key_b64=pub(e3key),ci_only=False)
    capsha=hashlib.sha256(canon(asdict(cap))).hexdigest()
    schema={'schema_version':1,'schema_id':'generic/message-v1',
            'required':['message'],'additional_properties':False,
            'properties':{'message':{'type':'string','minimum':1,'maximum':80}}}
    schema_sha=hashlib.sha256(schema_canon(schema)).hexdigest()
    data=json.dumps({'message':revised.decode().strip()}).encode()
    effect={'action_type':'bounded_process_run','effect_class':'E3',
            'target':'/tasks/cafe/build','real_world_effect':True,'reversible':True,
            'payload_sha256':hashlib.sha256(data).hexdigest(),'payload_bytes':len(data),'proofs':[]}
    class Proxy(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.headers.get('X-Evaluation-Key')!=H.API_KEY:
                self.send_response(403);self.end_headers();return
            resp=H.CLIENT.get(self.path,headers=H.HEAD)
            self.send_response(resp.status_code);self.send_header('Content-Type','application/json')
            self.end_headers();self.wfile.write(resp.content)
        def log_message(self,*args):pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Proxy)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    url=f'http://127.0.0.1:{server.server_port}'
    pid=os.fork()
    if pid==0:
        try:
            _as(uid)
            fixed=next(str(p) for p in (Path('/usr/bin/python3.12'),Path('/usr/bin/python3.13')) if p.exists())
            effect_worker=TrustedProcessEffect(journal_dir=e3journal,private_key=e3key,
                adapter_id=adapter,hitl_key_b64=pub(human),executable=fixed,
                fixed_args=(str(checker),),target=effect['target'],timeout=10,
                input_schema=schema,input_schema_sha256=schema_sha,
                output_schema=schema,output_schema_sha256=schema_sha)
            serve(socket_path=str(sockdir/'worker.sock'),adapter=effect_worker,
                  capability_sha256=capsha,eg_url=url,eg_key=H.API_KEY,
                  hitl_public_key_b64=pub(human),controller_uid=0,max_requests=3)
            os._exit(0)
        except BaseException:
            import traceback;traceback.print_exc();os._exit(1)
    try:
        for _ in range(150):
            if (sockdir/'worker.sock').is_socket():break
            time.sleep(.02)
        assert (sockdir/'worker.sock').is_socket()
        op_dir=base/'operator';op_dir.mkdir(mode=0o700)
        now=int(time.time())
        binding={'version':1,'adapter_id':adapter,'capability_sha256':capsha,
                 'worker_uid':uid,'socket_path':str(sockdir/'worker.sock'),
                 'worker_public_key_b64':pub(e3key),'issued_at':now-1,
                 'expires_at':now+120,'environment':'ci',
                 'operator_nonce':'cafe-authority-one-time-setup'}
        binding['signature_b64']=base64.b64encode(operator.sign(bind_canon(binding))).decode()
        registry=OperatorAdapterRegistry(op_dir,pub(operator))
        assert registry.activate(binding,adapter_id=adapter,
             capability_sha256=capsha)['status']=='ACTIVE_CONFIG_ONLY'
        monkeypatch.setattr(H.gw,'EXTERNAL_ADAPTER_MODE','enabled')
        monkeypatch.setattr(H.gw,'EXTERNAL_ADAPTER_UID',-1)
        monkeypatch.setattr(H.gw,'EXTERNAL_ADAPTER_SOCKET','')
        monkeypatch.setattr(H.gw,'EXTERNAL_REGISTRY_DIR',str(op_dir))
        monkeypatch.setattr(H.gw,'EXTERNAL_REGISTRY_KEY',pub(operator))
        monkeypatch.setattr(H.gw,'HIGH_EFFECT_CAPABILITIES_JSON',json.dumps([asdict(cap)]))
        monkeypatch.setattr(H.gw,'HITL_PUBLIC_KEY_B64',pub(human))
        monkeypatch.setenv('EVALUATION_GATEWAY_EXTERNAL_REGISTRY_DIR',str(op_dir))
        monkeypatch.setenv('EVALUATION_GATEWAY_EXTERNAL_REGISTRY_OPERATOR_PUBLIC_KEY_B64',pub(operator))
        from tools.operator_scoped_approval import Grants
        grants_dir=base/'standing-policy';grants_dir.mkdir(mode=0o700)
        grants=Grants({'key':human,'ledger_dir':str(grants_dir),
              'adapter_id':adapter,'target_prefix':'/tasks/cafe',
              'expires_at':int(time.time())+120,'max_grants':1,'max_payload_bytes':4096})
        approval=grants.issue({'task_id':task,'step_key':'01.03',
              'gate_checkpoint_no':cp+1,'action':effect})
        assert grants.issue({'task_id':task,'step_key':'01.03',
              'gate_checkpoint_no':cp+1,'action':effect})==approval
        pre3=H.raw_eval(task,contract,cp,step='01.03',
            claims=[high_pre_claim(high_pre_ref(task,cp,step='01.03'))],
            phase='PRE_EXECUTION',action=effect,hitl_approval=approval)
        assert pre3.status_code==200 and pre3.json()['verdict']=='READY_TO_EXECUTE',pre3.text
        result=dispatch_action({'task_id':task,'step_key':'01.03','action':effect,
                 'data_b64':base64.b64encode(data).decode()},eg_url=url,api_key=H.API_KEY,
                 hitl_public_key_b64=pub(human),hitl_approval=approval)
        assert result['status']=='RECEIPT_VERIFIED_POST_REQUIRED'
        assert result['execution_receipt']['output_sha256']==hashlib.sha256(data).hexdigest()
        post3=H.raw_eval(task,contract,pre3.json()['checkpoint_no'],step='01.03',
            claims=[H.claim(H.step_ref(task,'POST_EXECUTION',pre3.json()['gate_checkpoint_no'],step='01.03'))],
            phase='POST_EXECUTION',action=effect,execution_receipt=result['execution_receipt'])
        assert post3.status_code==200 and post3.json()['verdict']=='VERIFIED_PASS',post3.text
        cp=verified_file_step(task,contract,post3.json()['checkpoint_no'],
              '01.04',target,initial,revised,worker)
        assert target.read_bytes()==initial
        parent,_=H.do_pre(task,contract,cp,step='01',
             criteria=[(0,'parent criterion')],stdout='PARENT=PASS',value='PARENT=PASS')
        tref=H.task_ref(task,parent.json()['gate_checkpoint_no'])
        final,_=H.do_post(task,contract,parent,step='01',
             criteria=[(0,'parent criterion')],task_claims=[H.task_claim(tref)],finalize=True,
             stdout='PARENT=PASS',value='PARENT=PASS')
        assert final.status_code==200 and final.json()['contract_status']=='SATISFIED'
        _,wait=os.waitpid(pid,0);pid=0
        assert os.waitstatus_to_exitcode(wait)==0
        monkeypatch.setattr(H.gw,'EXTERNAL_ADAPTER_MODE','disabled')
        assert H.CLIENT.get('/v1/audit/verify',headers=H.HEAD).json()['status']=='PASS'
    finally:
        if pid:
            try:os.kill(pid,9)
            except ProcessLookupError:pass
            os.waitpid(pid,0)
        server.shutdown();server.server_close()
        shutil.rmtree(base,ignore_errors=True)
