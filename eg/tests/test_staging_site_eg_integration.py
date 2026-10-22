"""One EG task: persistent staging release, revision and rollback with signed E3."""
import os,base64,hashlib,json,shutil,socket,subprocess,sys,tempfile,time,threading,urllib.request
from pathlib import Path
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import pytest,harness as H
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tools.adapter_liveness import canon
from tools.high_effect_admission import AdapterCapability
from tools.operator_adapter_binding import canonical as binding_canonical
from tools.operator_runtime_registry import OperatorAdapterRegistry
from tools.operator_scoped_approval import Grants
from tools.trusted_generic_rpc import serve
from tools.trusted_process_effect import TrustedProcessEffect
from tools.governed_agent_dispatcher import dispatch_action
from test_high_effect_gateway_integration import pub,high_pre_claim,high_pre_ref

SITE=65530
WORKER=65532

def identity(uid):
    def change():os.setgroups([]);os.setgid(uid);os.setuid(uid)
    return change

@pytest.mark.skipif(os.geteuid()!=0,reason='requires two non-root OS identities')
def test_one_task_real_site_deploy_edit_and_rollback(monkeypatch):
    root=Path(tempfile.mkdtemp(prefix='eg-staging-eg-',dir='/tmp'));root.chmod(0o755)
    source=Path(os.environ['EG_TEST_SOURCE'])
    site=None;pid=None;proxy=None
    try:
        private=root/'site';private.mkdir(mode=0o700);os.chown(private,SITE,SITE)
        state=private/'state';state.mkdir(mode=0o700);os.chown(state,SITE,SITE)
        socketdir=root/'site-socket';socketdir.mkdir(mode=0o700)
        os.chown(socketdir,SITE,WORKER);socketdir.chmod(0o2710)
        workerdir=root/'worker-socket';workerdir.mkdir(mode=0o700)
        journal=root/'worker-journal';journal.mkdir(mode=0o700)
        for folder in (workerdir,journal):os.chown(folder,WORKER,WORKER)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
        sitesock=str(socketdir/'site.sock')
        cfg=private/'config.json'
        cfg.write_text(json.dumps({'socket_path':sitesock,'state_dir':str(state),
            'http_port':port,'controller_uid':WORKER,'controller_gid':WORKER}))
        cfg.chmod(0o600);os.chown(cfg,SITE,SITE)
        site=subprocess.Popen([sys.executable,'-m','tools.staging_site_service',str(cfg)],
            cwd=source,env={**os.environ,'PYTHONPATH':str(source)},
            preexec_fn=identity(SITE),stderr=subprocess.PIPE)
        for _ in range(100):
            if Path(sitesock).is_socket():break
            assert site.poll() is None,site.stderr.read()
            time.sleep(.04)
        assert Path(sitesock).is_socket()
        v1=b'<!doctype html><html><body>Cafe 1</body></html>'
        v2=b'<!doctype html><html><body>Cafe 2</body></html>'
        website=f'http://127.0.0.1:{port}/'
        operator,worker,human=(Ed25519PrivateKey.generate() for _ in range(3))
        adapter='trusted-adapter-staging-site'
        cap=AdapterCapability(adapter_id=adapter,action_type='bounded_process_run',
            effect_class='E3',target_prefix='/tasks/cafe/',maximum_payload_bytes=4096,
            isolated=True,public_key_b64=pub(worker),ci_only=False)
        capsha=hashlib.sha256(canon(asdict(cap))).hexdigest()
        task=H.eid('cafe-live-site')
        reg=H.CLIENT.post('/v1/tasks/register',headers=H.HEAD,json={
            'event_id':H.eid('register'),'task_id':task,
            'protocol_hash':H.gw.protocol_hash(),'agent':'ChatGPT',
            'original_instruction':'Deploy, revise and rollback cafe staging site',
            'acceptance_criteria':['all steps evidenced'],
            'steps':[{'step_key':'01','title':'Accept site release',
                      'acceptance_criteria':['parent criterion'],'execution_required':False},
                *[{'step_key':step,'title':name,
                   'preconditions':['high-effect independent baseline ready'],
                   'acceptance_criteria':[H.CRIT],'execution_required':True}
                  for step,name in (('01.01','deploy'),('01.02','revise'),('01.03','rollback'))]
        })
        assert reg.status_code==200,reg.text
        contract=reg.json()['contract_hash']
        class Api(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.headers.get('X-Evaluation-Key')!=H.API_KEY:
                    self.send_response(403);self.end_headers();return
                r=H.CLIENT.get(self.path,headers=H.HEAD)
                self.send_response(r.status_code);self.send_header('Content-Type','application/json')
                self.end_headers();self.wfile.write(r.content)
            def log_message(self,*args):pass
        proxy=ThreadingHTTPServer(('127.0.0.1',0),Api)
        threading.Thread(target=proxy.serve_forever,daemon=True).start()
        gateway=f'http://127.0.0.1:{proxy.server_port}'
        cwd=os.getcwd()
        try:
            os.chdir(source)
            pid=os.fork()
        finally:os.chdir(cwd)
        if pid==0:
            try:
                identity(WORKER)()
                executable=next(str(p) for p in (Path('/usr/bin/python3.12'),
                    Path('/usr/bin/python3.13')) if p.exists())
                w=TrustedProcessEffect(journal_dir=journal,private_key=worker,
                    adapter_id=adapter,hitl_key_b64=pub(human),executable=executable,
                    fixed_args=('-m','tools.staging_site_service','client',sitesock),
                    target='/tasks/cafe/site',timeout=8,max_stdout=4096)
                serve(socket_path=str(workerdir/'worker.sock'),adapter=w,
                    capability_sha256=capsha,eg_url=gateway,eg_key=H.API_KEY,
                    hitl_public_key_b64=pub(human),controller_uid=0,max_requests=12)
                os._exit(0)
            except BaseException:
                import traceback;traceback.print_exc();os._exit(2)
        for _ in range(150):
            if (workerdir/'worker.sock').is_socket():break
            time.sleep(.02)
        assert (workerdir/'worker.sock').is_socket()
        opdir=root/'operator';opdir.mkdir(mode=0o700)
        now=int(time.time())
        binding={'version':1,'adapter_id':adapter,'capability_sha256':capsha,
             'worker_uid':WORKER,'socket_path':str(workerdir/'worker.sock'),
             'worker_public_key_b64':pub(worker),'issued_at':now-1,
             'expires_at':now+120,'environment':'ci','operator_nonce':'staging-site-authority'}
        binding['signature_b64']=base64.b64encode(operator.sign(binding_canonical(binding))).decode()
        assert OperatorAdapterRegistry(opdir,pub(operator)).activate(binding,
            adapter_id=adapter,capability_sha256=capsha)['status']=='ACTIVE_CONFIG_ONLY'
        for key,value in [('EXTERNAL_ADAPTER_MODE','enabled'),('EXTERNAL_ADAPTER_UID',-1),
              ('EXTERNAL_ADAPTER_SOCKET',''),('EXTERNAL_REGISTRY_DIR',str(opdir)),
              ('EXTERNAL_REGISTRY_KEY',pub(operator)),
              ('HIGH_EFFECT_CAPABILITIES_JSON',json.dumps([asdict(cap)])),
              ('HITL_PUBLIC_KEY_B64',pub(human))]:
            monkeypatch.setattr(H.gw,key,value)
        monkeypatch.setenv('EVALUATION_GATEWAY_EXTERNAL_REGISTRY_DIR',str(opdir))
        monkeypatch.setenv('EVALUATION_GATEWAY_EXTERNAL_REGISTRY_OPERATOR_PUBLIC_KEY_B64',pub(operator))
        grantdir=root/'grants';grantdir.mkdir(mode=0o700)
        grant=Grants({'key':human,'ledger_dir':str(grantdir),'adapter_id':adapter,
            'target_prefix':'/tasks/cafe','expires_at':now+120,
            'max_grants':3,'max_payload_bytes':4096})
        cp=0
        for step,op,content,expected in (
            ('01.01','deploy',v1,v1),('01.02','deploy',v2,v2),
            ('01.03','rollback',b'',v1)):
            req={'operation':op,'content_b64':base64.b64encode(content).decode() if op=='deploy' else '',
                 'content_sha256':hashlib.sha256(expected).hexdigest()}
            payload=json.dumps(req,separators=(',',':')).encode()
            action={'action_type':'bounded_process_run','effect_class':'E3',
                'target':'/tasks/cafe/site','real_world_effect':True,'reversible':True,
                'payload_sha256':hashlib.sha256(payload).hexdigest(),
                'payload_bytes':len(payload),'proofs':[]}
            approval=grant.issue({'task_id':task,'step_key':step,
                'gate_checkpoint_no':cp+1,'action':action})
            pre=H.raw_eval(task,contract,cp,step=step,
                claims=[high_pre_claim(high_pre_ref(task,cp,step=step))],
                phase='PRE_EXECUTION',action=action,hitl_approval=approval)
            assert pre.status_code==200 and pre.json()['verdict']=='READY_TO_EXECUTE',pre.text
            completed=dispatch_action({'task_id':task,'step_key':step,'action':action,
                'data_b64':base64.b64encode(payload).decode()},
                eg_url=gateway,api_key=H.API_KEY,
                hitl_public_key_b64=pub(human),hitl_approval=approval)
            assert completed['status']=='RECEIPT_VERIFIED_POST_REQUIRED'
            assert len(completed['execution_receipt']['output_sha256'])==64
            assert urllib.request.urlopen(website,timeout=3).read()==expected
            assert site.poll() is None  # Site survives each governed worker call.
            post=H.raw_eval(task,contract,pre.json()['checkpoint_no'],step=step,
                claims=[H.claim(H.step_ref(task,'POST_EXECUTION',
                    pre.json()['gate_checkpoint_no'],step=step))],
                phase='POST_EXECUTION',action=action,
                execution_receipt=completed['execution_receipt'])
            assert post.status_code==200 and post.json()['verdict']=='VERIFIED_PASS',post.text
            cp=post.json()['checkpoint_no']
        parent,_=H.do_pre(task,contract,cp,step='01',
            criteria=[(0,'parent criterion')],stdout='PARENT=PASS',value='PARENT=PASS')
        accepted,_=H.do_post(task,contract,parent,step='01',
            criteria=[(0,'parent criterion')],stdout='PARENT=PASS',value='PARENT=PASS',
            task_claims=[H.task_claim(H.task_ref(task,parent.json()['gate_checkpoint_no']))],
            finalize=True)
        assert accepted.status_code==200 and accepted.json()['contract_status']=='SATISFIED'
        os.kill(pid,15);os.waitpid(pid,0);pid=None
        monkeypatch.setattr(H.gw,'EXTERNAL_ADAPTER_MODE','disabled')
        assert H.CLIENT.get('/v1/audit/verify',headers=H.HEAD).json()['status']=='PASS'
    finally:
        if pid:
            try:os.kill(pid,9)
            except ProcessLookupError:pass
            os.waitpid(pid,0)
        if site and site.poll() is None:
            site.terminate()
            try:site.wait(timeout=3)
            except subprocess.TimeoutExpired:site.kill();site.wait()
        if proxy:proxy.shutdown();proxy.server_close()
        shutil.rmtree(root,ignore_errors=True)
