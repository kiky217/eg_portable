"""One agent orchestrates a real signed E2 file creation; no simulated receipt."""
import base64
import json
import pytest
import harness as H
from tools import trusted_execution_worker as worker
from tools.single_agent_workflow import run_task, run_step, WorkflowDenied
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption


def test_one_agent_run_task_performs_once_and_verifies_actual_file(monkeypatch):
    task=H.eid('orchestrated-project')
    raw=b'<!doctype html><html><h1>Real cafe</h1></html>'
    target=H.WORKER_OUTPUT / (H.eid('file')+'.txt')
    journal=H.RUNTIME / H.eid('e2-journal')
    journal.mkdir(mode=0o700)
    private=H.RUNTIME / (H.eid('worker')+'.pem')
    private.write_bytes(H.EXEC_PRIV.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
    private.chmod(0o600)
    agent=worker.TrustedWriter(H.WORKER_OUTPUT,journal,private,
        'http://127.0.0.1:18766','fixture','trusted-worker-orchestrated')
    def state(_url,_key,task_id):
        return (H.CLIENT.get('/v1/tasks/'+task_id+'/state',headers=H.HEAD).json(),
                H.CLIENT.get('/v1/tasks/'+task_id,headers=H.HEAD).json())
    monkeypatch.setattr(worker,'api',state)
    registration={'event_id':H.eid('reg'),'task_id':task,'protocol_hash':H.gw.protocol_hash(),
        'agent':'ChatGPT','original_instruction':'Make a cafe website','acceptance_criteria':['all steps evidenced'],
        'steps':[{'step_key':'01','title':'parent','acceptance_criteria':['parent criterion'],
                  'execution_required':False},
                 {'step_key':'01.01','title':'write site','preconditions':[H.CRIT],
                  'acceptance_criteria':[H.CRIT],'execution_required':True}]}
    writes=[]
    contract_holder={}
    def step_provider(reg):
        contract_holder["hash"]=reg["contract_hash"]
        def pre_request(cp):
            ref=H.step_ref(task,'PRE_EXECUTION',cp)
            return {'event_id':H.eid('pre'),'task_id':task,'contract_hash':reg['contract_hash'],
                    'protocol_hash':H.gw.protocol_hash(),'checkpoint_no':cp,'step_key':'01.01',
                    'agent':'ChatGPT','phase':'PRE_EXECUTION','claims':[H.claim(ref)],
                    'action':action}
        def post_evidence(pre,receipt):
            assert target.read_bytes()==raw
            ref=H.step_ref(task,'POST_EXECUTION',pre['gate_checkpoint_no'])
            return {'event_id':H.eid('post'),'claims':[H.claim(ref)]}
        action=H.e2_action(task,0,target=str(target),payload=raw)
        yield {'step_key':'01.01','action':action,'data_b64':base64.b64encode(raw).decode(),
               'pre_request':pre_request,'post_evidence':post_evidence}
    def dispatch_once(request):
        writes.append(request)
        return {'status':'RECEIPT_VERIFIED_POST_REQUIRED','execution_receipt':agent.execute(request)}
    def finish(cp):
        parent,_=H.do_pre(task,contract_holder["hash"],cp,step="01",
            criteria=[(0,"parent criterion")],stdout="PARENT=PASS",value="PARENT=PASS")
        accepted,_=H.do_post(task,contract_holder["hash"],parent,step="01",
            criteria=[(0,"parent criterion")],stdout="PARENT=PASS",value="PARENT=PASS",finalize=True)
        assert accepted.status_code==200
    result=run_task(H.CLIENT,H.HEAD,registration=registration,
                    step_provider=step_provider,dispatch_once=dispatch_once,finalize=finish)
    assert result["contract_status"]=="SATISFIED"
    assert result['physical_steps_verified'] is True
    assert len(writes)==1
    assert target.read_bytes()==raw
    assert H.CLIENT.get('/v1/audit/verify',headers=H.HEAD).json()['status']=='PASS'


def test_gate_denial_never_invokes_executor():
    called=[]
    with pytest.raises(WorkflowDenied,match='ORIGINAL_PRE_PAYLOAD_REQUIRED'):
        run_step(H.CLIENT,H.HEAD,task_id='t',step_key='01.01',action={},payload_b64='',
            pre_request={'phase':'POST_EXECUTION'},dispatch_once=lambda r:called.append(r),
            post_evidence=lambda a,b:{'claims':[]})
    assert called==[]
