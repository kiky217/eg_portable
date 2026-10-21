#!/usr/bin/env python3
"""Real local single-agent website acceptance using the existing EG E0/E2 worker.

This is an isolated, temporary integration runner, not a production executor.
The source task requires no second AI agent. Every file creation goes through
PRE -> separate-UID worker signed receipt -> physical readback -> POST.
"""
import argparse
import http.server
import threading
import urllib.request
import base64
import hashlib
import json
import re
import os
import sys
from pathlib import Path


ALLOWED = {'.html', '.css', '.js', '.json', '.txt'}


def validated_files(path: Path) -> list[tuple[str, bytes]]:
    data = json.loads(path.read_text(encoding='utf-8'))
    if (not isinstance(data, dict) or set(data) not in ({'name', 'files'}, {'name', 'files', 'revisions'})
        or not isinstance(data['name'], str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,31}', data['name'])
        or not isinstance(data['files'], dict) or not 1 <= len(data['files']) <= 25):
        raise ValueError('INVALID_LOCAL_PROJECT_MANIFEST')
    result = []
    for name, contents in data['files'].items():
        if (not isinstance(name, str) or not re.fullmatch(r'[a-zA-Z0-9_-]+\.[a-z0-9]{1,12}', name)
            or Path(name).suffix not in ALLOWED or not isinstance(contents, str)):
            raise ValueError('UNSAFE_PROJECT_FILE')
        raw = contents.encode('utf-8')
        if not 0 < len(raw) <= 524288:
            raise ValueError('INVALID_PROJECT_FILE_SIZE')
        if name.endswith('.json'):
            json.loads(contents)
        result.append((name, raw))
    return result


def validated_revisions(path: Path, files: list[tuple[str, bytes]]) -> list[tuple[str, bytes]]:
    changes = json.loads(path.read_text(encoding='utf-8')).get('revisions', [])
    if not isinstance(changes,list) or len(changes)>25:
        raise ValueError('INVALID_PROJECT_REVISIONS')
    allowed={name for name,_ in files}
    output=[]
    current=dict(files)
    for row in changes:
        if (not isinstance(row,dict) or set(row)!={'path','content'}
            or row['path'] not in allowed or not isinstance(row['content'],str)):
            raise ValueError('UNSAFE_PROJECT_REVISION')
        raw=row['content'].encode('utf-8')
        if not 0<len(raw)<=524288:
            raise ValueError('INVALID_PROJECT_FILE_SIZE')
        if row['path'].endswith('.json'):
            json.loads(row['content'])
        if raw==current[row['path']]:
            raise ValueError('NO_OP_PROJECT_REVISION')
        current[row['path']]=raw
        output.append((row['path'],raw))
    return output


def smoke_web(root: Path, names: set[str]) -> dict:
    """Local preview readback, never a production deployment or EG E3 action."""
    if 'index.html' not in names:
        return {'status':'SKIPPED_NO_ENTRYPOINT'}
    class Quiet(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(root), **kwargs)
        def log_message(self, *args):
            pass
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Quiet)
    thread=threading.Thread(target=server.serve_forever,daemon=True)
    thread.start()
    try:
        content={}
        for name in names:
            with urllib.request.urlopen(f'http://127.0.0.1:{server.server_port}/{name}',timeout=3) as response:
                if response.status!=200:
                    raise RuntimeError('HTTP_ASSET_FAILED')
                content[name]=response.read()
        if 'menu.json' in content and not isinstance(json.loads(content['menu.json']),list):
            raise RuntimeError('CAFE_MENU_RESPONSE_INVALID')
        return {'status':'PASS','http_200_assets':len(content)}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def run(manifest: Path):
    files = validated_files(manifest)
    revisions = validated_revisions(manifest, files)
    changes=[(name,raw,False) for name,raw in files]+[(name,raw,True) for name,raw in revisions]
    if os.geteuid() != 0:
        raise RuntimeError("ISOLATED_LOCAL_STAGING_REQUIRES_PRIVILEGED_OPERATOR_BOOTSTRAP")
    import run_trusted_e2e as eg
    suffixes = ','.join(sorted(ALLOWED))
    eg.environ['EVALUATION_GATEWAY_EXECUTOR_ALLOWED_SUFFIXES'] = suffixes
    config = json.loads(eg.worker_config.read_text())
    config['allowed_suffixes'] = suffixes
    eg.worker_config.write_text(json.dumps(config))
    eg.worker_config.chmod(0o600)
    task = eg.PROJECT + '-website'
    criterion = 'Actual file SHA-256 independently read back after trusted execution'
    create_precondition = 'File not present and target within the worker-owned output root'
    edit_precondition = 'Existing file digest matches action previous_sha256 within the worker-owned output root'
    step_keys = [f'01.{i:02d}' for i in range(1, len(changes)+1)]
    steps = [{'step_key':'01', 'title':'Verify complete website',
              'acceptance_criteria':['Every project file independently verified'],
              'execution_required':False}]
    steps += [{'step_key':key,'title':('Revise ' if replace else 'Create ') + filename,
               'acceptance_criteria':[criterion],
               'preconditions':[edit_precondition if replace else create_precondition],
               'execution_required':True}
              for key, (filename, _, replace) in zip(step_keys, changes)]
    eg.start()
    try:
        eg.PH = eg.eg_req('GET', '/v1/protocol')['hash']
        registration = eg.eg_req('POST','/v1/tasks/register', {
            'event_id':eg.id('reg'),'task_id':task,'agent':'SingleAgentLocalE2E',
            'original_instruction':'Build a static website with PRE/POST for every file',
            'protocol_hash':eg.PH,'acceptance_criteria':['All file steps verified'],
            'steps':steps})
        contract, checkpoint, evidence = registration['contract_hash'], 0, []
        for key, (filename, raw, replace) in zip(step_keys, changes):
            target = eg.WORK/'outputs'/filename
            if replace and not target.is_file():
                raise RuntimeError('REVISION_BASELINE_MISSING')
            if not replace and target.exists():
                raise RuntimeError('BASELINE_TARGET_NOT_EMPTY')
            previous=target.read_bytes() if replace else None
            action = eg.e2_action(task,key,checkpoint,target,raw,previous=previous)
            precondition=edit_precondition if replace else create_precondition
            marker='PREIMAGE_SHA='+hashlib.sha256(previous).hexdigest() if replace else 'ABSENT=PASS'
            prepared = eg.notarize([eg.binding(task,key,precondition,'PRE_EXECUTION',checkpoint,marker)],marker)
            pre = eg.eg_req('POST', '/v1/evaluate', {
                'event_id':eg.id('pre'),'task_id':task,'contract_hash':contract,
                'protocol_hash':eg.PH,'checkpoint_no':checkpoint,'step_key':key,
                'agent':'SingleAgentLocalE2E','phase':'PRE_EXECUTION','action':action,
                'claims':[{'criterion_index':0,'claim':precondition,'evidence':[prepared]}]})
            if pre['verdict'] != 'READY_TO_EXECUTE':
                raise RuntimeError('EG_PRE_NOT_READY:'+repr(pre))
            from tools.governed_agent_dispatcher import dispatch
            result = dispatch({'task_id':task,'step_key':key,'action':action,
                               'data_b64':base64.b64encode(raw).decode()},
                              eg_url=eg.EG_URL,api_key=eg.EG_API,
                              worker_socket=str(eg.sock),executor_public_key_b64=eg.raw_pub(eg.EXEC_NOTARY))
            if result['status'] != 'RECEIPT_VERIFIED_POST_REQUIRED':
                raise RuntimeError('WORKER_RECEIPT_NOT_VERIFIED')
            actual = target.read_bytes()
            if actual != raw or result['execution_receipt']['output_sha256'] != hashlib.sha256(actual).hexdigest():
                raise RuntimeError('ACTUAL_OUTPUT_MISMATCH')
            post_ref = eg.notarize([eg.binding(task,key,criterion,'POST_EXECUTION',pre['gate_checkpoint_no'],
                                   'ACTUAL_SHA='+hashlib.sha256(actual).hexdigest())],
                                   'ACTUAL_SHA='+hashlib.sha256(actual).hexdigest())
            post = eg.eg_req('POST','/v1/evaluate', {
                'event_id':eg.id('post'),'task_id':task,'contract_hash':contract,
                'protocol_hash':eg.PH,'checkpoint_no':pre['checkpoint_no'],'step_key':key,
                'agent':'SingleAgentLocalE2E','phase':'POST_EXECUTION','action':action,
                'execution_receipt':result['execution_receipt'],
                'claims':[{'criterion_index':0,'claim':criterion,'evidence':[post_ref]}]})
            if post['verdict'] != 'VERIFIED_PASS':
                raise RuntimeError('EG_POST_NOT_VERIFIED:'+repr(post))
            checkpoint = post['checkpoint_no']
            evidence.append({'step':key,'filename':filename,
                             'action':'replace' if replace else 'write',
                             'sha256':hashlib.sha256(actual).hexdigest(),
                             'receipt_verified':True,'verdict':post['verdict']})
        smoke=smoke_web(eg.WORK/'outputs',set(name for name,_ in files))
        if smoke['status'] not in ('PASS','SKIPPED_NO_ENTRYPOINT'):
            raise RuntimeError('WEB_PREVIEW_FAILED')
        final_criterion = 'Every project file independently verified'
        task_criterion = 'All file steps verified'
        marker = 'FILES_VERIFIED='+str(len(evidence))
        def finish(phase, cp, refcp, finalize=False):
            bindings = [eg.binding(task,'01',final_criterion,phase,refcp,marker)]
            if finalize:
                bindings.append(eg.binding(task,'01',task_criterion,phase,refcp,marker,'task'))
            ref=eg.notarize(bindings,marker)
            return eg.eg_req('POST','/v1/evaluate', {
                'event_id':eg.id('final'),'task_id':task,'contract_hash':contract,
                'protocol_hash':eg.PH,'checkpoint_no':cp,'step_key':'01',
                'agent':'SingleAgentLocalE2E','phase':phase,'action':None,
                'finalize_task':finalize,
                'claims':[{'criterion_index':0,'claim':final_criterion,'evidence':[ref]}],
                'task_claims':[{'criterion_index':0,'claim':task_criterion,'evidence':[ref]}] if finalize else []})
        parent_pre=finish('PRE_EXECUTION',checkpoint,checkpoint)
        parent_post=finish('POST_EXECUTION',parent_pre['checkpoint_no'],
                           parent_pre['gate_checkpoint_no'],finalize=True)
        current = eg.eg_req('GET', '/v1/tasks/'+task+'/state')
        audit = eg.eg_req('GET','/v1/audit/verify')
        verified = current['contract_status']=='SATISFIED' and parent_post['verdict']=='VERIFIED_PASS' and audit['status']=='PASS'
        result={'pass':verified,'task_id':task,                'status':current['contract_status'],'audit':audit['status'],
                'verified_steps':len(evidence),'files':evidence,'http_smoke':smoke,
                'workspace':str(eg.WORK/'outputs'),'scope':'E2 file creation and atomic replacement; no E3 build or deployment'}
        (eg.SESSION/'local_project_e2e.json').write_text(json.dumps(result,indent=2))
        return result
    finally:
        eg.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest',type=Path)
    args=parser.parse_args()
    try:
        response=run(args.manifest)
        print(json.dumps(response,indent=2))
        sys.exit(0 if response['pass'] else 1)
    except Exception as exc:
        print(json.dumps({'pass':False,'error':type(exc).__name__,'reason':str(exc),'details':exc.read().decode(errors="replace") if hasattr(exc,"read") else ""}))
        sys.exit(1)
