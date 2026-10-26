"""Read-only, provider-neutral EG deployment doctor (E0, E2, E3, E4, E5).

Verifies signed operator bindings and fresh worker liveness. Does not issue PRE,
execute effects, rotate keys, grant approval, or advance an EG checkpoint.
"""
from __future__ import annotations
import argparse,json,os,stat,time,urllib.error,urllib.request
from pathlib import Path
from tools.operator_runtime_registry import OperatorAdapterRegistry
from tools.adapter_liveness import probe_unix

class InspectionError(RuntimeError):pass


def _read_private_env(path):
    path=Path(path)
    info=path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid()
        or stat.S_IMODE(info.st_mode)&0o077 or path.is_symlink()):
        raise InspectionError('PRIVATE_RUNTIME_CONFIG_REQUIRED')
    values={}
    for line in path.read_text().splitlines():
        if not line or '=' not in line:raise InspectionError('INVALID_RUNTIME_CONFIG')
        key,value=line.split('=',1)
        if key in values:raise InspectionError('DUPLICATE_RUNTIME_CONFIG_KEY')
        values[key]=value
    return values


def inspect(*,state,manifest,url='http://127.0.0.1:18766',task_id=None):
    if not (url.startswith('http://127.0.0.1:') or url.startswith('http://localhost:')):
        raise InspectionError('LOCAL_GATEWAY_URL_REQUIRED')
    state=Path(state)
    cfg=_read_private_env(state/'runtime.env')
    # Match the signed registry's identity validation mode to the actual
    # private gateway configuration; the doctor never relaxes a host policy.
    os.environ['EVALUATION_GATEWAY_LOCAL_HOST_MODE']=(
        'enabled' if cfg.get('EVALUATION_GATEWAY_LOCAL_HOST_MODE')=='enabled'
        else 'disabled')
    manifest=Path(manifest)
    if manifest.is_symlink() or not manifest.is_file():raise InspectionError('CATALOG_NOT_PRESENT')
    doc=json.loads(manifest.read_text())
    pin=cfg.get('EVALUATION_GATEWAY_EXTERNAL_REGISTRY_OPERATOR_PUBLIC_KEY_B64')
    if not pin or pin!=doc.get('operator_public_key_b64'):
        raise InspectionError('UNTRUSTED_CATALOG_OPERATOR_ROOT')
    caps=doc.get('capabilities',[])
    if not isinstance(caps,list) or not 1<=len(caps)<=32:
        raise InspectionError('INVALID_CATALOG_CAPABILITIES')
    expected={c['adapter_id']:(c['effect_class'],c['action_type']) for c in caps}
    if len(expected)!=len(caps):raise InspectionError('DUPLICATE_ADAPTER_ID')
    headers={'X-Evaluation-Key':cfg['EVALUATION_GATEWAY_API_KEY']}
    def get(path):
        request=urllib.request.Request(url+path,headers=headers)
        with urllib.request.urlopen(request,timeout=5) as response:return json.load(response)
    health=get('/health')
    audit=get('/v1/audit/verify')
    catalog=get('/v1/agent/capabilities')
    listed={c['adapter_id']:(c['effect_class'],c['action_type'])
            for c in catalog['capabilities'] if c.get('effect_class') in ('E3','E4','E5')}
    registered={c['effect_class'] for c in catalog['capabilities']}
    registry=OperatorAdapterRegistry(doc['registry_dir'],pin,read_only=True)
    rows=[]
    for adapter,(effect,action) in expected.items():
        row={'adapter_id':adapter,'effect_class':effect,'action_type':action,
             'catalog_match':listed.get(adapter)==(effect,action),
             'binding':'NOT_VERIFIED','worker_liveness':'NOT_VERIFIED','admission':False}
        try:
            signed=registry.resolve(adapter)
            row['binding']='SIGNED_VALID'
            row['binding_ttl_seconds']=max(0,int(signed['expires_at']-time.time()))
            capability=next(c for c in caps if c['adapter_id']==adapter)
            from hashlib import sha256
            from dataclasses import asdict
            from tools.adapter_liveness import canon
            from tools.high_effect_admission import AdapterCapability
            computed=sha256(canon(asdict(AdapterCapability(**capability)))).hexdigest()
            if computed!=signed['capability_sha256']:
                raise InspectionError('CAPABILITY_DIGEST_MISMATCH')
            proof=probe_unix(signed['socket_path'],adapter_id=adapter,
                 capability_sha256=computed,public_key_b64=signed['worker_public_key_b64'],
                 task_id='inspection-read-only',step_key='00.01',gate_checkpoint_no=1,
                 action_fingerprint=computed,expected_worker_uid=signed['worker_uid'])
            if proof['status']!='SIGNED_LIVENESS_ONLY_NOT_EXECUTION_ADMITTED':
                raise InspectionError('UNEXPECTED_LIVENESS_STATUS')
            row['worker_liveness']='SIGNED_PASS'
        except Exception as exc:
            row['issue']=type(exc).__name__+':'+str(exc)
        row['status']=('MATCHED_LIVE_PRE_REQUIRED' if row['catalog_match'] and
                       row['binding']=='SIGNED_VALID' and row['worker_liveness']=='SIGNED_PASS'
                       else 'UNAVAILABLE')
        rows.append(row)
    result={'gateway':health.get('status'),'audit':audit.get('status'),
            'audit_records':audit.get('records'),'admission_mode':catalog.get('admission_mode'),
            'builtins':{k:('CONFIGURED_NOT_VERIFIED' if k in registered else 'MISSING') for k in ('E0','E2')},
            'high_effect':rows,'all_high_effect_listed_and_live':all(x['status']=='MATCHED_LIVE_PRE_REQUIRED' for x in rows),
            'effect_verification':'NOT_EVALUATED_BY_READ_ONLY_INSPECTION'}
    if task_id:
        state_doc=get('/v1/tasks/'+task_id+'/state')
        checkpoint=state_doc.get('latest_checkpoint')
        result['task']={'id':task_id,'status':state_doc.get('status'),
                        'contract_status':state_doc.get('contract_status'),
                        'next_step':state_doc.get('current_step'),
                        'checkpoint':checkpoint.get('checkpoint_no') if checkpoint else None}
    return result


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--state',type=Path,required=True)
    ap.add_argument('--manifest',type=Path,required=True)
    ap.add_argument('--url',default='http://127.0.0.1:18766')
    ap.add_argument('--task-id')
    args=ap.parse_args()
    print(json.dumps(inspect(state=args.state,manifest=args.manifest,
                             url=args.url,task_id=args.task_id),sort_keys=True))

if __name__=='__main__':main()
