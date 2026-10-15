#!/usr/bin/env python3
"""Record reconciled terminal state after read-only EG and effect verification."""
import importlib.util,hashlib,json,os,sys
from pathlib import Path
W=Path('/content/workspace')
spec=importlib.util.spec_from_file_location('eg',str(W/'bin/eg-gated-run.py'))
eg=importlib.util.module_from_spec(spec);spec.loader.exec_module(eg)
jdir=W/'artifacts/eg-managed/journal';outputs=W/'artifacts/eg-managed/outputs'
for task in sys.argv[1:]:
 state=eg.req('GET','/v1/tasks/'+task+'/state')
 audit=eg.req('GET','/v1/audit/verify')
 payload=('EG_E2_RUNTIME:'+task+'\n').encode()
 target=outputs/(task+'.txt')
 if state.get('contract_status')!='SATISFIED' or audit.get('status')!='PASS' or target.read_bytes()!=payload:
  print('NOT_VERIFIED '+task);continue
 current=jdir/(task+'.json')
 info={'task_id':task,'stage':'RECONCILED_VERIFIED','effect_sha256':hashlib.sha256(payload).hexdigest(),
       'checkpoint_no':state['latest_checkpoint']['checkpoint_no']}
 tmp=current.with_suffix('.verified.tmp')
 with tmp.open('xb') as out:
  out.write(json.dumps(info,sort_keys=True).encode());out.flush();os.fsync(out.fileno())
 os.replace(tmp,current)
 print('RECONCILED_VERIFIED '+task)
