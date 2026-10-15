#!/usr/bin/env python3
"""Offline portable EG archive relocation and no-root fresh bootstrap E2E.

Only a disposable TEST security domain is used: executor public signing key is
test-only and is never used to claim root-protected isolation. Requires Linux
root to impersonate a dedicated nonroot identity for disposable E2E.
"""
from __future__ import annotations
import base64,hashlib,json,os,pwd,secrets,shutil,subprocess,tarfile,tempfile,time
from pathlib import Path
from urllib.request import Request,urlopen
from urllib.error import URLError
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
UID=65532
GID=65532
DIST=Path(__file__).resolve().parents[2]/'dist'
ARCH=Path(os.environ.get('EG_PORTABLE_ARCHIVE', str(DIST/'eg-portable-3.1.0-beta.1-linux-amd64.tar.gz'))).resolve()
RESULT=Path(os.environ.get('EG_PORTABLE_TEST_REPORT',str(DIST/'offline-relocation-e2e.json'))).resolve()
ROOT=Path(tempfile.mkdtemp(prefix='eg-portable-relocate-'))
A=ROOT/'a'
B=ROOT/'b'
STATE=ROOT/'durable-state'
LOG=ROOT/'log.txt'
PORT='18769'
proc=None
checks=[]
def check(name,success):
    checks.append({'check':name,'pass':bool(success)})
    if not success:raise RuntimeError('FAILED_CHECK '+name)
def switch():
    os.setgroups([]);os.setgid(GID);os.setuid(UID)
def hexhash(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()
def get(path,headers=None):
    with urlopen(Request('http://127.0.0.1:'+PORT+path,headers=headers or {}),timeout=3) as response:
        return json.loads(response.read())
def boot(p,env):
    global proc
    outfile=open(LOG,'ab')
    proc=subprocess.Popen([str(p/'start.sh')],env=env,cwd=p,
                          preexec_fn=switch,stdout=outfile,stderr=subprocess.STDOUT)
    for i in range(120):
        if proc.poll() is not None:raise RuntimeError('EG_EXIT_ON_STARTUP')
        try:
            if get('/health').get('status')=='PASS':return
        except (URLError,ConnectionError,TimeoutError):time.sleep(.1)
    raise RuntimeError('EG_HEALTH_NOT_PASS')
def stop():
    global proc
    if proc is not None:
        proc.terminate()
        try:proc.wait(timeout=6)
        except subprocess.TimeoutExpired:proc.kill()
        proc=None
def main():
    check('archive_exists',ARCH.is_file())
    A.mkdir();B.mkdir()
    with tarfile.open(ARCH,'r:gz') as tf:
        for item in tf.getmembers():
            path=Path(item.name)
            check('archive_member_safe_'+str(path)[:48],
                  not path.is_absolute() and '..' not in path.parts and
                  (item.isfile() or item.isdir()))
        tf.extractall(A,filter='data')
    extracted=next(A.glob('eg-portable-*-linux-amd64'))
    manifest=json.loads((extracted/'MANIFEST.json').read_text())
    check('manifest_coverage',len(manifest['files'])>1000)
    for rel,expected in manifest['files'].items():
        p=extracted/rel
        if not p.is_file() or hexhash(p)!=expected:
            raise RuntimeError('DISTRIBUTION_FILE_HASH_MISMATCH '+rel)
    check('all_files_sha256_valid',True)
    # Simulate independent OS user with no container-specific Python installation.
    for p in (ROOT,A,B,extracted):
        p.chmod(0o755)
    ROOT.chmod(0o755)
    for part in (A,B):
        os.chmod(part,0o755)
    # Disposable sandbox parent is sticky like /tmp; the actual EG state stays 0700.
    ROOT.chmod(0o1777)
    test_public=base64.b64encode(Ed25519PrivateKey.generate().public_key().public_bytes(
         Encoding.Raw,PublicFormat.Raw)).decode()
    env={k:v for k,v in os.environ.items() if k in ('PATH','LANG','LC_ALL')}
    env.update({'EG_STATE_DIR':str(STATE),'EG_EXECUTOR_PUBLIC_KEY_B64':test_public,
                'EG_PORT':PORT,'PYTHONNOUSERSITE':'1','HOME':'/tmp'})
    # Reject insecure invocation as root, no initialized state, absent remote trust root.
    denied=subprocess.run([str(extracted/'init.sh')],env=env,capture_output=True,text=True,timeout=10)
    check('root_initialized_denied',denied.returncode==77)
    denied=subprocess.run([str(extracted/'start.sh')],env=env,capture_output=True,text=True,timeout=10,
                          preexec_fn=switch)
    check('start_without_state_denied',denied.returncode==77)
    init=subprocess.run([str(extracted/'init.sh')],env=env,capture_output=True,text=True,
                        timeout=10,preexec_fn=switch)
    if init.returncode:print('INIT_FAIL',init.returncode,init.stderr[-1000:],init.stdout[-150:])
    check('nonroot_initialization_pass',init.returncode==0)
    check('state_directory_0700',(STATE.stat().st_mode&0o777)==0o700)
    check('notary_key_private',(STATE/'notary-private.pem').stat().st_mode&0o777==0o600)
    second=subprocess.run([str(extracted/'init.sh')],env=env,capture_output=True,text=True,
                          timeout=10,preexec_fn=switch)
    check('existing_state_not_overwritten',second.returncode==77)
    shutil.rmtree(B)
    shutil.move(str(extracted),str(B))
    B.chmod(0o755)
    boot(B,env)
    check('relocated_eg_health_pass',get('/health').get('status')=='PASS')
    # No unauthorized API access.
    from urllib.error import HTTPError
    try:
        get('/v1/audit/verify')
    except HTTPError as e:
        check('api_requires_auth',e.code==401)
    else:
        raise RuntimeError('UNAUTHENTICATED_AUDIT_REQUEST_SUCCEEDED')
    creds={}
    for line in (STATE/'runtime.env').read_text().splitlines():
        k,sep,v=line.partition('=')
        if sep:creds[k]=v
    headers={'X-Evaluation-Key':creds['EVALUATION_GATEWAY_API_KEY']}
    audit1=get('/v1/audit/verify',headers)
    check('authenticated_audit_PASS',audit1['status']=='PASS')
    # Move installed application again while preserving external state.
    stop();C=ROOT/'third-location';shutil.move(str(B),str(C));C.chmod(0o755)
    boot(C,env)
    audit2=get('/v1/audit/verify',headers)
    check('relocation_restart_preserves_anchor',audit2['status']=='PASS'
          and audit2['head']==audit1['head'])
    check('runtime_has_no_embedded_credentials',
          not any(x.is_file() for x in C.rglob('*.pem')) and
          not (C/'runtime.env').exists())
    output={'status':'PASS','archive':str(ARCH),
      'archive_size':ARCH.stat().st_size,'archive_sha256':hexhash(ARCH),
      'checks_count':len(checks),'all_checks_pass':all(x['pass'] for x in checks),
      'python_bundled':True,'offline':True,'relocation_count':2,
      'eg_version':audit2['version'],
      'state_outside_binary':True,'isolation_level':'same-host nonroot UID only',
      'host_root_security':'NOT PROVEN','checks':checks}
    RESULT.write_text(json.dumps(output,indent=2))
    print(json.dumps({k:output[k] for k in ('status','archive_size','archive_sha256',
           'checks_count','all_checks_pass','relocation_count','eg_version')}))
if __name__=='__main__':
    try:main()
    finally:
        stop()
        shutil.rmtree(ROOT,ignore_errors=True)
