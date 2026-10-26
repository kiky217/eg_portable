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
RELEASE_VERSION=(Path(__file__).resolve().parents[1]/'VERSION').read_text().strip()
ARCH=Path(os.environ.get('EG_PORTABLE_ARCHIVE', str(DIST/f'eg-portable-{RELEASE_VERSION}-linux-amd64.tar.gz'))).resolve()
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
    with ARCH.open('rb') as stream:
        header=stream.read(10)
    check('gzip_mtime_normalized',len(header)==10 and header[:2]==b'\x1f\x8b' and header[4:8]==b'\0'*4)
    A.mkdir();B.mkdir()
    with tarfile.open(ARCH,'r:gz') as tf:
        forbidden={'.env','runtime.env','id_rsa','id_ed25519','.npmrc','.pypirc',
                   'evidence','backups','secrets','data','.git','_runtime'}
        check('no_runtime_data_in_archive',
              all(not (set(Path(m.name).parts) & forbidden) for m in tf.getmembers()))
        check('tar_metadata_normalized',all(item.mtime==0 and item.uid==0 and item.gid==0 and not item.uname and not item.gname for item in tf.getmembers()))
        # Distribution permissions are a release contract: the build runner may
        # have used umask 077, but an independent non-root UID must traverse
        # every public directory and read every shipped runtime module.
        executable_paths={'python/bin/python3.12','python.sh','run.sh','init.sh','start.sh'}
        check('tar_public_permissions_nonroot',all(
            (member.mode & 0o777)==(0o755 if member.isdir() or
                 '/'.join(Path(member.name).parts[1:]) in executable_paths else 0o644)
            for member in tf.getmembers()))
        for item in tf.getmembers():
            path=Path(item.name)
            check('archive_member_safe_'+str(path)[:48],
                  not path.is_absolute() and '..' not in path.parts and
                  (item.isfile() or item.isdir()))
        tf.extractall(A,filter='data')
    extracted=next(A.glob('eg-portable-*-linux-amd64'))
    manifest=json.loads((extracted/'MANIFEST.json').read_text())
    check('extracted_public_permissions_nonroot',all(
        (path.stat().st_mode & 0o777)==(0o755 if path.is_dir() or
            path.relative_to(extracted).as_posix() in executable_paths else 0o644)
        for path in (extracted,*extracted.rglob('*'))))
    check('manifest_coverage',len(manifest['files'])>1000)
    project_license=extracted/'eg/LICENSE'
    check('project_license_present',project_license.is_file() and project_license.read_text(encoding='utf-8').startswith('MIT License\n'))
    check('project_license_hash',manifest['files'].get('eg/LICENSE')==hexhash(project_license))
    public_docs=('README.md','SKILL.md','SECURITY.md','LICENSE')
    check('root_operational_docs_bundled',all(
        (extracted/name).is_file() and manifest['files'].get(name)==hexhash(extracted/name)
        for name in public_docs))
    public_artwork=('eg-step-review.svg','eg-workflow.svg')
    check('linked_public_diagrams_bundled',all(
        (extracted/'eg/docs/assets'/name).is_file() and
        manifest['files'].get('eg/docs/assets/'+name)==hexhash(extracted/'eg/docs/assets'/name)
        for name in public_artwork))
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
    notary_public=base64.b64encode(Ed25519PrivateKey.generate().public_key().public_bytes(
         Encoding.Raw,PublicFormat.Raw)).decode()
    check('separate_test_notary_and_executor_roots',test_public!=notary_public)
    env={k:v for k,v in os.environ.items() if k in ('PATH','LANG','LC_ALL')}
    env.update({'EG_STATE_DIR':str(STATE),'EG_EXECUTOR_PUBLIC_KEY_B64':test_public,
                'EG_NOTARY_PUBLIC_KEY_B64':notary_public,
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
    check('notary_private_key_absent_from_service_state',not (STATE/'notary-private.pem').exists())
    check('notary_public_root_configured',
          'EVALUATION_GATEWAY_EVIDENCE_PUBLIC_KEY_B64='+notary_public in (STATE/'runtime.env').read_text())
    second=subprocess.run([str(extracted/'init.sh')],env=env,capture_output=True,text=True,
                          timeout=10,preexec_fn=switch)
    check('existing_state_not_overwritten',second.returncode==77)
    # Regression: explicitly disabled audit-only installer must not require an executor key.
    audit_state=ROOT/'audit-only-state'
    audit_env=dict(env,EG_STATE_DIR=str(audit_state),
                   EVALUATION_GATEWAY_ADMISSION_MODE='disabled')
    audit_env.pop('EG_EXECUTOR_PUBLIC_KEY_B64',None)
    audit_init=subprocess.run([str(extracted/'init.sh')],env=audit_env,
                              capture_output=True,text=True,timeout=10,preexec_fn=switch)
    check('audit_only_init_without_executor_pass',audit_init.returncode==0)
    audit_config=(audit_state/'runtime.env').read_text()
    check('audit_only_mode_persisted',
          'EVALUATION_GATEWAY_ADMISSION_MODE=disabled' in audit_config)
    check('audit_only_executor_root_empty',
          'EVALUATION_GATEWAY_EXECUTOR_PUBLIC_KEY_B64=\n' in audit_config)
    enabled_env=dict(env,EG_STATE_DIR=str(ROOT/'no-executor-state'))
    enabled_env.pop('EG_EXECUTOR_PUBLIC_KEY_B64',None)
    enabled_init=subprocess.run([str(extracted/'init.sh')],env=enabled_env,
                                capture_output=True,text=True,timeout=10,preexec_fn=switch)
    check('enabled_missing_executor_still_denied',enabled_init.returncode==77)
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
