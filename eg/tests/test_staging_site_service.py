"""Actual separately owned staging service persists across deployments and rollback."""
import base64,hashlib,json,os,shutil,socket,subprocess,sys,tempfile,time,urllib.error,urllib.request
from pathlib import Path
import pytest

OWNER=65530
EXECUTOR=65532

def identity(uid):
    def enter():os.setgroups([]);os.setgid(uid);os.setuid(uid)
    return enter

def action(operation,raw=b''):
    return json.dumps({'operation':operation,'content_b64':base64.b64encode(raw).decode() if operation=='deploy' else '',
        'content_sha256':hashlib.sha256(raw).hexdigest()}).encode()+b'\n'

@pytest.mark.skipif(os.geteuid()!=0,reason='requires independent OS identities')
def test_real_staging_persistence_and_rollback():
    base=Path(tempfile.mkdtemp(prefix='eg-site-staging-',dir='/tmp'));base.chmod(0o755)
    source=Path(os.environ['EG_TEST_SOURCE'])
    process=None
    try:
        state=base/'state';state.mkdir(mode=0o700);os.chown(state,OWNER,OWNER)
        sockdir=base/'socket';sockdir.mkdir(mode=0o700);os.chown(sockdir,OWNER,EXECUTOR);sockdir.chmod(0o2710)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
        sock=str(sockdir/'site.sock')
        config=base/'config.json'
        config.write_text(json.dumps({'socket_path':sock,'state_dir':str(state),
            'controller_uid':EXECUTOR,'controller_gid':EXECUTOR,'http_port':port}))
        os.chown(config,OWNER,OWNER);config.chmod(0o600)
        env={**os.environ,'PYTHONPATH':str(source)}
        process=subprocess.Popen([sys.executable,'-m','tools.staging_site_service',str(config)],
            cwd=source,env=env,preexec_fn=identity(OWNER),stderr=subprocess.PIPE)
        for _ in range(100):
            if Path(sock).is_socket():break
            assert process.poll() is None,process.stderr.read()
            time.sleep(.04)
        assert Path(sock).is_socket()
        url=f'http://127.0.0.1:{port}/'
        with pytest.raises(urllib.error.HTTPError) as missing:
            urllib.request.urlopen(url,timeout=3)
        assert missing.value.code==503
        old=b'<!doctype html><h1>Cafe One</h1>'
        new=b'<!doctype html><h1>Cafe Two</h1>'
        def execute(packet):
            return subprocess.run([sys.executable,'-m','tools.staging_site_service','client',sock],
                cwd=source,env=env,preexec_fn=identity(EXECUTOR),input=packet,
                capture_output=True,timeout=10)
        for content in (old,new):
            result=execute(action('deploy',content))
            assert result.returncode==0,result.stderr
            assert json.loads(result.stdout)['sha256']==hashlib.sha256(content).hexdigest()
            assert urllib.request.urlopen(url,timeout=3).read()==content
            assert process.poll() is None
        bad=json.loads(action('deploy',old));bad['content_sha256']='0'*64
        denied=execute(json.dumps(bad).encode()+b'\n')
        assert denied.returncode!=0
        assert urllib.request.urlopen(url,timeout=3).read()==new
        rollback=execute(action('rollback',old))
        assert rollback.returncode==0,rollback.stderr
        assert urllib.request.urlopen(url,timeout=3).read()==old
        stale_inode=Path(sock).stat().st_ino
        process.kill();process.wait(timeout=3)
        process=subprocess.Popen([sys.executable,'-m','tools.staging_site_service',str(config)],
            cwd=source,env=env,preexec_fn=identity(OWNER),stderr=subprocess.PIPE)
        for _ in range(100):
            if Path(sock).is_socket() and Path(sock).stat().st_ino!=stale_inode:break
            assert process.poll() is None,process.stderr.read()
            time.sleep(.04)
        assert process.poll() is None
        assert urllib.request.urlopen(url,timeout=3).read()==old
        no_key=subprocess.run([sys.executable,'-c',
            'from pathlib import Path;import sys;Path(sys.argv[1]).read_bytes()',
            str(state/'active.json')],preexec_fn=identity(EXECUTOR),capture_output=True,timeout=5)
        assert no_key.returncode!=0 and b'PermissionError' in no_key.stderr
        with socket.socket(socket.AF_UNIX) as unauthorized:
            unauthorized.connect(sock)
            unauthorized.sendall(action('deploy',new))
            denial=json.loads(unauthorized.recv(4096))
        assert denial['status']=='DENIED'
        assert 'UNAUTHORIZED_EXECUTOR_UID' in denial['reason']
    finally:
        if process and process.poll() is None:
            process.terminate()
            try:process.wait(timeout=3)
            except subprocess.TimeoutExpired:process.kill();process.wait()
        shutil.rmtree(base,ignore_errors=True)
