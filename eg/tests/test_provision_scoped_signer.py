"""One operator action configures private signer identity and agent socket path."""
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import pytest
from tools.provision_scoped_signer import provision


@pytest.mark.skipif(os.geteuid()!=0,reason='root operator and distinct UIDs required')
def test_provision_once_protected_key_and_separate_nonroot_start():
    with tempfile.TemporaryDirectory(prefix='eg-installer-',dir='/tmp') as temp:
        parent=Path(temp);parent.chmod(0o700)
        root=parent/'site'
        out=provision(root,signer_uid=65531,signer_gid=65531,
            agent_uid=65534,agent_gid=65534,
            adapter_id='trusted-adapter-cafe',target_prefix='/tasks/staging',max_grants=1)
        assert out['socket']==str(root/'socket/approve.sock')
        assert stat.S_IMODE((root/'config.json').stat().st_mode)==0o600
        assert stat.S_IMODE(root.stat().st_mode)==0o710
        assert stat.S_IMODE((root/'socket').stat().st_mode)==0o2710
        with pytest.raises(ValueError,match='TRUSTED_NEW_OPERATOR_ROOT_REQUIRED'):
            provision(root,signer_uid=65531,signer_gid=65531,
                agent_uid=65534,agent_gid=65534,
                adapter_id='trusted-adapter-cafe',target_prefix='/tasks/staging')
        # The parent is operator-owned and non-writable by other users.
        parent.chmod(0o755);os.chown(parent,0,0)
        def user(uid):
            def pre():os.setgroups([]);os.setgid(uid);os.setuid(uid)
            return pre
        denied=subprocess.run([sys.executable,'-c',
            'from pathlib import Path;import sys;Path(sys.argv[1]).read_bytes()',str(root/'signer.pem')],
            preexec_fn=user(65534),capture_output=True,timeout=5)
        assert denied.returncode!=0 and b'PermissionError' in denied.stderr
        source=os.environ.get('EG_TEST_SOURCE',str(Path(__file__).resolve().parents[1]))
        ok=subprocess.run([sys.executable,'-c',
            'from tools.operator_scoped_approval import configure;import sys;configure(sys.argv[1]);print("OK")',
            out['config']],preexec_fn=user(65531),cwd=source,
            env={**os.environ,'PYTHONPATH':source},capture_output=True,timeout=6)
        assert ok.returncode==0,ok.stderr
        assert ok.stdout.strip()==b'OK'
