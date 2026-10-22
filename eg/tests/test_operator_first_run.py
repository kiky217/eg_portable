"""One root-authorized installation; one agent and distinct non-AI workers thereafter."""
import base64
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest
from tools.operator_first_run import provision
from tools.operator_adapter_binding import verify_operator_binding
from tools.high_effect_admission import AdapterCapability

WORKER, SIGNER, AGENT = 65532, 65531, 65534


def switch(uid):
    def preexec():
        os.setgroups([]);os.setgid(uid);os.setuid(uid)
    return preexec


@pytest.mark.skipif(os.geteuid()!=0,reason='real separate UID OS privileges required')
def test_one_time_operator_provisioning_and_signed_worker_activation():
    parent=Path(tempfile.mkdtemp(prefix='eg-first-run-',dir='/tmp'))
    parent.chmod(0o755)
    src=Path(os.environ.get('EG_TEST_SOURCE',Path(__file__).resolve().parents[1]))
    eg_key=parent/'eg.key';eg_key.write_text('synthetic-local-only-key\n');eg_key.chmod(0o600)
    root=parent/'operator-workspace'
    policy={'root':str(root),'worker_uid':WORKER,'signer_uid':SIGNER,'agent_uid':AGENT,
            'adapter_id':'trusted-adapter-first-project','target_prefix':'/tasks/projects',
            'target':'/tasks/projects/build','executable':'/usr/bin/cat','fixed_args':[],
            'eg_url':'http://127.0.0.1:18766','gateway_key_file':str(eg_key)}
    worker=None
    try:
        with pytest.raises(ValueError,match='OUT_OF_SCOPE_OPERATOR_POLICY'):
            provision({**policy,'target_prefix':'/tasks/../escape','target':'/tasks/../escape/build'})
        result=provision(policy)
        assert result['adapter_id']==policy['adapter_id']
        assert len({result['operator_public_key_b64'],result['hitl_public_key_b64'],
                    result['capability']['public_key_b64']})==3
        with pytest.raises(ValueError,match='TRUSTED_NEW_INSTALL_DIR_REQUIRED'):
            provision(policy)
        for private in ('worker/worker.pem','worker/gateway.key','operator/operator.pem','signer/signer.pem'):
            info=(root/private).stat()
            assert stat.S_IMODE(info.st_mode)==0o600
        p=subprocess.run([sys.executable,'-c',
                'from pathlib import Path;import sys;Path(sys.argv[1]).read_bytes()',
                str(root/'worker/worker.pem')],preexec_fn=switch(AGENT),capture_output=True,timeout=5)
        assert p.returncode!=0 and b'PermissionError' in p.stderr
        env={**os.environ,'PYTHONPATH':str(src)}
        checker=subprocess.run([sys.executable,'-c',
              'from tools.operator_process_service import load_config;import sys;load_config(sys.argv[1])',
              result['worker_config_path']],cwd=src,env=env,
              preexec_fn=switch(WORKER),capture_output=True,timeout=5)
        assert checker.returncode==0,checker.stderr
        signer_checker=subprocess.run([sys.executable,'-c',
            'from tools.operator_scoped_approval import configure;import sys;configure(sys.argv[1])',
            result['signer_config_path']],cwd=src,env=env,
            preexec_fn=switch(SIGNER),capture_output=True,timeout=5)
        assert signer_checker.returncode==0,signer_checker.stderr
        binding=json.loads((root/'registry/binding.json').read_text())
        proof=verify_operator_binding(binding,operator_public_key_b64=result['operator_public_key_b64'],
                   adapter_id=policy['adapter_id'],capability_sha256=result['capability_sha256'])
        assert proof['status']=='SIGNED_CONFIGURATION_ONLY'
        worker=subprocess.Popen([sys.executable,'-m','tools.operator_process_service',result['worker_config_path']],
                cwd=src,env=env,preexec_fn=switch(WORKER),stderr=subprocess.PIPE)
        socket_path=Path(root/'socket/worker.sock')
        for _ in range(120):
            if socket_path.is_socket():break
            assert worker.poll() is None,worker.stderr.read().decode()
            time.sleep(.035)
        assert socket_path.is_socket()
        script='''import json,sys
from tools.operator_runtime_registry import OperatorAdapterRegistry
p=json.load(open(sys.argv[1]));b=json.load(open(sys.argv[2]))
a=OperatorAdapterRegistry(sys.argv[3],p['operator_public_key_b64']).activate(b,adapter_id=b['adapter_id'],capability_sha256=b['capability_sha256'])
assert a['status']=='ACTIVE_CONFIG_ONLY',a
'''
        result2=subprocess.run([sys.executable,'-c',script,str(root/'registry/public.json'),
                str(root/'registry/binding.json'),str(root/'registry')],cwd=src,env=env,
                preexec_fn=switch(AGENT),capture_output=True,timeout=8)
        assert result2.returncode==0,result2.stderr
    finally:
        if worker and worker.poll() is None:
            worker.terminate()
            try:worker.wait(timeout=3)
            except subprocess.TimeoutExpired:worker.kill();worker.wait()
        shutil.rmtree(parent,ignore_errors=True)
