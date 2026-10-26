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
            'effect_class':'E3','action_type':'bounded_process_run',
            'profiles':[{'target':'/tasks/projects/build','executable':'/usr/bin/cat','fixed_args':[]}],
            'eg_url':'http://127.0.0.1:18766','gateway_key_file':str(eg_key)}
    worker=None
    try:
        untrusted=parent/'agent-command'
        untrusted.write_text('#!/bin/sh\necho untrusted\n')
        untrusted.chmod(0o755)
        os.chown(untrusted,AGENT,AGENT)
        with pytest.raises(ValueError,match='UNTRUSTED_OPERATOR_EXECUTABLE'):
            provision({**policy,'profiles':[dict(policy['profiles'][0],executable=str(untrusted))]})
        with pytest.raises(ValueError,match='OUT_OF_SCOPE_OPERATOR_POLICY'):
            provision({**policy,'target_prefix':'/tasks/../escape'})
        with pytest.raises(ValueError,match='INVALID_OPERATOR_POLICY'):
            provision({**policy,'target':'/tasks/projects/build'})
        implicit=dict(policy)
        implicit.pop('effect_class')
        with pytest.raises(ValueError,match='INVALID_OPERATOR_POLICY'):
            provision(implicit)
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
        pin=root/'operator-public-key.b64'
        assert pin.stat().st_uid == 0
        assert stat.S_IMODE(pin.stat().st_mode) == 0o444
        assert pin.read_text().strip() == result['operator_public_key_b64']
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
        result2=subprocess.run([sys.executable,'-m','tools.operator_activate_catalog',
                str(root),'--mode','activate'],cwd=src,env=env,
                preexec_fn=switch(AGENT),capture_output=True,timeout=8)
        assert result2.returncode==0,result2.stderr
        assert json.loads(result2.stdout)['status']=='ACTIVE_CONFIG_ONLY'
        verified=subprocess.run([sys.executable,'-m','tools.operator_activate_catalog',
                str(root),'--mode','verify'],cwd=src,env=env,
                preexec_fn=switch(AGENT),capture_output=True,timeout=8)
        assert verified.returncode==0,verified.stderr
        assert json.loads(verified.stdout)['status']=='REGISTRY_ACTIVE_AND_WORKER_LIVE'
        assert json.loads(verified.stdout)['canonical_pre_post_verified'] is False
        # Agent-writable discovery metadata cannot substitute root-pinned trust.
        public_file=root/'registry/public.json'
        metadata=json.loads(public_file.read_text())
        metadata['operator_public_key_b64']='AA' * 22
        public_file.write_text(json.dumps(metadata))
        denied=subprocess.run([sys.executable,'-m','tools.operator_activate_catalog',
                str(root),'--mode','inspect'],cwd=src,env=env,
                preexec_fn=switch(AGENT),capture_output=True,timeout=8)
        assert denied.returncode!=0
        assert 'OPERATOR_PUBLIC_KEY_PIN_MISMATCH' in denied.stdout.decode()
    finally:
        if worker and worker.poll() is None:
            worker.terminate()
            try:worker.wait(timeout=3)
            except subprocess.TimeoutExpired:worker.kill();worker.wait()
        shutil.rmtree(parent,ignore_errors=True)


@pytest.mark.skipif(os.geteuid()!=0,reason='independent-UID operator bootstrap fixture')
def test_one_generic_catalog_bootstraps_multiple_tasks_in_named_environment():
    base=Path(tempfile.mkdtemp(prefix='eg-catalog-install-',dir='/tmp'))
    try:
        base.chmod(0o755)
        credential=base/'gateway.key'
        credential.write_text('isolated-gateway-fixture-only\n')
        credential.chmod(0o600)
        policy={'root':str(base/'worker-install'),'worker_uid':WORKER,
                'signer_uid':SIGNER,'agent_uid':AGENT,
                'adapter_id':'trusted-adapter-shared-workflow',
                'target_prefix':'/tasks/workflow',
                'effect_class':'E3','action_type':'bounded_process_run',
                'profiles':[
                    {'target':'/tasks/workflow/inspect','executable':'/usr/bin/cat',
                     'fixed_args':[]},
                    {'target':'/tasks/workflow/check','executable':'/usr/bin/cat',
                     'fixed_args':[], 'timeout':8}],
                'environment':'isolated','grant_seconds':90,'max_grants':3,
                'eg_url':'http://127.0.0.1:18766','gateway_key_file':str(credential)}
        with pytest.raises(ValueError,match='INVALID_GENERIC_OPERATOR_LIFETIME'):
            provision({**policy,'grant_seconds':90000})
        result=provision(policy)
        root=Path(policy['root'])
        config=json.loads((root/'worker/config.json').read_text())
        assert 'profiles' in config and len(config['profiles'])==2
        assert not any(x in config for x in ('target','executable','fixed_args'))
        assert config['profiles'][1]['timeout']==8
        binding=json.loads((root/'registry/binding.json').read_text())
        assert binding['environment']=='isolated'
        assert binding['expires_at']-binding['issued_at']<=91
        signer=json.loads((root/'signer/config.json').read_text())
        assert signer['max_grants']==3
        assert signer['target_prefix']=='/tasks/workflow'
        assert result['adapter_id']==policy['adapter_id']
    finally:
        shutil.rmtree(base,ignore_errors=True)


@pytest.mark.parametrize("effect", ["E4", "E5"])
@pytest.mark.skipif(os.geteuid()!=0,reason="independent-UID operator bootstrap fixture")
def test_high_effect_generic_worker_provisions_without_new_executor_module(effect):
    base=Path(tempfile.mkdtemp(prefix="eg-generic-high-",dir="/tmp"))
    try:
        base.chmod(0o755)
        credential=base/"gateway.key"
        credential.write_text("isolated-high-effect-gateway-fixture\n")
        credential.chmod(0o600)
        policy={"root":str(base/"worker-install"),"worker_uid":WORKER,
                "signer_uid":SIGNER,"agent_uid":AGENT,
                "adapter_id":"trusted-adapter-high-"+effect.lower(),
                "target_prefix":"/tasks/workflow",
                "effect_class":effect,"action_type":"bounded_process_run",
                "profiles":[
                    {"target":"/tasks/workflow/app","executable":"/usr/bin/cat","fixed_args":[]},
                    {"target":"/tasks/workflow/database","executable":"/usr/bin/cat","fixed_args":[]}],
                "eg_url":"http://127.0.0.1:18766",
                "gateway_key_file":str(credential)}
        with pytest.raises(ValueError,match="INVALID_TYPED_OPERATOR_CAPABILITY"):
            provision({**policy,"effect_class":"E9"})
        result=provision(policy)
        assert result["capability"]["effect_class"]==effect
        assert result["capability"]["action_type"]=="bounded_process_run"
        worker=json.loads((Path(policy["root"])/"worker/config.json").read_text())
        signer=json.loads((Path(policy["root"])/"signer/config.json").read_text())
        assert worker["effect_class"]==signer["effect_class"]==effect
        assert worker["action_type"]==signer["action_type"]=="bounded_process_run"
        assert len(worker["profiles"])==2
        assert result["capability"]["ci_only"] is False
        # Same activation implementation must accept each separately signed
        # high-effect identity; never use the E3 adapter as an E4/E5 grant.
        env={**os.environ, 'PYTHONPATH':str(Path(__file__).resolve().parents[1])}
        worker=subprocess.Popen([sys.executable,'-m','tools.operator_process_service',
                result['worker_config_path']],cwd=Path(__file__).resolve().parents[1],
                env=env,preexec_fn=switch(WORKER),stderr=subprocess.PIPE)
        try:
            socket_path=Path(policy['root'])/'socket/worker.sock'
            for _ in range(120):
                if socket_path.is_socket():break
                assert worker.poll() is None,worker.stderr.read().decode()
                time.sleep(.035)
            assert socket_path.is_socket()
            activated=subprocess.run([sys.executable,'-m','tools.operator_activate_catalog',
                    str(Path(policy['root'])),'--mode','activate'],
                    cwd=Path(__file__).resolve().parents[1],env=env,
                    preexec_fn=switch(AGENT),capture_output=True,timeout=8)
            assert activated.returncode==0,activated.stdout+activated.stderr
            state=json.loads(activated.stdout)
            assert state['effect_class']==effect
            assert state['status']=='ACTIVE_CONFIG_ONLY'
            assert state['canonical_pre_post_verified'] is False
        finally:
            if worker.poll() is None:
                worker.terminate()
                try:worker.wait(timeout=3)
                except subprocess.TimeoutExpired:worker.kill();worker.wait()
    finally:
        shutil.rmtree(base,ignore_errors=True)
