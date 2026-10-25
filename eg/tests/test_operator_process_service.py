"""Real separate-UID process-service startup and fail-closed identity checks."""
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption,PublicFormat
from tools.adapter_liveness import canon
from tools.high_effect_admission import AdapterCapability

pytestmark=pytest.mark.skipif(os.geteuid()!=0,reason="isolated cross-UID integration requires root fixture")
# Cross-UID subprocesses must import from an independently readable test source.
ROOT = Path(os.environ.get("EG_TEST_SOURCE", Path(__file__).resolve().parents[1]))
WORKER_UID=65533
CONTROLLER_UID=65534


def _identity(uid):
    def switch():
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)
    return switch


def _layout(tmp):
    tmp.chmod(0o755)
    worker_dir=tmp/"worker";worker_dir.mkdir(mode=0o700)
    journal=worker_dir/"journal";journal.mkdir(mode=0o700)
    socket_dir=tmp/"socket";socket_dir.mkdir()
    os.chown(worker_dir,WORKER_UID,WORKER_UID)
    os.chown(journal,WORKER_UID,WORKER_UID)
    os.chown(socket_dir,WORKER_UID,CONTROLLER_UID)
    socket_dir.chmod(0o2710)
    key=Ed25519PrivateKey.generate()
    pub=base64.b64encode(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
    cap=AdapterCapability(adapter_id="trusted-adapter-process-real-service",effect_class="E3",
          action_type="bounded_process_run",target_prefix="/tasks/app/",maximum_payload_bytes=4096,
          isolated=True,public_key_b64=pub,ci_only=False)
    digest=hashlib.sha256(canon(asdict(cap))).hexdigest()
    secret=worker_dir/"worker.pem"
    secret.write_bytes(key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
    token=worker_dir/"gateway-key";token.write_text("isolated-gateway-test-key\n")
    config=worker_dir/"config.json"
    settings={"adapter_id":cap.adapter_id,"capability_sha256":digest,
              "socket_path":str(socket_dir/"worker.sock"),"journal_dir":str(journal),
              "private_key_path":str(secret),"eg_url":"http://127.0.0.1:18766",
              "eg_api_key_path":str(token),"hitl_public_key_b64":pub,
              "controller_uid":CONTROLLER_UID,"controller_group_gid":CONTROLLER_UID,
              "effect_class":"E3","action_type":"bounded_process_run",
              "profiles":[{"target":"/tasks/app/build","executable":"/usr/bin/cat","fixed_args":[]}]}
    config.write_text(json.dumps(settings))
    for path in (secret,token,config):
        os.chown(path,WORKER_UID,WORKER_UID)
        path.chmod(0o600)
    return config,settings,pub,digest


def test_real_worker_startup_identity_and_no_agent_key_access():
    from tools.adapter_liveness import probe_unix
    base=Path(tempfile.mkdtemp(prefix="eg-service-",dir="/tmp"))
    worker=None
    try:
        config,settings,pub,digest=_layout(base)
        command=[sys.executable,"-m","tools.operator_process_service",str(config)]
        env={**os.environ,"PYTHONPATH":str(ROOT)}
        denied=subprocess.run([sys.executable,"-c","from pathlib import Path;import sys;Path(sys.argv[1]).read_bytes()",
                               settings["private_key_path"]],preexec_fn=_identity(CONTROLLER_UID),
                               capture_output=True,timeout=6)
        assert denied.returncode!=0
        assert b"PermissionError" in denied.stderr
        worker=subprocess.Popen(command,cwd=ROOT,env=env,preexec_fn=_identity(WORKER_UID),
                                stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        for _ in range(60):
            if Path(settings["socket_path"]).is_socket():break
            assert worker.poll() is None,worker.stderr.read().decode()
            time.sleep(.05)
        assert Path(settings["socket_path"]).is_socket()
        script="""from tools.adapter_liveness import probe_unix
import sys
probe_unix(sys.argv[1],adapter_id=sys.argv[2],capability_sha256=sys.argv[3],
 public_key_b64=sys.argv[4],task_id='test',step_key='01.01',
 gate_checkpoint_no=1,action_fingerprint=sys.argv[3],expected_worker_uid=65533)
print('SIGNED_OS_UID_PINNED_LIVENESS_PASS')"""
        verified=subprocess.run([sys.executable,"-c",script,settings["socket_path"],
             settings["adapter_id"],digest,pub],cwd=ROOT,env=env,
             preexec_fn=_identity(CONTROLLER_UID),capture_output=True,timeout=6)
        assert verified.returncode==0,verified.stderr
        assert b"SIGNED_OS_UID_PINNED_LIVENESS_PASS" in verified.stdout
        wrong=subprocess.run([sys.executable,"-c",script.replace("expected_worker_uid=65533", "expected_worker_uid=65532"),
             settings["socket_path"],settings["adapter_id"],digest,pub],cwd=ROOT,env=env,
             preexec_fn=_identity(CONTROLLER_UID),capture_output=True,timeout=6)
        assert wrong.returncode!=0 and b"LIVENESS_WORKER_UID_MISMATCH" in wrong.stderr
    finally:
        if worker and worker.poll() is None:
            worker.terminate()
            try:worker.wait(timeout=3)
            except subprocess.TimeoutExpired:worker.kill();worker.wait()
        shutil.rmtree(base,ignore_errors=True)


def test_root_or_world_readable_worker_config_denied():
    from tools.operator_process_service import load_config,ConfigurationDenied
    base=Path(tempfile.mkdtemp(prefix="eg-policy-",dir="/tmp"))
    try:
        config,settings,_,_=_layout(base)
        with pytest.raises(ConfigurationDenied,match="WORKER_MUST_RUN_UNPRIVILEGED"):
            load_config(config)
        config.chmod(0o644)
        probe=subprocess.run([sys.executable,"-m","tools.operator_process_service",str(config)],
            cwd=ROOT,env={**os.environ,"PYTHONPATH":str(ROOT)},
            preexec_fn=_identity(WORKER_UID),capture_output=True,timeout=5)
        assert probe.returncode!=0 and b"PRIVATE_WORKER_FILE_REQUIRED" in probe.stderr
    finally:
        shutil.rmtree(base,ignore_errors=True)


def test_worker_denies_removed_config_schema_and_missing_class():
    base=Path(tempfile.mkdtemp(prefix="eg-typed-policy-",dir="/tmp"))
    try:
        config,settings,_,_=_layout(base)
        def run(config_payload):
            config.write_text(json.dumps(config_payload))
            return subprocess.run(
                [sys.executable,"-m","tools.operator_process_service",str(config)],
                cwd=ROOT,env={**os.environ,"PYTHONPATH":str(ROOT)},
                preexec_fn=_identity(WORKER_UID),capture_output=True,timeout=5)
        without_type=dict(settings)
        without_type.pop("effect_class")
        denied=run(without_type)
        assert denied.returncode!=0 and b"INVALID_OPERATOR_WORKER_CONFIGURATION" in denied.stderr
        obsolete=dict(settings)
        obsolete.pop("effect_class")
        obsolete.pop("action_type")
        obsolete.pop("profiles")
        obsolete.update(target="/tasks/app/build", executable="/usr/bin/cat", fixed_args=[])
        denied=run(obsolete)
        assert denied.returncode!=0 and b"INVALID_OPERATOR_WORKER_CONFIGURATION" in denied.stderr
    finally:
        shutil.rmtree(base,ignore_errors=True)
