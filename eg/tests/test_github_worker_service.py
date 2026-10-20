"""Production GitHub worker must only start with independently protected files."""
import json,os
import pytest
from tools.github_worker_service import load_worker,WorkerConfigurationDenied

def test_nonroot_worker_rejects_injected_untrusted_operator_config(tmp_path,monkeypatch):
    real_uid=os.getuid()
    monkeypatch.setattr("tools.github_worker_service.os.getuid",lambda:real_uid if real_uid else 10001)
    file=tmp_path/"operator.json"
    file.write_text("{}")
    file.chmod(0o600)
    with pytest.raises(WorkerConfigurationDenied,match="INVALID_OPERATOR_CONFIG|UNSAFE_PRIVATE_WORKER_FILE"):
        load_worker(str(file))

def test_protected_worker_config_rejects_world_readability(tmp_path,monkeypatch):
    real_uid=os.getuid()
    if real_uid==0:
        pytest.skip("root cannot instantiate independent worker")
    file=tmp_path/"operator.json"
    file.write_text("{}")
    file.chmod(0o644)
    with pytest.raises(WorkerConfigurationDenied,match="UNSAFE_PRIVATE_WORKER_FILE"):
        load_worker(str(file))

def test_root_can_never_start_production_worker(tmp_path,monkeypatch):
    monkeypatch.setattr("tools.github_worker_service.os.getuid",lambda:0)
    with pytest.raises(WorkerConfigurationDenied,match="INDEPENDENT_NONROOT_WORKER_REQUIRED"):
        load_worker(str(tmp_path/"nonexistent"))


@pytest.mark.skipif(os.getuid()==0,reason="Production worker is never run as root")
def test_operator_provisioned_private_worker_loads_without_remote_effect(tmp_path):
    import base64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,PublicFormat,NoEncryption
    worker=Ed25519PrivateKey.generate()
    human=Ed25519PrivateKey.generate()
    journal=tmp_path/"journal";journal.mkdir(mode=0o700)
    def secret(name,data):
        path=tmp_path/name;path.write_bytes(data);path.chmod(0o600)
        return str(path)
    key=secret("worker.key",worker.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()))
    token=secret("github.token",b"CI_ONLY_NOT_REMOTE")
    eg_key=secret("eg.key",b"CI_ONLY_NOT_REMOTE")
    config={"version":1,"adapter_id":"trusted-adapter-github-test",
       "socket_path":str(tmp_path/"socket"),"journal_dir":str(journal),
       "policy":{"repository":"example/project","branch_prefix":"agent/",
                 "path_prefix":"src","actions":["create_file"]},
       "worker_key_file":key,"github_token_file":token,"eg_key_file":eg_key,
       "hitl_public_key_b64":base64.b64encode(human.public_key().public_bytes(
              Encoding.Raw,PublicFormat.Raw)).decode(),
       "capability_sha256":"a"*64,"eg_url":"http://127.0.0.1:9000",
       "controller_uid":os.getuid()+1,"controller_group_gid":None}
    path=tmp_path/"operator.json"
    path.write_text(json.dumps(config));path.chmod(0o600)
    result=load_worker(str(path))
    assert result["adapter"].adapter_id=="trusted-adapter-github-test"
    assert result["controller_uid"]!=os.getuid()
    assert result["worker_public_key_b64"]==base64.b64encode(worker.public_key().public_bytes(
        Encoding.Raw,PublicFormat.Raw)).decode()
