"""Opt-in independently operated GitHub E4 worker service.

Run as a dedicated non-root OS user with privately provisioned files. Neither
EG nor this program generates operator keys, HITL approvals or GitHub tokens.
"""
from __future__ import annotations
import argparse,base64,json,os,stat
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from tools.trusted_github_effect import TrustedGitHubEffect
from tools.github_rpc_adapter import GitHubRpcAdapter
from tools.trusted_generic_rpc import serve

class WorkerConfigurationDenied(RuntimeError): pass

CONFIG_FIELDS={"version","adapter_id","socket_path","journal_dir","policy",
               "worker_key_file","github_token_file","eg_key_file",
               "hitl_public_key_b64","capability_sha256","eg_url",
               "controller_uid","controller_group_gid"}

def _private_file(path,*,limit=8192):
    p=Path(path)
    if not p.is_absolute() or p.is_symlink():
        raise WorkerConfigurationDenied("ABSOLUTE_REGULAR_PRIVATE_FILE_REQUIRED")
    metadata=p.stat(follow_symlinks=False)
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid!=os.getuid()
        or stat.S_IMODE(metadata.st_mode)&0o077 or metadata.st_size>limit
        or metadata.st_size<=0):
        raise WorkerConfigurationDenied("UNSAFE_PRIVATE_WORKER_FILE")
    with p.open("rb") as handle:
        return handle.read(limit+1)

def load_worker(config_path):
    if os.getuid()==0:
        raise WorkerConfigurationDenied("INDEPENDENT_NONROOT_WORKER_REQUIRED")
    try:
        config=json.loads(_private_file(config_path).decode("utf-8"))
        if not isinstance(config,dict) or set(config)!=CONFIG_FIELDS or config["version"]!=1:
            raise WorkerConfigurationDenied("INVALID_OPERATOR_CONFIG")
        private_key_bytes=_private_file(config["worker_key_file"],limit=64)
        if len(private_key_bytes)!=32:
            raise WorkerConfigurationDenied("INVALID_WORKER_ED25519_KEY")
        private=Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        token=_private_file(config["github_token_file"],limit=4096).decode().strip()
        eg_key=_private_file(config["eg_key_file"],limit=4096).decode().strip()
        if (not token or not eg_key or "\n" in token or "\r" in token
            or "\n" in eg_key or "\r" in eg_key):
            raise WorkerConfigurationDenied("INVALID_OPERATOR_SECRET")
        if type(config["controller_uid"]) is not int or config["controller_uid"]<=0:
            raise WorkerConfigurationDenied("INVALID_SEPARATE_CONTROLLER_UID")
        group=config["controller_group_gid"]
        if group is not None and (type(group) is not int or group<=0):
            raise WorkerConfigurationDenied("INVALID_CONTROLLER_GROUP")
        worker=TrustedGitHubEffect(
            journal_dir=config["journal_dir"],private_key=private,
            adapter_id=config["adapter_id"],
            hitl_public_key_b64=config["hitl_public_key_b64"],
            policy=config["policy"],github_token=token)
        public=base64.b64encode(private.public_key().public_bytes(
               Encoding.Raw,PublicFormat.Raw)).decode()
        return {"adapter":GitHubRpcAdapter(worker),
                "socket_path":config["socket_path"],
                "capability_sha256":config["capability_sha256"],
                "eg_url":config["eg_url"],"eg_key":eg_key,
                "hitl_public_key_b64":config["hitl_public_key_b64"],
                "controller_uid":config["controller_uid"],
                "controller_group_gid":group,"worker_public_key_b64":public}
    except (OSError,ValueError,TypeError,KeyError) as exc:
        raise WorkerConfigurationDenied("OPERATOR_WORKER_CONFIG_DENIED") from exc

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operator-config",required=True)
    args=parser.parse_args(argv)
    settings=load_worker(args.operator_config)
    settings.pop("worker_public_key_b64")
    serve(**settings)
    return 0

if __name__=="__main__":
    raise SystemExit(main())
