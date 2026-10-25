"""Provision an independent, operator-pinned E3 worker and scoped staging signer.

Root-owned one-time install; never a tool that can be invoked by the AI agent.
The operator still chooses exact executable/arguments, UIDs, and capability scope.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
import secrets
import stat
import time
from dataclasses import asdict
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat
from tools.adapter_liveness import canon
from tools.high_effect_admission import AdapterCapability
from tools.operator_adapter_binding import canonical as binding_canon
from tools.operator_process_service import load_config
from tools.trusted_process_catalog import validate_profiles
from tools.provision_scoped_signer import provision as provision_signer


def _write(path, payload, uid, gid):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(payload)
        f.flush()
        os.fsync(f.fileno())
    os.chown(path, uid, gid)


def _private_pem(key):
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def _public(key):
    return base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def provision(policy):
    if os.geteuid() != 0:
        raise ValueError('TRUSTED_ROOT_INSTALLER_REQUIRED')
    required={'root','worker_uid','signer_uid','agent_uid','adapter_id','target_prefix',
              'target','executable','fixed_args','eg_url','gateway_key_file'}
    catalog_required=(required-{'target','executable','fixed_args'})|{'profiles'}
    if not isinstance(policy,dict) or set(policy) not in (required,catalog_required):
        raise ValueError('INVALID_OPERATOR_POLICY')
    catalog_mode='profiles' in policy
    profiles=validate_profiles(policy['profiles']) if catalog_mode else ({
        'target':policy['target'], 'executable':policy['executable'],
        'fixed_args':tuple(policy['fixed_args'])},)
    worker,signer,agent=(policy[x] for x in ('worker_uid','signer_uid','agent_uid'))
    if (any(type(x) is not int or x<=0 for x in (worker,signer,agent))
        or len({worker,signer,agent})!=3
        or not isinstance(policy['target_prefix'],str) or not policy['target_prefix'].startswith('/tasks/')
        or '..' in policy['target_prefix'].split('/') or any(
            not x['target'].startswith(policy['target_prefix'].rstrip('/')+'/')
            or '..' in x['target'].split('/') for x in profiles)
        or not policy['adapter_id'].startswith('trusted-adapter-')
        or not (policy['eg_url'].startswith('https://') or policy['eg_url'].startswith(('http://127.0.0.1:', 'http://localhost:')))):
        raise ValueError('OUT_OF_SCOPE_OPERATOR_POLICY')
    # All catalog entries are pinned before creating any privileged identity.
    for profile in profiles:
        executable=Path(profile['executable'])
        if not executable.is_absolute():
            raise ValueError('UNTRUSTED_OPERATOR_EXECUTABLE')
        binary=executable.lstat()
        if (not stat.S_ISREG(binary.st_mode) or binary.st_uid not in (0,worker)
            or binary.st_mode & 0o022 or not binary.st_mode & 0o111):
            raise ValueError('UNTRUSTED_OPERATOR_EXECUTABLE')
        for ancestor in executable.parents:
            info=ancestor.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0,worker)
                or info.st_mode & 0o022):
                raise ValueError('UNTRUSTED_EXECUTABLE_PATH')
    original=Path(policy['gateway_key_file']);src=os.open(original,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        info=os.fstat(src)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or
            stat.S_IMODE(info.st_mode)&0o077 or info.st_nlink!=1):
            raise ValueError('ROOT_ONLY_GATEWAY_KEY_REQUIRED')
        token=os.read(src,513).strip()
        if not 1<=len(token)<=512:raise ValueError('INVALID_GATEWAY_CREDENTIAL')
    finally:os.close(src)
    root=Path(policy['root']);parent=root.parent
    parent_info=parent.lstat()
    if (not root.is_absolute() or not stat.S_ISDIR(parent_info.st_mode) or
        parent_info.st_uid!=0 or stat.S_IMODE(parent_info.st_mode)&0o022 or root.exists()):
        raise ValueError('TRUSTED_NEW_INSTALL_DIR_REQUIRED')
    root.mkdir(mode=0o755)
    os.chown(root,0,0)
    root.chmod(0o755)
    worker_dir=root/'worker';worker_dir.mkdir(mode=0o700);os.chown(worker_dir,worker,worker)
    journal=worker_dir/'journal';journal.mkdir(mode=0o700);os.chown(journal,worker,worker)
    socket_dir=root/'socket';socket_dir.mkdir(mode=0o700)
    os.chown(socket_dir,worker,agent);socket_dir.chmod(0o2710)
    operator_dir=root/'operator';operator_dir.mkdir(mode=0o700)
    registry=root/'registry';registry.mkdir(mode=0o700);os.chown(registry,agent,agent)
    signer_dir=root/'signer'
    signer_result=provision_signer(signer_dir,signer_uid=signer,signer_gid=signer,
        agent_uid=agent,agent_gid=agent,adapter_id=policy['adapter_id'],
        target_prefix=policy['target_prefix'],max_grants=50,seconds=3600)
    operator_key,worker_key=Ed25519PrivateKey.generate(),Ed25519PrivateKey.generate()
    _write(operator_dir/'operator.pem',_private_pem(operator_key),0,0)
    _write(worker_dir/'worker.pem',_private_pem(worker_key),worker,worker)
    _write(worker_dir/'gateway.key',token+b'\n',worker,worker)
    capability=AdapterCapability(adapter_id=policy['adapter_id'],effect_class='E3',
        action_type='bounded_process_run',target_prefix=policy['target_prefix'],
        maximum_payload_bytes=4096,isolated=True,public_key_b64=_public(worker_key),ci_only=False)
    capsha=hashlib.sha256(canon(asdict(capability))).hexdigest()
    worker_config={'adapter_id':policy['adapter_id'],'capability_sha256':capsha,
        'socket_path':str(socket_dir/'worker.sock'),'journal_dir':str(journal),
        'private_key_path':str(worker_dir/'worker.pem'),'eg_url':policy['eg_url'],
        'eg_api_key_path':str(worker_dir/'gateway.key'),
        'hitl_public_key_b64':signer_result['signer_public_key_b64'],
        'controller_uid':agent,'controller_group_gid':agent}
    if catalog_mode:
        worker_config['profiles']=[dict(p, fixed_args=list(p['fixed_args'])) for p in profiles]
    else:
        worker_config.update(executable=policy['executable'],
                             fixed_args=policy['fixed_args'],target=policy['target'])
    _write(worker_dir/'config.json',canon(worker_config)+b'\n',worker,worker)
    now=int(time.time())
    binding={'version':1,'adapter_id':capability.adapter_id,'capability_sha256':capsha,
        'worker_uid':worker,'socket_path':str(socket_dir/'worker.sock'),
        'worker_public_key_b64':_public(worker_key), 'issued_at':now-1,
        'expires_at':now+3600,'environment':'staging',
        'operator_nonce':secrets.token_urlsafe(24)}
    binding['signature_b64']=base64.b64encode(operator_key.sign(binding_canon(binding))).decode()
    _write(registry/'binding.json',canon(binding)+b'\n',agent,agent)
    public={'adapter_id':capability.adapter_id,'capability_sha256':capsha,
        'operator_public_key_b64':_public(operator_key),
        'hitl_public_key_b64':signer_result['signer_public_key_b64'],
        'capability':asdict(capability), 'registry_dir':str(registry),
        'worker_config_path':str(worker_dir/'config.json'),
        'signer_config_path':signer_result['config'],
        'standing_approval_socket':signer_result['socket']}
    _write(registry/'public.json',canon(public)+b'\n',agent,agent)
    return public


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root_owned_policy_json',type=Path)
    args=parser.parse_args()
    fd=os.open(args.root_owned_policy_json,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        statinfo=os.fstat(fd)
        if statinfo.st_uid!=0 or stat.S_IMODE(statinfo.st_mode)&0o077:
            raise ValueError('ROOT_ONLY_OPERATOR_POLICY_REQUIRED')
        policy=json.loads(os.read(fd,65537))
    finally:os.close(fd)
    print(json.dumps(provision(policy),sort_keys=True))


if __name__=='__main__':main()
