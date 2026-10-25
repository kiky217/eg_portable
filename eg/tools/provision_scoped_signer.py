"""One-time operator installer for independently owned generic E3 scoped-approval service.

Requires a root operator and pre-existing signer/agent OS IDs; never runs as the
agent. Creates keys and policy atomically in a new trusted private directory.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import stat
import time
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption,PublicFormat


def provision(path, *, signer_uid, signer_gid, agent_uid, agent_gid,
              adapter_id, target_prefix, seconds=3600, max_grants=50,
              max_payload_bytes=8192):
    if os.geteuid()!=0:
        raise ValueError('ROOT_OPERATOR_REQUIRED')
    if (not all(type(x) is int and x>0 for x in (signer_uid,signer_gid,agent_uid,agent_gid))
        or signer_uid==agent_uid or not isinstance(adapter_id,str)
        or not adapter_id.startswith('trusted-adapter-') or not isinstance(target_prefix,str)
        or not target_prefix.startswith('/tasks/') or '..' in target_prefix.split('/')
        or type(seconds) is not int or not 30<=seconds<=86400
        or type(max_grants) is not int or not 1<=max_grants<=100
        or type(max_payload_bytes) is not int or not 1<=max_payload_bytes<=524288):
        raise ValueError('INVALID_OPERATOR_SCOPE')
    root=Path(path)
    parent=root.parent
    ps=parent.lstat()
    if (not root.is_absolute() or not stat.S_ISDIR(ps.st_mode) or ps.st_uid!=0
        or stat.S_IMODE(ps.st_mode)&0o022 or root.exists() or root.is_symlink()):
        raise ValueError('TRUSTED_NEW_OPERATOR_ROOT_REQUIRED')
    root.mkdir(mode=0o700)
    os.chown(root,signer_uid,agent_gid)
    root.chmod(0o710)  # Exact controller group may traverse, never read signer files.
    secret=Ed25519PrivateKey.generate()
    key=root/'signer.pem'
    raw=secret.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption())
    # Exclusive file creation, private before any content is written.
    fd=os.open(key,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())
    os.chown(key,signer_uid,signer_gid)
    ledger=root/'ledger';ledger.mkdir(mode=0o700)
    os.chown(ledger,signer_uid,signer_gid)
    socket_dir=root/'socket';socket_dir.mkdir(mode=0o700)
    os.chown(socket_dir,signer_uid,agent_gid)
    socket_dir.chmod(0o2710)
    conf=root/'config.json'
    doc={'key_file':str(key),'ledger_dir':str(ledger),
         'socket_path':str(socket_dir/'approve.sock'),
         'controller_uid':agent_uid,'controller_group_gid':agent_gid,
         'adapter_id':adapter_id,'target_prefix':target_prefix,
         'expires_at':int(time.time())+seconds,'max_grants':max_grants,
         'max_payload_bytes':max_payload_bytes}
    fd=os.open(conf,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as stream:
        json.dump(doc,stream,sort_keys=True);stream.write('\n')
        stream.flush();os.fsync(stream.fileno())
    os.chown(conf,signer_uid,signer_gid)
    public=base64.b64encode(secret.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
    return {'config':str(conf),'socket':doc['socket_path'],
            'signer_public_key_b64':public,
            'start_command':['python','-m','tools.operator_scoped_approval',str(conf)]}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,required=True)
    for field in ('signer-uid','signer-gid','agent-uid','agent-gid'):
        p.add_argument('--'+field,type=int,required=True)
    p.add_argument('--adapter-id',required=True)
    p.add_argument('--target-prefix',required=True)
    p.add_argument('--seconds',type=int,default=3600)
    p.add_argument('--max-grants',type=int,default=50)
    args=p.parse_args()
    result=provision(args.root,signer_uid=args.signer_uid,signer_gid=args.signer_gid,
        agent_uid=args.agent_uid,agent_gid=args.agent_gid,adapter_id=args.adapter_id,
        target_prefix=args.target_prefix,seconds=args.seconds,max_grants=args.max_grants)
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':
    main()
