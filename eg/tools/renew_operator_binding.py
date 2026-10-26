"""Reissue an existing scoped operator binding without changing its authority.

Maintenance only. Requires the original protected operator key and old binding;
never generates authority, approves an effect or issues canonical PRE.
"""
from __future__ import annotations
import argparse,base64,json,os,secrets,stat,time
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_pem_private_key,Encoding,PublicFormat
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from tools.operator_adapter_binding import canonical
from tools.operator_runtime_registry import OperatorAdapterRegistry

class RenewalDenied(RuntimeError):pass


def _private_file(path):
    path=Path(path)
    info=path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid()
        or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)&0o077
        or path.is_symlink()):raise RenewalDenied('PRIVATE_OPERATOR_FILE_REQUIRED')
    return path.read_bytes()


def renew(*,binding_path,operator_key_path,registry_dir,operator_public_key_b64,
          ttl_seconds=3600,now=None):
    if type(ttl_seconds) is not int or not 60<=ttl_seconds<=86400:
        raise RenewalDenied('INVALID_BINDING_TTL')
    instant=int(time.time() if now is None else now)
    original=json.loads(_private_file(binding_path))
    if (not isinstance(original,dict) or 'signature_b64' not in original):
        raise RenewalDenied('INVALID_PRIOR_BINDING')
    old_body={k:v for k,v in original.items() if k!='signature_b64'}
    secret=load_pem_private_key(_private_file(operator_key_path),password=None)
    if not isinstance(secret,Ed25519PrivateKey):raise RenewalDenied('INVALID_OPERATOR_KEY')
    pub=base64.b64encode(secret.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
    if pub!=operator_public_key_b64:raise RenewalDenied('OPERATOR_ROOT_MISMATCH')
    try:
        sig=base64.b64decode(original['signature_b64'],validate=True)
        secret.public_key().verify(sig,canonical(old_body))
    except Exception as exc:raise RenewalDenied('UNTRUSTED_PREVIOUS_BINDING') from exc
    if (type(original.get('issued_at')) is not int or instant<=original['issued_at']
        or type(original.get('expires_at')) is not int or
        not 1<=original['expires_at']-original['issued_at']<=86400):
        raise RenewalDenied('INVALID_PREVIOUS_BINDING_SCOPE')
    # The exact same adapter, capability, socket, peer UID and worker key stay pinned.
    new={**old_body,'issued_at':instant,'expires_at':instant+ttl_seconds,
         'operator_nonce':secrets.token_urlsafe(24)}
    signed={**new,'signature_b64':base64.b64encode(secret.sign(canonical(new))).decode()}
    registry=OperatorAdapterRegistry(registry_dir,operator_public_key_b64)
    path=Path(binding_path)
    temp=path.with_name(path.name+'.pending')
    # Stage a durable signed recovery artifact BEFORE activating the new lease.
    # A crash after registry commit will leave the pending binding inspectable.
    with temp.open('x') as out:
        out.write(json.dumps(signed,sort_keys=True,separators=(',',':'))+'\n')
        out.flush();os.fsync(out.fileno())
    temp.chmod(0o600)
    # Activate performs fresh worker signature/peer-UID attestation and refuses revocation.
    activated=False
    try:
        status=registry.activate(signed,adapter_id=new['adapter_id'],
                                 capability_sha256=new['capability_sha256'])
        activated=True
        os.replace(temp,path)
    except Exception:
        if not activated:
            temp.unlink(missing_ok=True)
        # Once activation succeeds, preserve a pending file on rename failure.
        raise
    return {'status':status['status'],'adapter_id':new['adapter_id'],
            'binding_expires_at':new['expires_at'], 'authority_expanded':False,
            'execution_approved':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binding',type=Path,required=True)
    parser.add_argument('--operator-key',type=Path,required=True)
    parser.add_argument('--registry',type=Path,required=True)
    parser.add_argument('--operator-public-key',required=True)
    parser.add_argument('--ttl-seconds',type=int,default=3600)
    args=parser.parse_args()
    print(json.dumps(renew(binding_path=args.binding,operator_key_path=args.operator_key,
                           registry_dir=args.registry,operator_public_key_b64=args.operator_public_key,
                           ttl_seconds=args.ttl_seconds),sort_keys=True))

if __name__=='__main__':main()
