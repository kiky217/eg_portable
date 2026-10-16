"""Externally signed cutover report/rollback archive + real isolated restore rehearsal.

Verifier is read-only and does not create an authorization to perform cutover.
The trust root MUST be supplied independently, never read from the report.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import tarfile
import tempfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()

def _digest(path):
    h=hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()

def rehearse_restore(archive_path):
    """Restore every regular archived file into a private disposable directory."""
    output=[]
    with tempfile.TemporaryDirectory(prefix="eg-rollback-rehearsal-") as root:
        base=Path(root)
        seen=set()
        with tarfile.open(archive_path,"r:*") as archive:
            members=archive.getmembers()
            if not members:raise ValueError("EMPTY_ROLLBACK_ARCHIVE")
            for member in members:
                name=Path(member.name)
                if (name.is_absolute() or ".." in name.parts or
                    not (member.isdir() or member.isfile())):
                    raise ValueError("UNSAFE_ROLLBACK_MEMBER")
                clean=name.as_posix().strip("/")
                if not clean or clean in seen:raise ValueError("DUPLICATE_OR_EMPTY_ARCHIVE_MEMBER")
                seen.add(clean)
                target=base.joinpath(*name.parts)
                if member.isdir():
                    target.mkdir(parents=True,exist_ok=True)
                    continue
                if member.size<0 or member.size>1024*1024*1024:
                    raise ValueError("ROLLBACK_MEMBER_OVERSIZE")
                target.parent.mkdir(parents=True,exist_ok=True)
                src=archive.extractfile(member)
                if src is None:raise ValueError("ROLLBACK_MEMBER_UNREADABLE")
                h=hashlib.sha256();count=0
                with target.open("xb") as dest:
                    for chunk in iter(lambda:src.read(1024*1024),b""):
                        count+=len(chunk)
                        if count>member.size:raise ValueError("ROLLBACK_MEMBER_LENGTH_MISMATCH")
                        h.update(chunk);dest.write(chunk)
                    dest.flush();os.fsync(dest.fileno())
                if count!=member.size or _digest(target)!=h.hexdigest():
                    raise ValueError("ROLLBACK_RESTORE_READBACK_MISMATCH")
                output.append({"path":clean,"sha256":h.hexdigest(),"size":count})
    return sorted(output,key=lambda x:x["path"])

def verify_independent_cutover(report_path, archive_path, attest_path, public_key_b64):
    if not public_key_b64 or not attest_path or not Path(attest_path).is_file():
        return False,"INDEPENDENT_CUTOVER_ATTESTATION_MISSING"
    try:
        obj=json.loads(Path(attest_path).read_text())
        expected={"version","report_sha256","archive_sha256","restore_files",
                  "checkpoint","audit_head","verification_scope","signature_b64"}
        if set(obj)!=expected:raise ValueError("ATTESTATION_SCHEMA_INVALID")
        payload={k:v for k,v in obj.items() if k!="signature_b64"}
        if (type(obj["version"]) is not int or obj["version"]!=1
            or obj["verification_scope"]!="INDEPENDENT_CUTOVER_AND_RESTORE"
            or obj["report_sha256"]!=_digest(report_path)
            or obj["archive_sha256"]!=_digest(archive_path)):
            raise ValueError("ATTESTATION_ARTIFACT_MISMATCH")
        report=json.loads(Path(report_path).read_text())
        if (obj["checkpoint"]!=report.get("checkpoint")
            or obj["audit_head"]!=report.get("audit_head")):
            raise ValueError("ATTESTATION_CANONICAL_STATE_MISMATCH")
        raw=base64.b64decode(public_key_b64,validate=True)
        sig=base64.b64decode(obj["signature_b64"],validate=True)
        if len(raw)!=32 or len(sig)!=64:raise ValueError("ATTESTATION_SIGNATURE_FORMAT")
        Ed25519PublicKey.from_public_bytes(raw).verify(sig,_canonical(payload))
        actual=rehearse_restore(archive_path)
        if actual!=obj["restore_files"]:
            raise ValueError("ROLLBACK_RESTORE_REHEARSAL_MISMATCH")
        return True,"INDEPENDENT_CUTOVER_AND_RESTORE_ATTESTED"
    except Exception as exc:
        return False,"CUTOVER_ATTESTATION_INVALID:"+type(exc).__name__
