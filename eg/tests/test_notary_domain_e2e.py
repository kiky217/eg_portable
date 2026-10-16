"""Separate-UID notary signing, denied EG identity, and public-key verification."""
import base64
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

EG_UID = 65532
NOTARY_UID = 65533


@pytest.mark.skipif(os.geteuid() != 0, reason="requires disposable CI root to switch UIDs")
def test_private_notary_key_unreadable_to_gateway_identity(tmp_path):
    # pytest parent directories are mode 0700; use a disposable traversable root.
    shared = Path(tempfile.mkdtemp(prefix="eg-notary-domain-", dir="/tmp"))
    shared.chmod(0o755)
    private_dir = shared / "independent-notary"
    private_dir.mkdir(mode=0o700)
    os.chown(private_dir, NOTARY_UID, NOTARY_UID)
    key = Ed25519PrivateKey.generate()
    pem = private_dir / "key.pem"
    pem.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    os.chown(pem, NOTARY_UID, NOTARY_UID)
    pem.chmod(0o600)
    assert not (shared / 'key.pem').exists()

    script = """import sys
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_pem_private_key
key = load_pem_private_key(Path(sys.argv[1]).read_bytes(), password=None)
sys.stdout.buffer.write(key.sign(b'EG separate-UID domain test'))
"""
    def run(uid):
        def identity():
            os.setgroups([])
            os.setgid(uid)
            os.setuid(uid)
        return subprocess.run([sys.executable, "-c", script, str(pem)],
                              preexec_fn=identity, capture_output=True, timeout=15)
    denied = run(EG_UID)
    assert denied.returncode != 0
    assert b"PermissionError" in denied.stderr
    authorized = run(NOTARY_UID)
    assert authorized.returncode == 0, authorized.stderr
    key.public_key().verify(authorized.stdout, b"EG separate-UID domain test")
