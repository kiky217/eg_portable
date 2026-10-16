"""Separate-UID notary signing, denied EG identity, and public-key verification."""
import base64
import json
import time
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import shutil

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
    # Use the actual manifest-v4 notary under its distinct identity.
    evidence = shared / "evidence-task"
    evidence.mkdir(mode=0o755)
    os.chown(evidence, NOTARY_UID, NOTARY_UID)
    state = {"task_id": evidence.name, "status": "PASS", "exit_code": 0,
             "finished_at": time.time()}
    (evidence / "state.json").write_text(json.dumps(state))
    (evidence / "stdout.log").write_text("readiness verified")
    binding = {"kind": "step_criterion", "eg_task_id": "demo-task",
               "step_key": "01.01", "criterion_index": 0, "criterion": "ready",
               "phase": "PRE_EXECUTION", "checkpoint_no": 0,
               "matcher": {"kind": "contains", "value": "readiness verified"}}
    bindings = shared / "bindings.json"
    bindings.write_text(json.dumps([binding]))
    for item in (bindings, evidence / "state.json", evidence / "stdout.log"):
        item.chmod(0o644)
        if item.parent == evidence:
            os.chown(item, NOTARY_UID, NOTARY_UID)
    notarizer = shared / "notarize_evidence.py"
    shutil.copyfile(Path(__file__).resolve().parents[1] / "tools" / "notarize_evidence.py", notarizer)
    notarizer.chmod(0o644)
    signed = subprocess.run([sys.executable, str(notarizer), str(pem),
                             str(evidence), str(bindings)],
                            preexec_fn=lambda: (os.setgroups([]), os.setgid(NOTARY_UID),
                                                os.setuid(NOTARY_UID)),
                            capture_output=True, timeout=15)
    assert signed.returncode == 0, signed.stderr
    manifest = json.loads((evidence / "evidence.json").read_text())
    signature = base64.b64decode(manifest.pop("notary_ed25519_signature_b64"))
    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode()
    key.public_key().verify(signature, payload)
    assert manifest["bindings"] == [binding]
    assert manifest["stdout_sha256"] == hashlib.sha256(b"readiness verified").hexdigest()

    # Verify the same independent signer through the actual gateway verifier.
    from harness import gw
    from unittest.mock import patch
    pub = base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    with patch.object(gw, "EVIDENCE_ROOT", shared), patch.object(gw, "TRUSTED_UID", NOTARY_UID), patch.object(gw, "NOTARY_PUBLIC_KEY_B64", pub):
        accepted = gw.verify_evidence(gw.Evidence(source_type="knid_task", reference=evidence.name),
                                      {k: v for k, v in binding.items() if k != "matcher"})
        assert accepted.ok, accepted.note
        forged = dict(binding)
        forged["criterion"] = "not approved"
        rejected = gw.verify_evidence(gw.Evidence(source_type="knid_task", reference=evidence.name),
                                      {k: v for k, v in forged.items() if k != "matcher"})
        assert not rejected.ok


