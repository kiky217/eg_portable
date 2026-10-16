"""Issue #21: historical evidence survives root rotation but retired roots cannot mint new evidence."""
import base64
import json
import time
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat

from harness import gw,PRIV,PUB,evp,step_ref,sb,eid

def pub(key):
    return base64.b64encode(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()

def test_retired_notary_evidence_before_cutoff_is_still_valid(monkeypatch):
    task=eid("rotated");source=step_ref(task,"PRE_EXECUTION",0)
    record=gw.Evidence(**evp(source))
    binding=gw.step_identity(task,"01.01",0,"child criterion","PRE_EXECUTION",0)
    fresh=pub(Ed25519PrivateKey.generate())
    monkeypatch.setattr(gw,"NOTARY_PUBLIC_KEY_B64",fresh)
    monkeypatch.setattr(gw,"LEGACY_NOTARY_KEYS_JSON",json.dumps([
        {"public_b64":PUB,"valid_before":time.time()+60}]))
    assert gw.verify_evidence(record,binding).ok

def test_retired_notary_cannot_authorize_after_cutoff(monkeypatch):
    task=eid("rotated-denial");source=step_ref(task,"PRE_EXECUTION",0)
    record=gw.Evidence(**evp(source))
    identity=gw.step_identity(task,"01.01",0,"child criterion","PRE_EXECUTION",0)
    monkeypatch.setattr(gw,"NOTARY_PUBLIC_KEY_B64",pub(Ed25519PrivateKey.generate()))
    monkeypatch.setattr(gw,"LEGACY_NOTARY_KEYS_JSON",json.dumps([
        {"public_b64":PUB,"valid_before":time.time()-1}]))
    result=gw.verify_evidence(record,identity)
    assert not result.ok and "invalid notary signature" in result.note

def test_invalid_rotation_configuration_rejected(monkeypatch):
    monkeypatch.setattr(gw,"LEGACY_NOTARY_KEYS_JSON",json.dumps([
        {"public_b64":PUB,"valid_before":float("inf")}]))
    with pytest.raises(RuntimeError,match="INVALID_LEGACY"):
        gw.legacy_notary_keys()
