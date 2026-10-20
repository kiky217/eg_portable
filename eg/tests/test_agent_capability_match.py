"""Issue #61: matching typed capability never elevates an untrusted agent."""
import base64
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from harness import CLIENT, HEAD, gw

URL="/v1/agent/capability-match"

def test_match_requires_authentication():
    assert CLIENT.get(URL,params={"effect_class":"E3","action_type":"operate","target":"/scope/a"}).status_code==401

def test_match_respects_type_scope_and_admission(monkeypatch):
    key=Ed25519PrivateKey.generate()
    public=base64.b64encode(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
    record={"adapter_id":"trusted-adapter-test","action_type":"operate",
            "effect_class":"E3","target_prefix":"/scope/",
            "maximum_payload_bytes":4096,"isolated":True,
            "public_key_b64":public,"version":1,"ci_only":False}
    monkeypatch.setattr(gw,"HIGH_EFFECT_CAPABILITIES_JSON",json.dumps([record]))
    monkeypatch.setattr(gw,"EXTERNAL_ADAPTER_MODE","enabled")
    params={"effect_class":"E3","action_type":"operate","target":"/scope/work"}
    matched=CLIENT.get(URL,params=params,headers=HEAD).json()
    assert matched["status"]=="MATCHED_PRE_REQUIRED"
    assert not matched["admission"]
    assert matched["candidates"][0]["status"]=="LIVE_PRE_ATTESTATION_REQUIRED"
    denied=CLIENT.get(URL,params={**params,"target":"/scope-evil/work"},headers=HEAD).json()
    assert denied["status"]=="CAPABILITY_UNPROVISIONED"
    assert denied["next_action"]=="ONBOARD_INDEPENDENT_TRUSTED_ADAPTER"
    monkeypatch.setattr(gw,"ADMISSION_MODE","disabled")
    disabled=CLIENT.get(URL,params=params,headers=HEAD).json()
    assert disabled["status"]=="ADMISSION_DISABLED"
    assert not disabled["candidates"]

def test_bad_query_rejected():
    response=CLIENT.get(URL,params={"effect_class":"E9","action_type":"operate","target":"/a"},headers=HEAD)
    assert response.status_code==422
