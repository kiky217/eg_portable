"""Host identity must not reject otherwise valid generic E3-E5 configuration."""
import json
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
import harness as H
from tools.operator_runtime_registry import OperatorAdapterRegistry

def key():
    return __import__('base64').b64encode(Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()

@pytest.mark.parametrize('host_uid',(0,1000))
@pytest.mark.parametrize('effect',('E3','E4','E5'))
def test_signed_generic_external_gateway_accepts_host_identity(monkeypatch,tmp_path,host_uid,effect):
    gw=H.gw
    registry=tmp_path/'registry'
    registry.mkdir(mode=0o700)
    operator=key()
    OperatorAdapterRegistry(registry,operator)
    signer=key()
    worker=key()
    adapter='trusted-adapter-generic-'+effect.lower()
    cap={'adapter_id':adapter,'action_type':'bounded_process_run',
         'effect_class':effect,'target_prefix':'/tasks/generic/',
         'maximum_payload_bytes':4096,'isolated':True,'public_key_b64':worker,
         'version':1,'ci_only':False}
    monkeypatch.setattr(gw,'ADMISSION_MODE','enabled')
    monkeypatch.setattr(gw,'EXTERNAL_ADAPTER_MODE','enabled')
    monkeypatch.setattr(gw,'EXTERNAL_REGISTRY_DIR',str(registry))
    monkeypatch.setattr(gw,'EXTERNAL_REGISTRY_KEY',operator)
    monkeypatch.setattr(gw,'EXTERNAL_ADAPTER_SOCKET','')
    monkeypatch.setattr(gw,'EXTERNAL_ADAPTER_UID',-1)
    monkeypatch.setattr(gw,'HIGH_EFFECT_CI_FIXTURE_ENABLED',False)
    monkeypatch.setattr(gw,'HIGH_EFFECT_CAPABILITIES_JSON',json.dumps([cap]))
    monkeypatch.setattr(gw,'HITL_PUBLIC_KEY_B64',signer)
    monkeypatch.setattr(gw.os,'geteuid',lambda:host_uid)
    gw.require_config()
