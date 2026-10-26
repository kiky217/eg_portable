"""Per-typed-adapter independent E3/E4/E5 standing-approval trust roots."""
import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app import main as gateway
from tools.high_effect_admission import AdapterCapability


def public_key():
    key=Ed25519PrivateKey.generate()
    return base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def capability(effect):
    return AdapterCapability(
        adapter_id="trusted-adapter-"+effect.lower(), effect_class=effect,
        action_type="bounded_process_run", target_prefix="/tasks/eg-samples/",
        maximum_payload_bytes=4096, isolated=True, public_key_b64=public_key(),
        ci_only=False)


def test_distinct_signer_roots_match_e3_e4_e5_without_provider_branches(monkeypatch):
    adapters=[capability(effect) for effect in ("E3","E4","E5")]
    keys={adapter.adapter_id:public_key() for adapter in adapters}
    monkeypatch.setattr(gateway,"HIGH_EFFECT_HITL_KEYS_JSON",json.dumps(keys))
    monkeypatch.setattr(gateway,"HITL_PUBLIC_KEY_B64","")
    assert gateway.high_effect_hitl_keys(strict=True)==keys
    for adapter in adapters:
        assert gateway.hitl_key_for(adapter)==keys[adapter.adapter_id]
        assert gateway.hitl_key_for(adapter)!=adapter.public_key_b64


@pytest.mark.parametrize("bad",[
    "{}",
    '["not-an-adapter-map"]',
    '{"trusted-adapter-e3":"invalid"}',
    '{"not-trusted-adapter":"invalid"}',
])
def test_invalid_map_fails_closed_at_startup(monkeypatch,bad):
    monkeypatch.setattr(gateway,"HIGH_EFFECT_HITL_KEYS_JSON",bad)
    with pytest.raises(RuntimeError,match="INVALID_HIGH_EFFECT_HITL_MAP"):
        gateway.high_effect_hitl_keys(strict=True)


def test_reused_key_across_two_high_effect_classes_denied(monkeypatch):
    signing=public_key()
    monkeypatch.setattr(gateway,"HIGH_EFFECT_HITL_KEYS_JSON",json.dumps({
        "trusted-adapter-e3":signing,"trusted-adapter-e5":signing}))
    with pytest.raises(RuntimeError,match="INVALID_HIGH_EFFECT_HITL_MAP"):
        gateway.high_effect_hitl_keys(strict=True)
