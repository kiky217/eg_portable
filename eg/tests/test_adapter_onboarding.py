"""No self-declared adapter can complete operator admission."""
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from tools.adapter_onboarding import inspect_onboarding

def key():
    return base64.b64encode(Ed25519PrivateKey.generate().public_key().public_bytes(
        Encoding.Raw,PublicFormat.Raw)).decode()

def record(public):
    return {"adapter_id":"trusted-adapter-generic","action_type":"operate",
            "effect_class":"E3","target_prefix":"/scope/",
            "maximum_payload_bytes":1024,"isolated":True,
            "public_key_b64":public,"ci_only":False}

def test_configured_descriptor_never_proves_live_onboarding():
    k=[key() for _ in range(4)]
    result=inspect_onboarding(record(k[3]),gateway_uid=10001,worker_uid=10002,
        notary_key=k[0],executor_key=k[1],hitl_key=k[2])
    assert result["status"]=="OPERATOR_PROVISIONING_REQUIRED"
    assert not result["admission"]
    assert "WORKER_RUNTIME_ATTESTATION" in result["missing"]
    assert "CANONICAL_PRE_AND_POST" in result["missing"]

def test_shared_uid_or_signer_never_passes():
    k=[key() for _ in range(4)]
    result=inspect_onboarding(record(k[3]),gateway_uid=10001,worker_uid=10001,
        notary_key=k[0],executor_key=k[0],hitl_key=k[2])
    assert "INDEPENDENT_WORKER_UID" in result["missing"]
    assert "FOUR_INDEPENDENT_SIGNING_ROOTS" in result["missing"]

def test_malformed_and_ci_only_fail_closed():
    k=[key() for _ in range(4)]
    base=dict(gateway_uid=10001,worker_uid=10002,notary_key=k[0],
              executor_key=k[1],hitl_key=k[2])
    assert inspect_onboarding({"adapter_id":"oops"},**base)["status"]=="INVALID_ADAPTER_DESCRIPTOR"
    result=inspect_onboarding({**record(k[3]),"ci_only":True},**base)
    assert "CI_FIXTURE_NOT_PRODUCTION" in result["missing"]
