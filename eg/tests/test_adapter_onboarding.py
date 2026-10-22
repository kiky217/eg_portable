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

def test_malformed_descriptor_types_fail_closed_without_crash():
    k=[key() for _ in range(4)]
    opts=dict(gateway_uid=10001,worker_uid=10002,notary_key=k[0],
              executor_key=k[1],hitl_key=k[2])
    for field,bad in (("adapter_id",None),("action_type",42),
                      ("target_prefix",None),("maximum_payload_bytes","1024"),
                      ("maximum_payload_bytes",True),("isolated","true"),
                      ("public_key_b64",42)):
        result=inspect_onboarding({**record(k[3]),field:bad},**opts)
        assert result["status"]=="INVALID_ADAPTER_DESCRIPTOR",field
        assert result["admission"] is False


def test_external_only_onboarding_does_not_require_unrelated_e2_executor():
    k=[key() for _ in range(3)]
    args=dict(gateway_uid=10001,worker_uid=10002,notary_key=k[0],hitl_key=k[1])
    result=inspect_onboarding(record(k[2]),**args)
    assert "THREE_INDEPENDENT_SIGNING_ROOTS" not in result["missing"]
    assert "FOUR_INDEPENDENT_SIGNING_ROOTS" not in result["missing"]
    assert "WORKER_RUNTIME_ATTESTATION" in result["missing"]
    for conflicting in [dict(notary_key=k[2]),dict(hitl_key=k[2]),dict(notary_key="")]:
        result=inspect_onboarding(record(k[2]),**{**args,**conflicting})
        assert "THREE_INDEPENDENT_SIGNING_ROOTS" in result["missing"]
        assert result["admission"] is False
    assert "FOUR_INDEPENDENT_SIGNING_ROOTS" in inspect_onboarding(
        record(k[2]),**args,executor_key=k[2])["missing"]


def test_malformed_optional_e2_root_is_not_treated_as_absent():
    k=[key() for _ in range(3)]
    for invalid in (0,False,[],{},42):
        result=inspect_onboarding(record(k[2]),gateway_uid=10001,worker_uid=10002,
            notary_key=k[0],hitl_key=k[1],executor_key=invalid)
        assert "FOUR_INDEPENDENT_SIGNING_ROOTS" in result["missing"]
