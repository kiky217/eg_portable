"""Production mode admission remains opt-in and requires a distinct live worker."""
import base64,json
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
import harness as H
import app.main as gw
from tools.high_effect_admission import AdapterCapability,AdmissionDenied
def pub():
 k=Ed25519PrivateKey.generate()
 return base64.b64encode(k.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
def action():
 return gw.Action(action_type="cargo_test",target="/content/workspace/knid-solana/Cargo.toml",
                  effect_class="E3",reversible=True,real_world_effect=True,
                  payload_sha256="0"*64,payload_bytes=10)
def desc():
 return {"adapter_id":"trusted-adapter-solana-cargo","action_type":"cargo_test","effect_class":"E3",
         "target_prefix":"/content/workspace/knid-solana","maximum_payload_bytes":4096,
         "isolated":True,"public_key_b64":pub(),"ci_only":False}
def test_production_flag_alone_insufficient(monkeypatch):
 monkeypatch.setattr(gw,"EXTERNAL_ADAPTER_MODE","enabled")
 monkeypatch.setattr(gw,"HIGH_EFFECT_REQUIRE_RPC_LIVENESS",True)
 monkeypatch.setattr(gw,"EXTERNAL_ADAPTER_SOCKET","")
 monkeypatch.setattr(gw,"EXTERNAL_ADAPTER_UID",None)
 monkeypatch.setattr(gw,"HIGH_EFFECT_CAPABILITIES_JSON",json.dumps([desc()]))
 # Catalog discovery is not executor readiness; admission additionally checks
 # the socket, peer UID, signed HITL and independent liveness at PRE.
 assert gw.high_effect_capability(action()) is not None
def test_cannot_admit_ci_capability_as_production(monkeypatch):
 a=desc();a["ci_only"]=True
 monkeypatch.setattr(gw,"HIGH_EFFECT_CI_FIXTURE_ENABLED",False)
 monkeypatch.setattr(gw,"EXTERNAL_ADAPTER_MODE","enabled")
 monkeypatch.setattr(gw,"HIGH_EFFECT_REQUIRE_RPC_LIVENESS",True)
 monkeypatch.setattr(gw,"EXTERNAL_ADAPTER_SOCKET","/nonexistent/adapter.sock")
 monkeypatch.setattr(gw,"EXTERNAL_ADAPTER_UID",65534)
 monkeypatch.setattr(gw,"HIGH_EFFECT_CAPABILITIES_JSON",json.dumps([a]))
 assert gw.high_effect_capability(action()) is None
def test_production_capability_requires_explicit_validate():
 with pytest.raises(AdmissionDenied):
  AdapterCapability(**desc()).validate()
 AdapterCapability(**desc()).validate(allow_external=True)
