"""Two unrelated E3/E4 adapters reuse operator-signed identities in canonical PRE."""
import base64
import hashlib
import json
import os
import time
from dataclasses import asdict

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from tools.operator_adapter_binding import canonical
from tools.operator_runtime_registry import OperatorAdapterRegistry
from tools.high_effect_admission import AdapterCapability,AdmissionDenied
from test_high_effect_gateway_integration import (
    gw,H,register_high_effect,high_pre_ref,high_pre_claim,signed,pub,
)

def binding(operator,worker,cap,uid,now):
    doc={"version":1,"adapter_id":cap.adapter_id,
        "capability_sha256":hashlib.sha256(canonical(asdict(cap))).hexdigest(),
        "worker_uid":uid,"socket_path":"/run/"+cap.adapter_id+"/worker.sock",
        "worker_public_key_b64":pub(worker),"issued_at":now-1,
        "expires_at":now+120,"environment":"test",
        "operator_nonce":"signed-operator-"+cap.adapter_id}
    return {**doc,"signature_b64":base64.b64encode(operator.sign(canonical(doc))).decode()}

def test_two_independent_adapter_routes_reach_canonical_pre(monkeypatch,tmp_path):
    directory=tmp_path/"private";directory.mkdir(mode=0o700)
    operator,human=Ed25519PrivateKey.generate(),Ed25519PrivateKey.generate()
    workers=[Ed25519PrivateKey.generate(),Ed25519PrivateKey.generate()]
    caps=[AdapterCapability(adapter_id="trusted-adapter-example-e3",
         action_type="sandbox_cutover",effect_class="E3",target_prefix="/tmp/eg-high/",
         maximum_payload_bytes=1024,isolated=True,public_key_b64=pub(workers[0]),ci_only=False),
          AdapterCapability(adapter_id="trusted-adapter-example-e4",
         action_type="sandbox_critical_update",effect_class="E4",target_prefix="/tmp/eg-high/",
         maximum_payload_bytes=1024,isolated=True,public_key_b64=pub(workers[1]),ci_only=False)]
    now=int(time.time())
    uids=[os.getuid()+1021,os.getuid()+1022]
    activated=[]
    monkeypatch.setattr("tools.operator_runtime_registry.probe_unix",
                        lambda socket_path,**k: activated.append((socket_path,k["expected_worker_uid"])))
    reg=OperatorAdapterRegistry(directory,pub(operator))
    for cap,worker,uid in zip(caps,workers,uids):
        signed_binding=binding(operator,worker,cap,uid,now)
        assert reg.activate(signed_binding,adapter_id=cap.adapter_id,
                            capability_sha256=signed_binding["capability_sha256"])["admission"] is False
    monkeypatch.setattr(gw,"HIGH_EFFECT_CI_FIXTURE_ENABLED",False)
    monkeypatch.setattr(gw,"HIGH_EFFECT_CAPABILITIES_JSON",
                        json.dumps([asdict(c) for c in caps]))
    monkeypatch.setattr(gw,"EXTERNAL_ADAPTER_MODE","enabled")
    monkeypatch.setattr(gw,"EXTERNAL_REGISTRY_DIR",str(directory))
    monkeypatch.setattr(gw,"EXTERNAL_REGISTRY_KEY",pub(operator))
    monkeypatch.setattr(gw,"EXTERNAL_ADAPTER_SOCKET","")
    monkeypatch.setattr(gw,"EXTERNAL_ADAPTER_UID",-1)
    monkeypatch.setattr(gw,"HITL_PUBLIC_KEY_B64",pub(human))
    probes=[]
    monkeypatch.setattr(gw,"probe_unix",
                        lambda socket_path,**k: probes.append((socket_path,k["expected_worker_uid"],
                                                               k["public_key_b64"])))
    for cap,worker,uid in zip(caps,workers,uids):
        task,ch=register_high_effect()
        payload=b"{}"
        action={"action_type":cap.action_type,"effect_class":cap.effect_class,
                "target":"/tmp/eg-high/result.json","reversible":cap.effect_class!="E5",
                "real_world_effect":True,
                "payload_sha256":hashlib.sha256(payload).hexdigest(),
                "payload_bytes":len(payload),"proofs":[]}
        approval=signed(human,task,action,cap.adapter_id,1,time.time())
        pre=H.raw_eval(task,ch,0,claims=[high_pre_claim(high_pre_ref(task,0))],
                       action=action,hitl_approval=approval)
        assert pre.status_code==200,pre.text
        assert pre.json()["verdict"]=="READY_TO_EXECUTE",pre.text
        assert pre.json()["high_effect_pin"]["public_key_b64"]==pub(worker)
        assert probes[-1]==("/run/"+cap.adapter_id+"/worker.sock",uid,pub(worker))
    assert len(probes)==2
    assert len(activated)==2

    # A valid operator signature cannot silently change the canonical cap signer.
    wrong=AdapterCapability(**{**asdict(caps[0]),"public_key_b64":pub(workers[1])})
    with pytest.raises(AdmissionDenied,match="BINDING_INVALID_OR_EXPIRED"):
        gw.external_route(wrong)

def test_incomplete_registry_configuration_denied(monkeypatch):
    monkeypatch.setattr(gw,"EXTERNAL_ADAPTER_MODE","enabled")
    monkeypatch.setattr(gw,"EXTERNAL_REGISTRY_DIR","/tmp/not-operator-controlled")
    monkeypatch.setattr(gw,"EXTERNAL_REGISTRY_KEY","")
    with pytest.raises(RuntimeError,match="UNSAFE_EXTERNAL_EXECUTOR_BOUNDARY"):
        gw.require_config()
