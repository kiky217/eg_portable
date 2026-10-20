"""Live discovery must never authorize execution or reveal API credentials."""
import json
import pytest
from tools import agent_readiness as readiness


class _Response:
    def __init__(self, data):self.data=data
    def __enter__(self):return self
    def __exit__(self,*args):return False
    def read(self):return json.dumps(self.data).encode()


def test_authenticated_live_adapter_discovery(monkeypatch):
    reqs=[]
    def fake_open(request, timeout):
        reqs.append(request)
        return _Response({"admission_mode":"enabled","catalog_valid":True,
            "capabilities":[{"id":"registered.scanner","effect_class":"E3",
                "action_type":"scan","adapter_id":"trusted-adapter-scan",
                "status":"EXTERNAL_LIVE_PRE_ATTESTATION_REQUIRED"}]})
    monkeypatch.setattr(readiness,"urlopen",fake_open)
    report=readiness.diagnose_live("E3","scan",url="https://eg.example",api_key="hidden")
    assert report["registered_count"]==1
    assert report["preflight"]=="REQUIRES_LIVE_PRE" and report["live_verified"] is False
    assert reqs[0].get_header("X-evaluation-key")=="hidden"


@pytest.mark.parametrize("url",["http://attacker.invalid","file:///etc/passwd",
                                "https://u:p@example.com","http://127.0.0.2:8765"])
def test_untrusted_discovery_url_denied(monkeypatch,url):
    monkeypatch.setattr(readiness,"urlopen",lambda *_a,**_kw:pytest.fail("network"))
    with pytest.raises(ValueError,match="UNTRUSTED_EG_DISCOVERY_URL"):
        readiness.diagnose_live("E3","scan",url=url,api_key="hidden")


@pytest.mark.parametrize("catalog_valid,admission_mode,capabilities,reason",[
    (False,"enabled",[{"effect_class":"E3","action_type":"scan"}],"INVALID_LIVE_CAPABILITY_CATALOG"),
    (True,"disabled",[{"effect_class":"E3","action_type":"scan"}],"ADMISSION_DISABLED"),
    (True,"enabled",[],"CAPABILITY_NOT_DISCOVERED"),
])
def test_live_discovery_unavailable_is_not_admitted(monkeypatch,catalog_valid,admission_mode,capabilities,reason):
    monkeypatch.setattr(readiness,"urlopen",lambda *_a,**_kw:_Response({
        "admission_mode":admission_mode,"catalog_valid":catalog_valid,
        "capabilities":capabilities}))
    report=readiness.diagnose_live("E3","scan",url="https://eg.example",api_key="fixture")
    assert report["preflight"]=="NOT_ADMITTED"
    assert reason in report["reasons"]
    assert report["live_verified"] is False
