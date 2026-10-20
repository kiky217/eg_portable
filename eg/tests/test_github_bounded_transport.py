"""Offline tests: no GitHub network effects or real credentials."""
import json
import pytest
from tools.github_bounded_transport import contents_put,GitHubTransportDenied
POL={"repository":"example/project","branch_prefix":"agent/","path_prefix":"src","actions":["create_file","update_file"]}
OP={"repository":"example/project","operation":"create_file","branch":"agent/fix","path":"src/file.py","expected_blob_sha":""}
class Response:
    def __init__(self,obj):self.data=json.dumps(obj).encode()
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def read(self,n):return self.data[:n]
def ok(req,timeout):
    assert req.full_url=="https://api.github.com/repos/example/project/contents/src/file.py"
    assert req.get_method()=="PUT"
    assert json.loads(req.data)["branch"]=="agent/fix"
    return Response({"commit":{"sha":"a"*40},"content":{"sha":"b"*40,"path":"src/file.py"}})
def test_api_ack_is_not_verified_effect():
    r=contents_put(OP,POL,b"hello",token="fixture",commit_message="create",opener=ok)
    assert r["status"]=="GITHUB_ACK_RECONCILE_BEFORE_RECEIPT"
    assert r["commit_sha"]=="a"*40
@pytest.mark.parametrize("token,message",[("","fine"),("bad\rheader","fine"),("token","\ninvalid")])
def test_invalid_inputs_fail_closed(token,message):
    with pytest.raises(GitHubTransportDenied):
        contents_put(OP,POL,b"hello",token=token,commit_message=message,opener=ok)
def test_scope_fails_before_io():
    with pytest.raises(ValueError):
        contents_put({**OP,"branch":"main"},POL,b"hi",token="fixture",commit_message="x",opener=ok)
def test_ambiguous_transport_is_no_replay():
    def fail(req,timeout):raise TimeoutError("indeterminate")
    with pytest.raises(GitHubTransportDenied,match="UNKNOWN_EFFECT_RECONCILIATION_REQUIRED"):
        contents_put(OP,POL,b"hello",token="fixture",commit_message="x",opener=fail)
def test_incomplete_ack_is_not_receipt():
    with pytest.raises(GitHubTransportDenied,match="UNKNOWN_EFFECT_RECONCILIATION_REQUIRED"):
        contents_put(OP,POL,b"hello",token="fixture",commit_message="x",opener=lambda req,timeout:Response({"commit":{}}))
