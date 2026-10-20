"""Immutable GitHub SHA readback cannot be confused with an effect receipt."""
import base64,json
import pytest
from tools.github_commit_readback import verify_commit_content,GitHubReadbackDenied
POL={"repository":"kiky217/eg_portable","branch_prefix":"agent/","path_prefix":"eg/app","actions":["create_file","update_file"]}
OP={"repository":"kiky217/eg_portable","operation":"create_file","branch":"agent/test","path":"eg/app/a.py","expected_blob_sha":""}
COMMIT="a"*40
class Response:
    def __init__(self,data):self.data=data
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def read(self,limit):return self.data

def opener(request,timeout):
    assert "ref="+COMMIT in request.full_url
    assert "/contents/eg/app/a.py" in request.full_url
    return Response(json.dumps({"type":"file","path":"eg/app/a.py","encoding":"base64",
        "content":base64.b64encode(b"source").decode()}).encode())

def test_verified_content_is_not_execution_proof():
    result=verify_commit_content(OP,POL,commit_sha=COMMIT,expected_bytes=b"source",
                                 token="fixture",opener=opener)
    assert result["status"]=="CONTENT_VERIFIED_NOT_EXECUTION_PROOF"
    assert result["bytes"]==6

def test_mismatch_fails_closed():
    with pytest.raises(GitHubReadbackDenied,match="MISMATCH"):
        verify_commit_content(OP,POL,commit_sha=COMMIT,expected_bytes=b"altered",
                              token="fixture",opener=opener)

@pytest.mark.parametrize("sha,token",[(COMMIT,""),("a"*39,"fixture"),("z"*40,"fixture")])
def test_untrusted_readback_params_rejected(sha,token):
    with pytest.raises(GitHubReadbackDenied):
        verify_commit_content(OP,POL,commit_sha=sha,expected_bytes=b"source",
                              token=token,opener=opener)
