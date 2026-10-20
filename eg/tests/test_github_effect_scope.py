"""GitHub adapter input scope is fail-closed; no connector action implied."""
import pytest
from tools.github_effect_scope import validate_operation,GitHubScopeDenied
POL={"repository":"kiky217/eg_portable","branch_prefix":"agent/","path_prefix":"eg/app","actions":["update_file","create_file"]}
REQ={"repository":"kiky217/eg_portable","operation":"update_file",
     "branch":"agent/fix-issue-68","path":"eg/app/main.py","expected_blob_sha":"a"*40}

def test_scoped_update():
    assert validate_operation(REQ,POL)==REQ

@pytest.mark.parametrize("field,value",[
    ("repository","other/repo"),("branch","main"),("branch","agent/../main"),
    ("branch","agent-other"),("path","eg/app/../secrets"),
    ("path","eg/application/main.py"),("path","README.md"),
    ("expected_blob_sha",""),("expected_blob_sha","invalid"),
    ("operation","merge_pull_request"),("operation","delete_file")])
def test_rejects_untrusted_operations(field,value):
    with pytest.raises(GitHubScopeDenied):
        validate_operation({**REQ,field:value},POL)

def test_new_files_must_not_claim_prior_hash():
    create={**REQ,"operation":"create_file","expected_blob_sha":""}
    assert validate_operation(create,POL)["operation"]=="create_file"
    with pytest.raises(GitHubScopeDenied):
        validate_operation({**create,"expected_blob_sha":"a"*40},POL)

@pytest.mark.parametrize("bad",[[["create_file"]],[42],["create_file",{}],["create_file",None]])
def test_malformed_allowlist_denies_with_typed_scope_error(bad):
    with pytest.raises(GitHubScopeDenied,match="INVALID_GITHUB_SCOPE_POLICY"):
        validate_operation(REQ,{**POL,"actions":bad})
