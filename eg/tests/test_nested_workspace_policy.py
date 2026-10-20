"""Opt-in nested workspace never permits traversal, symlink or unowned parents."""
import os
import pytest
from app.executor_policy import parse_subdir_depth, scoped_parts
from harness import gw, WORKER_OUTPUT
from tools.trusted_execution_worker import TrustedWriter, WorkerDenied


@pytest.mark.parametrize("value", ["-1", "5", "1.1", "abc", True, -1, 5, []])
def test_bad_depth_fails_closed(value):
    with pytest.raises(ValueError, match="INVALID_EXECUTOR_SUBDIR_DEPTH"):
        parse_subdir_depth(value)


def test_default_depth_prevents_nested_targets(monkeypatch, tmp_path):
    target=WORKER_OUTPUT/"src"/"scanner.py"
    monkeypatch.setenv("EVALUATION_GATEWAY_EXECUTOR_ALLOWED_SUFFIXES",".txt,.json,.py")
    monkeypatch.delenv("EVALUATION_GATEWAY_EXECUTOR_MAX_SUBDIR_DEPTH",raising=False)
    action=gw.Action(action_type="write",target=str(target),effect_class="E2",
        reversible=True,real_world_effect=False,payload_sha256="a"*64,payload_bytes=5)
    assert not gw.worker_capability(action)[0]
    monkeypatch.setenv("EVALUATION_GATEWAY_EXECUTOR_MAX_SUBDIR_DEPTH","1")
    assert gw.worker_capability(action)[0]


def test_lexical_bounds_reject_traversal(tmp_path):
    root=tmp_path/"root"
    for target in [root/"src"/".."/"outside.py",tmp_path/"other"/"source.py",
                   root/"src"/"pkg"/"too-deep.py"]:
        # pathlib normalizes ./ automatically, so raw literal dot is separately checked.
        with pytest.raises(ValueError):
            scoped_parts(root,target,1)
    with pytest.raises(ValueError):
        scoped_parts(root,str(root)+"/src/./source.py",1)


def test_worker_nested_preprovision_and_symlink_denial(tmp_path):
    root=tmp_path/"root";root.mkdir(mode=0o700)
    nested=root/"src";nested.mkdir(mode=0o700)
    writer=TrustedWriter.__new__(TrustedWriter)
    writer.root=root.resolve()
    writer.allowed_suffixes=(".txt",".py")
    writer.allowed_subdir_depth=1
    writer._validate_target(nested/"module.py")
    with pytest.raises(WorkerDenied):
        writer._validate_target(root/"src"/"deep"/"module.py")
    (root/"shortcut").symlink_to(nested,target_is_directory=True)
    with pytest.raises(WorkerDenied):
        writer._validate_target(root/"shortcut"/"module.py")
    nested.chmod(0o755)
    with pytest.raises(WorkerDenied,match="UNSAFE_NESTED_WORKSPACE_DIRECTORY"):
        writer._validate_target(nested/"module.py")
