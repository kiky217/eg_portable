"""Worker rejects ancestor symlinks, unsafe directories and path traversal."""
import pytest
from tools.trusted_execution_worker import TrustedWriter, WorkerDenied


def _writer(root):
    writer=object.__new__(TrustedWriter)
    writer.root=root.resolve(strict=True)
    writer.allowed_suffixes=(".txt",".json",".py")
    return writer


def test_prepared_private_subdirectories_are_allowed(tmp_path):
    root=tmp_path/"worker";root.mkdir(mode=0o700)
    sub=root/"project";sub.mkdir(mode=0o700)
    src=sub/"src";src.mkdir(mode=0o700)
    assert _writer(root).bounded_target(str(src/"main.py"))==src/"main.py"


def test_missing_and_symlink_ancestor_fail_closed(tmp_path):
    root=tmp_path/"worker";root.mkdir(mode=0o700)
    external=tmp_path/"external";external.mkdir(mode=0o700)
    (root/"link").symlink_to(external,target_is_directory=True)
    writer=_writer(root)
    for target in (root/"link"/"escape.py",root/"unknown"/"a.py",root/"../escape.py"):
        with pytest.raises(WorkerDenied,match="TARGET_OUTSIDE_WORKER_BOUNDS"):
            writer.bounded_target(str(target))


def test_group_readable_subdirectory_denied(tmp_path):
    root=tmp_path/"worker";root.mkdir(mode=0o700)
    sub=root/"open";sub.mkdir(mode=0o755)
    with pytest.raises(WorkerDenied,match="TARGET_OUTSIDE_WORKER_BOUNDS"):
        _writer(root).bounded_target(str(sub/"a.py"))
