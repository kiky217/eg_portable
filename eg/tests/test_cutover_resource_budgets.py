"""Issue #25: bounded archive hashing and restore rehearsal."""
import io
import tarfile

import pytest

from tools import cutover_attestation as att


def test_archive_size_budget_fails_before_tar_parse(tmp_path, monkeypatch):
    archive=tmp_path/"sparse.tar"
    with archive.open("wb") as f:
        f.truncate(2048)
    monkeypatch.setattr(att,"MAX_ARCHIVE_BYTES",1024)
    with pytest.raises(ValueError, match="SIZE_BUDGET"):
        att.rehearse_restore(archive)


def test_aggregate_member_budget_fails_before_extract(tmp_path, monkeypatch):
    archive=tmp_path/"two.tar"
    with tarfile.open(archive,"w") as tar:
        for i in range(2):
            payload=b"x"*7
            info=tarfile.TarInfo(f"{i}.txt")
            info.size=len(payload)
            tar.addfile(info,io.BytesIO(payload))
    monkeypatch.setattr(att,"MAX_RESTORE_BYTES",10)
    with pytest.raises(ValueError, match="EXPANSION_BUDGET"):
        att.rehearse_restore(archive)


def test_member_count_budget_fails_before_extract(tmp_path, monkeypatch):
    archive=tmp_path/"members.tar"
    with tarfile.open(archive,"w") as tar:
        for i in range(2):
            info=tarfile.TarInfo(f"{i}/")
            info.type=tarfile.DIRTYPE
            tar.addfile(info)
    monkeypatch.setattr(att,"MAX_ARCHIVE_MEMBERS",1)
    with pytest.raises(ValueError, match="EXPANSION_BUDGET"):
        att.rehearse_restore(archive)


def test_valid_archive_roundtrip_under_budget(tmp_path):
    archive=tmp_path/"ok.tar"
    with tarfile.open(archive,"w") as tar:
        payload=b"hello"
        info=tarfile.TarInfo("runtime/hello.txt")
        info.size=len(payload)
        tar.addfile(info,io.BytesIO(payload))
    assert att.rehearse_restore(archive)[0]["size"] == 5
