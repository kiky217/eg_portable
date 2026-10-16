"""Actual isolated archive extraction rehearsal; does not attest a production cutover."""
import hashlib
import json
import tarfile
from pathlib import Path

from test_post_cutover_readiness import fixture
from tools.check_live_cutover_readiness import inspect_completed_cutover


def _restore_safely(archive_path: Path, destination: Path):
    destination.mkdir()
    with tarfile.open(archive_path, "r:*") as archive:
        members=archive.getmembers()
        assert members
        for member in members:
            name=Path(member.name)
            assert not name.is_absolute() and ".." not in name.parts
            assert member.isfile()
            content=archive.extractfile(member)
            assert content is not None
            target=destination.joinpath(*name.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as stream:
                stream.write(content.read())
    return sorted(
        (str(p.relative_to(destination)),hashlib.sha256(p.read_bytes()).hexdigest())
        for p in destination.rglob("*") if p.is_file()
    )


def test_real_restore_rehearsal_preserves_archive_members_but_not_cutover_authority(tmp_path):
    report, db, audit, state, metadata=fixture(tmp_path)
    archive=Path(metadata["legacy_source_archive"])
    original=_restore_safely(archive,tmp_path/"original-restore")
    assert original and original[0][0]=="runtime/main.py"
    # Repeat restore from the same immutable archive; compare actual resulting bytes.
    restored=_restore_safely(archive,tmp_path/"restore-rehearsal")
    assert restored==original
    verdict=inspect_completed_cutover(report,audit,state,db)
    assert verdict["file_consistency_checked"] is True
    assert verdict["restore_rehearsal_verified"] is False
    assert verdict["verified"] is False


def test_corrupt_archive_cannot_be_restored_or_certified(tmp_path):
    report, db, audit, state, metadata=fixture(tmp_path)
    archive=Path(metadata["legacy_source_archive"])
    archive.write_bytes(b"invalid archive")
    metadata["legacy_source_archive_sha256"]=hashlib.sha256(archive.read_bytes()).hexdigest()
    report.write_text(json.dumps(metadata))
    try:
        _restore_safely(archive,tmp_path/"failed-restore")
    except (tarfile.TarError,OSError):
        pass
    else:
        raise AssertionError("invalid rollback archive restored")
    assert inspect_completed_cutover(report,audit,state,db)["verified"] is False
