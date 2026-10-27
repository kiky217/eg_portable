"""Legal attribution is a release gate, not optional documentation."""
from pathlib import Path
import json

import pytest
from tools.license_compliance import (
    REVIEWED_SPDX, BLOCKED_MODULES, BLOCKED_NATIVE, locked_versions,
    native_notice, verify_bundled_notices,
)

ROOT = Path(__file__).resolve().parents[1]


def test_exact_production_dependency_closure_requires_review():
    closure = locked_versions(ROOT / "requirements.lock")
    assert len(closure) == 17
    assert set(closure) == set(REVIEWED_SPDX)
    assert all(closure.values())


def test_unreviewed_package_fails_closed(tmp_path):
    lock = tmp_path / "requirements.lock"
    lock.write_text((ROOT / "requirements.lock").read_text() + "unreviewed==1.0.0 \\\n  --hash=sha256:fake\n")
    with pytest.raises(RuntimeError, match="LICENSE_UNREVIEWED_LOCKED_PACKAGE_LIST"):
        locked_versions(lock)


def test_gnu_copyleft_native_libraries_are_blocked(tmp_path):
    for soname in sorted(BLOCKED_NATIVE):
        with pytest.raises(RuntimeError, match="LICENSE_GPL_NATIVE_BUNDLING_BLOCKED"):
            native_notice(soname, tmp_path / "ignored.so", tmp_path)


def test_portable_builder_records_and_verifies_licenses():
    source = (ROOT / "tools/build_portable_bundle.py").read_text()
    for required in ("wheel_closure(", "prune_optional_gnu_extensions(",
                     "native_notice(", "publish_notice_index(",
                     "verify_bundled_notices("):
        assert required in source
    assert all(x not in source[source.index("allowed_native="):source.index("binary_files=")]
               for x in BLOCKED_NATIVE)
    assert BLOCKED_MODULES == ("readline.", "_gdbm.", "_dbm.")


def test_container_includes_project_mit_license():
    assert "COPY LICENSE ." in (ROOT / "Dockerfile").read_text()


def test_release_notice_validator_refuses_missing_provenance(tmp_path):
    release = tmp_path / "release"
    legal = release / "THIRD_PARTY_LICENSES"
    legal.mkdir(parents=True)
    (legal / "LICENSES.json").write_text(json.dumps(
        {"python_dependencies": [], "native_libraries": []}))
    with pytest.raises(RuntimeError, match="LICENSE_BUNDLE_PYTHON_CLOSURE_DRIFT"):
        verify_bundled_notices(release, ROOT / "requirements.lock")
