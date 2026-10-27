"""Legal attribution is a release gate, not optional documentation."""
from pathlib import Path
import json
import hashlib

import pytest
from tools.license_compliance import (
    REVIEWED_SPDX, REVIEWED_VERSIONS, BLOCKED_MODULES, BLOCKED_NATIVE, locked_versions,
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
    lock.write_text((ROOT / "requirements.lock").read_text() + "unreviewed==1.0.0 \\n  --hash=sha256:fake\n")
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
        {"format": 2, "python_dependencies": [], "native_libraries": []}))
    with pytest.raises(RuntimeError, match="LICENSE_BUNDLE_PYTHON_CLOSURE_DRIFT"):
        verify_bundled_notices(release, ROOT / "requirements.lock")


def _checked_release(tmp_path):
    """Minimal synthetic distribution so integrity tests need no Linux build."""
    root = tmp_path / "bundle"
    notices = root / "THIRD_PARTY_LICENSES"
    site = root / "python/lib/python3.12/site-packages"
    notices.mkdir(parents=True)
    site.mkdir(parents=True)
    (root / "eg").mkdir()
    mit = ("Copyright and MIT permission terms: " * 20).encode()
    (root / "LICENSE").write_bytes(mit)
    (root / "eg/LICENSE").write_bytes(mit)
    cpython = ("CPython PSF 2.0 text. " * 60).encode()
    notice = ("Third-party notice and attribution. " * 4).encode()
    (notices / "CPython-3.12-license.txt").write_bytes(cpython)
    (notices / "NOTICE.md").write_bytes(notice)
    python = []
    for name, version in sorted(REVIEWED_VERSIONS.items()):
        dist = site / (name.replace("-", "_") + "-" + version + ".dist-info")
        dist.mkdir()
        (dist / "METADATA").write_text(
            "Metadata-Version: 2.1\nName: " + name + "\nVersion: " + version + "\n"
        )
        rel = "python/" + name + "-" + version + "/0-LICENSE"
        legal = notices / rel
        legal.parent.mkdir(parents=True)
        data = (name + " license terms and copyright holder. " * 3).encode()
        legal.write_bytes(data)
        python.append({
            "name": name, "version": version, "reviewed_spdx": REVIEWED_SPDX[name],
            "license_files": [rel],
            "license_sha256": {rel: hashlib.sha256(data).hexdigest()},
        })
    manifest = {
        "format": 2, "python_dependencies": python, "native_libraries": [],
        "cpython_license": "CPython-3.12-license.txt",
        "cpython_sha256": hashlib.sha256(cpython).hexdigest(),
        "notice_sha256": hashlib.sha256(notice).hexdigest(),
        "project_mit_sha256": hashlib.sha256(mit).hexdigest(),
    }
    (notices / "LICENSES.json").write_text(json.dumps(manifest))
    return root, manifest


def test_positive_license_integrity_fixture(tmp_path):
    root, _ = _checked_release(tmp_path)
    assert verify_bundled_notices(root, ROOT / "requirements.lock") == {
        "status": "PASS", "python_packages": 17, "native_libraries": 0
    }


def test_license_notice_modified_after_collection_fails(tmp_path):
    root, manifest = _checked_release(tmp_path)
    rel = manifest["python_dependencies"][0]["license_files"][0]
    (root / "THIRD_PARTY_LICENSES" / rel).write_bytes(b"tampered copyright terms " * 3)
    with pytest.raises(RuntimeError, match="LICENSE_BUNDLE_NOTICE_HASH_MISMATCH"):
        verify_bundled_notices(root, ROOT / "requirements.lock")


def test_unreviewed_extra_distribution_fails(tmp_path):
    root, _ = _checked_release(tmp_path)
    extra = root / "python/lib/python3.12/site-packages/unknown-1.0.dist-info"
    extra.mkdir()
    (extra / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: unknown\nVersion: 1.0\n"
    )
    with pytest.raises(RuntimeError, match="LICENSE_BUNDLE_UNREVIEWED_INSTALLED_WHEEL"):
        verify_bundled_notices(root, ROOT / "requirements.lock")


def test_uninventoried_native_library_fails(tmp_path):
    root, _ = _checked_release(tmp_path)
    native = root / "python/lib"
    native.mkdir(exist_ok=True, parents=True)
    (native / "libunreviewed.so.1").write_bytes(b"native-binary")
    with pytest.raises(RuntimeError, match="LICENSE_BUNDLE_NATIVE_CLOSURE_DRIFT"):
        verify_bundled_notices(root, ROOT / "requirements.lock")


def test_missing_project_mit_copy_fails(tmp_path):
    root, _ = _checked_release(tmp_path)
    (root / "eg/LICENSE").unlink()
    with pytest.raises(RuntimeError, match="LICENSE_BUNDLE_PROJECT_MIT_COPY_DRIFT"):
        verify_bundled_notices(root, ROOT / "requirements.lock")


def test_pinned_version_change_requires_fresh_review(tmp_path):
    changed = (ROOT / "requirements.lock").read_text().replace(
        "fastapi==0.142.2", "fastapi==0.142.3"
    )
    path = tmp_path / "requirements.lock"
    path.write_text(changed)
    with pytest.raises(RuntimeError, match="LICENSE_UNREVIEWED_LOCKED_PACKAGE_LIST"):
        locked_versions(path)


def test_stdlib_copy_excludes_host_site_packages():
    builder = (ROOT / "tools/build_portable_bundle.py").read_text()
    assert "'site-packages'" in builder[builder.index("def copy_source("):
                                        builder.index("def copy_eg_source(")]
