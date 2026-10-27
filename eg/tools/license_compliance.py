"""Fail-closed third-party license provenance for the exact offline EG bundle.

This is an attribution/redistribution inventory, not a legal opinion. Changes to
the pinned closure or accepted license IDs require review before release.
"""
from __future__ import annotations

import hashlib
import importlib.metadata as metadata
import json
import re
import shutil
import subprocess
from pathlib import Path, PurePosixPath

# Reviewed at the exact locked versions; never infer MIT licensing for dependencies.
REVIEWED_SPDX = {
    "fastapi": "MIT", "starlette": "BSD-3-Clause",
    "pydantic": "MIT", "pydantic-core": "MIT",
    "annotated-types": "MIT", "annotated-doc": "MIT",
    "typing-extensions": "PSF-2.0", "typing-inspection": "MIT",
    "opentelemetry-api": "Apache-2.0", "anyio": "MIT",
    "idna": "BSD-3-Clause", "uvicorn": "BSD-3-Clause",
    "click": "BSD-3-Clause", "h11": "MIT",
    "cryptography": "Apache-2.0 OR BSD-3-Clause",
    "cffi": "MIT", "pycparser": "BSD-3-Clause",
}
# License approval applies to exact package versions, not just package names.
REVIEWED_VERSIONS = {
    "fastapi": "0.142.2", "starlette": "1.7.0",
    "pydantic": "2.13.5", "pydantic-core": "2.46.5",
    "annotated-types": "0.8.0", "annotated-doc": "0.0.4",
    "typing-extensions": "4.16.0", "typing-inspection": "0.4.4",
    "opentelemetry-api": "1.44.0", "anyio": "4.13.0",
    "idna": "3.17", "uvicorn": "0.54.0", "click": "8.1.8",
    "h11": "0.16.0", "cryptography": "50.0.2",
    "cffi": "2.0.0", "pycparser": "3.0",
}
# These optional GNU modules must not be shipped in an MIT-labelled portable
# distribution without a separately documented GPL compliance programme.
BLOCKED_MODULES = ("readline.", "_gdbm.", "_dbm.")
BLOCKED_NATIVE = frozenset(("libreadline.so.8", "libgdbm.so.6", "libgdbm_compat.so.4"))
# Debian Bookworm binary-owner mapping, reviewed per soname; new libraries block the build.
DEBIAN_NATIVE_OWNERS = {
    "libssl.so.3": "libssl3", "libcrypto.so.3": "libssl3",
    "libsqlite3.so.0": "libsqlite3-0", "libffi.so.8": "libffi8",
    "libbz2.so.1.0": "libbz2-1.0", "liblzma.so.5": "liblzma5",
    "libz.so.1": "zlib1g", "libexpat.so.1": "libexpat1",
    "libncursesw.so.6": "libncursesw6", "libtinfo.so.6": "libtinfo6",
    "libuuid.so.1": "libuuid1",
}
MAX_NOTICE = 1024 * 1024


def normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def locked_versions(path: Path) -> dict[str, str]:
    data = dict((normalized(name), version) for name, version in
                re.findall(r"(?m)^([A-Za-z0-9_.-]+)==([^\\\s]+)", path.read_text()))
    if not data or data != REVIEWED_VERSIONS or set(data) != set(REVIEWED_SPDX):
        raise RuntimeError("LICENSE_UNREVIEWED_LOCKED_PACKAGE_LIST")
    return data


def wheel_closure(site: Path, destination: Path, notice_root: Path,
                  requirements: Path) -> list[dict]:
    """Copy only locked wheels, including their actual license files."""
    versions = locked_versions(requirements)
    destination.mkdir(parents=True, exist_ok=True)
    notice_root.mkdir(parents=True, exist_ok=True)
    installed = {}
    for dist in metadata.distributions(path=[str(site)]):
        name = normalized(dist.metadata.get("Name", ""))
        if name in versions:
            if name in installed:
                raise RuntimeError("LICENSE_DUPLICATE_DISTRIBUTION_" + name)
            installed[name] = dist
    if set(installed) != set(versions):
        raise RuntimeError("LICENSE_MISSING_WHEELS_" +
                           ",".join(sorted(set(versions) - set(installed))))
    inventory = []
    for name, expected_version in sorted(versions.items()):
        dist = installed[name]
        if dist.version != expected_version:
            raise RuntimeError("LICENSE_VERSION_MISMATCH_" + name)
        actual_expression = (dist.metadata.get("License-Expression") or "").strip()
        reviewed = REVIEWED_SPDX[name]
        if actual_expression and actual_expression != reviewed:
            raise RuntimeError("LICENSE_SPDX_DRIFT_" + name + "_" + actual_expression)
        files = list(dist.files or ())
        if not files:
            raise RuntimeError("LICENSE_WHEEL_RECORD_MISSING_" + name)
        copied_legal = []
        legal_hashes = {}
        for file in files:
            source = Path(dist.locate_file(file))
            try:
                rel = source.resolve().relative_to(site.resolve())
            except ValueError:
                # Wheel-generated entry-point scripts outside site-packages
                # are unnecessary: portable launches uvicorn as a module.
                continue
            if source.is_symlink():
                raise RuntimeError("LICENSE_WHEEL_SYMLINK_" + name)
            if not source.is_file():
                continue
            target = destination / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            label = source.name.upper()
            if (".dist-info/" in rel.as_posix() and
                    ("/licenses/" in rel.as_posix().lower() or
                     label.startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE", "COPYRIGHT")))):
                raw = source.read_bytes()
                if not 40 <= len(raw) <= MAX_NOTICE:
                    raise RuntimeError("LICENSE_INVALID_TEXT_" + name)
                subdir = notice_root / "python" / (name + "-" + expected_version)
                subdir.mkdir(parents=True, exist_ok=True)
                notice = subdir / (str(len(copied_legal)) + "-" + source.name)
                notice.write_bytes(raw)
                rel_notice = str(notice.relative_to(notice_root))
                copied_legal.append(rel_notice)
                legal_hashes[rel_notice] = hashlib.sha256(raw).hexdigest()
        if not copied_legal:
            raise RuntimeError("LICENSE_TEXT_MISSING_" + name)
        inventory.append({"name": name, "version": expected_version,
                          "reviewed_spdx": reviewed, "license_files": copied_legal,
                          "license_sha256": legal_hashes})
    return inventory


def prune_optional_gnu_extensions(stdlib: Path) -> None:
    dynload = stdlib / "lib-dynload"
    for name in BLOCKED_MODULES:
        for module in dynload.glob(name + "*.so"):
            module.unlink()


def native_notice(soname: str, source: Path, notice_root: Path) -> dict:
    if soname in BLOCKED_NATIVE:
        raise RuntimeError("LICENSE_GPL_NATIVE_BUNDLING_BLOCKED_" + soname)
    pkg = DEBIAN_NATIVE_OWNERS.get(soname)
    if not pkg:
        raise RuntimeError("LICENSE_UNREVIEWED_NATIVE_LIBRARY_" + soname)
    try:
        version = subprocess.run(
            ["dpkg-query", "-W", "-f=${Version}", pkg],
            text=True, capture_output=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        raise RuntimeError("LICENSE_NATIVE_OWNER_UNVERIFIED_" + soname) from None
    if not version:
        raise RuntimeError("LICENSE_NATIVE_VERSION_MISSING_" + soname)
    source_notice = Path("/usr/share/doc") / pkg / "copyright"
    if not source_notice.is_file():
        raise RuntimeError("LICENSE_NATIVE_TEXT_MISSING_" + soname)
    data = source_notice.read_bytes()
    if not 40 <= len(data) <= MAX_NOTICE:
        raise RuntimeError("LICENSE_NATIVE_TEXT_INVALID_" + soname)
    target = notice_root / "native" / (soname + "-" + pkg + ".copyright")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return {"soname": soname, "debian_package": pkg, "debian_version": version,
            "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "notice_path": str(target.relative_to(notice_root)),
            "notice_sha256": hashlib.sha256(data).hexdigest()}


def publish_notice_index(notice_root: Path, python: list[dict],
                         native: list[dict], cpython_license: Path,
                         project_license: Path) -> None:
    if not cpython_license.is_file() or cpython_license.stat().st_size < 1000:
        raise RuntimeError("LICENSE_CPYTHON_TEXT_MISSING")
    if not project_license.is_file() or project_license.stat().st_size < 500:
        raise RuntimeError("LICENSE_PROJECT_MIT_TEXT_MISSING")
    notice_text = (
        "# Third-party notices for EG Portable\n\n"
        "The EG application source is licensed under MIT (see /LICENSE). "
        "Bundled Python, Python packages, and native libraries retain their own "
        "licenses; the EG MIT license does not relicense those components.\n\n"
        "See LICENSES.json and the full vendor texts under python/, native/, "
        "and CPython-3.12-license.txt. The Debian package copyright documents "
        "may contain terms for more than one component; retain them unmodified.\n\n"
        "This automated manifest checks copied metadata and attribution. "
        "It is not a legal opinion; copyleft/source-offer and export-law "
        "obligations, if any, still require independent review before distribution.\n"
    )
    (notice_root / "NOTICE.md").write_text(notice_text, encoding="utf-8")
    manifest = {
        "format": 2,
        "scope": "exact bundled EG portable distribution",
        "python_dependencies": python,
        "native_libraries": native,
        "cpython_license": str(cpython_license.relative_to(notice_root)),
        "cpython_sha256": hashlib.sha256(cpython_license.read_bytes()).hexdigest(),
        "project_mit_sha256": hashlib.sha256(project_license.read_bytes()).hexdigest(),
        "notice_sha256": hashlib.sha256(notice_text.encode("utf-8")).hexdigest(),
    }
    (notice_root / "LICENSES.json").write_text(
        json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _verified_file(base: Path, relative: str, expected_sha256: str,
                   label: str) -> Path:
    """Only accept present, unmodified, non-symlink attribution within base."""
    if not isinstance(relative, str) or not isinstance(expected_sha256, str):
        raise RuntimeError("LICENSE_BUNDLE_INVALID_ENTRY_" + label)
    rel = PurePosixPath(relative)
    if rel.is_absolute() or not rel.parts or ".." in rel.parts or "\\" in relative:
        raise RuntimeError("LICENSE_BUNDLE_UNSAFE_PATH_" + label)
    path = base.joinpath(*rel.parts)
    for depth in range(1, len(rel.parts) + 1):
        if base.joinpath(*rel.parts[:depth]).is_symlink():
            raise RuntimeError("LICENSE_BUNDLE_SYMLINK_" + label)
    if not path.is_file() or not 40 <= path.stat().st_size <= MAX_NOTICE:
        raise RuntimeError("LICENSE_BUNDLE_NOTICE_MISSING_OR_INVALID_" + label)
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if not re.fullmatch(r"[a-f0-9]{64}", expected_sha256) or actual != expected_sha256:
        raise RuntimeError("LICENSE_BUNDLE_NOTICE_HASH_MISMATCH_" + label)
    return path


def verify_bundled_notices(root: Path, requirements: Path) -> dict:
    notices = root / "THIRD_PARTY_LICENSES"
    obj = json.loads((notices / "LICENSES.json").read_text(encoding="utf-8"))
    if obj.get("format") != 2:
        raise RuntimeError("LICENSE_BUNDLE_MANIFEST_FORMAT_UNSUPPORTED")
    expected = locked_versions(requirements)
    python_items = obj["python_dependencies"]
    found = {item["name"]: item["version"] for item in python_items}
    if len(python_items) != len(found) or found != expected:
        raise RuntimeError("LICENSE_BUNDLE_PYTHON_CLOSURE_DRIFT")
    for item in python_items:
        name = item["name"]
        if item["reviewed_spdx"] != REVIEWED_SPDX[name]:
            raise RuntimeError("LICENSE_BUNDLE_SPDX_DRIFT")
        files = item["license_files"]
        hashes = item["license_sha256"]
        if not files or len(set(files)) != len(files) or set(files) != set(hashes):
            raise RuntimeError("LICENSE_BUNDLE_PYTHON_NOTICE_INDEX_DRIFT_" + name)
        for rel in files:
            if not rel.startswith("python/" + name + "-" + expected[name] + "/"):
                raise RuntimeError("LICENSE_BUNDLE_PYTHON_NOTICE_PATH_DRIFT_" + name)
            _verified_file(notices, rel, hashes[rel], name)
    # Presence of seventeen notices does not prove the bundle contains only
    # those seventeen distributions. Audit the *actual* copied site-packages.
    site = root / "python/lib/python3.12/site-packages"
    copied_dists = list(metadata.distributions(path=[str(site)]))
    actual_wheels = {
        normalized(d.metadata.get("Name", "")): d.version for d in copied_dists
    }
    if (len(copied_dists) != len(actual_wheels) or actual_wheels != expected):
        raise RuntimeError("LICENSE_BUNDLE_UNREVIEWED_INSTALLED_WHEEL")
    native_items = obj["native_libraries"]
    native_found = {item["soname"]: item for item in native_items}
    if len(native_items) != len(native_found):
        raise RuntimeError("LICENSE_BUNDLE_DUPLICATE_NATIVE")
    native_dir = root / "python" / "lib"
    actual_native = {
        f.name for f in native_dir.iterdir()
        if f.is_file() and ".so" in f.name and not f.name.startswith("libpython3.12.so")
    } if native_dir.is_dir() else set()
    if set(native_found) != actual_native:
        raise RuntimeError("LICENSE_BUNDLE_NATIVE_CLOSURE_DRIFT")
    for soname, item in native_found.items():
        if soname in BLOCKED_NATIVE:
            raise RuntimeError("LICENSE_BUNDLE_GPL_LIBRARY_DENIED")
        if DEBIAN_NATIVE_OWNERS.get(soname) != item["debian_package"]:
            raise RuntimeError("LICENSE_BUNDLE_NATIVE_OWNER_DRIFT_" + soname)
        if not item["debian_version"]:
            raise RuntimeError("LICENSE_BUNDLE_NATIVE_VERSION_MISSING_" + soname)
        binary = native_dir / soname
        if binary.is_symlink():
            raise RuntimeError("LICENSE_BUNDLE_NATIVE_SYMLINK_" + soname)
        if hashlib.sha256(binary.read_bytes()).hexdigest() != item["source_sha256"]:
            raise RuntimeError("LICENSE_BUNDLE_NATIVE_HASH_MISMATCH_" + soname)
        if item["notice_path"] != "native/" + soname + "-" + item["debian_package"] + ".copyright":
            raise RuntimeError("LICENSE_BUNDLE_NATIVE_NOTICE_PATH_DRIFT_" + soname)
        _verified_file(notices, item["notice_path"], item["notice_sha256"], soname)
    if obj["cpython_license"] != "CPython-3.12-license.txt":
        raise RuntimeError("LICENSE_BUNDLE_CPYTHON_PATH_DRIFT")
    _verified_file(notices, obj["cpython_license"], obj["cpython_sha256"], "cpython")
    _verified_file(notices, "NOTICE.md", obj["notice_sha256"], "notice")
    mit = _verified_file(root, "LICENSE", obj["project_mit_sha256"], "project_mit")
    if not (root / "eg" / "LICENSE").is_file() or (root / "eg" / "LICENSE").read_bytes() != mit.read_bytes():
        raise RuntimeError("LICENSE_BUNDLE_PROJECT_MIT_COPY_DRIFT")
    for blocked in BLOCKED_NATIVE:
        if (root / "python" / "lib" / blocked).exists():
            raise RuntimeError("LICENSE_BUNDLE_GPL_LIBRARY_PRESENT_" + blocked)
    for name in BLOCKED_MODULES:
        if list((root / "python/lib/python3.12/lib-dynload").glob(name + "*.so")):
            raise RuntimeError("LICENSE_BUNDLE_GNU_EXTENSION_PRESENT")
    return {"status": "PASS", "python_packages": len(found),
            "native_libraries": len(native_items)}
