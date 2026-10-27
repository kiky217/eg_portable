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
from pathlib import Path

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
    "cffi": "MIT-0", "pycparser": "BSD-3-Clause",
}
# These optional GNU modules must not be shipped in an MIT-labelled portable
# distribution without a separately documented GPL compliance programme.
BLOCKED_MODULES = ("readline.", "_gdbm.", "_dbm.")
BLOCKED_NATIVE = frozenset(("libreadline.so.8", "libgdbm.so.6", "libgdbm_compat.so.4"))
MAX_NOTICE = 1024 * 1024


def normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def locked_versions(path: Path) -> dict[str, str]:
    data = dict((normalized(name), version) for name, version in
                re.findall(r"(?m)^([A-Za-z0-9_.-]+)==([^\\\s]+)", path.read_text()))
    if not data or set(data) != set(REVIEWED_SPDX):
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
                copied_legal.append(str(notice.relative_to(notice_root)))
        if not copied_legal:
            raise RuntimeError("LICENSE_TEXT_MISSING_" + name)
        inventory.append({"name": name, "version": expected_version,
                          "reviewed_spdx": reviewed, "license_files": copied_legal})
    return inventory


def prune_optional_gnu_extensions(stdlib: Path) -> None:
    dynload = stdlib / "lib-dynload"
    for name in BLOCKED_MODULES:
        for module in dynload.glob(name + "*.so"):
            module.unlink()


def native_notice(soname: str, source: Path, notice_root: Path) -> dict:
    if soname in BLOCKED_NATIVE:
        raise RuntimeError("LICENSE_GPL_NATIVE_BUNDLING_BLOCKED_" + soname)
    try:
        owner = subprocess.run(["dpkg-query", "-S", str(source.resolve())],
                               text=True, capture_output=True, check=True).stdout
        # Multiarch package format: libssl3:amd64: /usr/lib/...
        pkg = owner.splitlines()[0].split(": ", 1)[0].split(":")[0]
    except (OSError, subprocess.CalledProcessError, IndexError):
        raise RuntimeError("LICENSE_NATIVE_OWNER_UNVERIFIED_" + soname) from None
    if not re.fullmatch(r"[a-z0-9+.-]+", pkg):
        raise RuntimeError("LICENSE_NATIVE_OWNER_INVALID_" + soname)
    source_notice = Path("/usr/share/doc") / pkg / "copyright"
    if not source_notice.is_file():
        raise RuntimeError("LICENSE_NATIVE_TEXT_MISSING_" + soname)
    data = source_notice.read_bytes()
    if not 40 <= len(data) <= MAX_NOTICE:
        raise RuntimeError("LICENSE_NATIVE_TEXT_INVALID_" + soname)
    target = notice_root / "native" / (soname + "-" + pkg + ".copyright")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return {"soname": soname, "debian_package": pkg,
            "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "notice_path": str(target.relative_to(notice_root))}


def publish_notice_index(notice_root: Path, python: list[dict],
                         native: list[dict], cpython_license: Path) -> None:
    if not cpython_license.is_file() or cpython_license.stat().st_size < 1000:
        raise RuntimeError("LICENSE_CPYTHON_TEXT_MISSING")
    manifest = {"format": 1, "scope": "exact bundled EG portable distribution",
                "python_dependencies": python, "native_libraries": native,
                "cpython_license": str(cpython_license.relative_to(notice_root))}
    (notice_root / "LICENSES.json").write_text(
        json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    (notice_root / "NOTICE.md").write_text(
        "# Third-party notices for EG Portable\n\n"
        "The EG application source is licensed under MIT (see /LICENSE). "
        "Bundled Python, Python packages, and native libraries retain their own "
        "licenses; the EG MIT license does not relicense those components.\n\n"
        "See LICENSES.json and the full vendor texts under python/, native/, "
        "and CPython-3.12-license.txt. The Debian package copyright documents "
        "may contain terms for more than one component; retain them unmodified.\n\n"
        "This automated manifest checks copied metadata and attribution. "
        "It is not a legal opinion; copyleft/source-offer and export-law "
        "obligations, if any, still require independent review before distribution.\n",
        encoding="utf-8")


def verify_bundled_notices(root: Path, requirements: Path) -> dict:
    notices = root / "THIRD_PARTY_LICENSES"
    obj = json.loads((notices / "LICENSES.json").read_text())
    expected = locked_versions(requirements)
    found = {item["name"]: item["version"] for item in obj["python_dependencies"]}
    if found != expected:
        raise RuntimeError("LICENSE_BUNDLE_PYTHON_CLOSURE_DRIFT")
    for item in obj["python_dependencies"]:
        if item["reviewed_spdx"] != REVIEWED_SPDX[item["name"]]:
            raise RuntimeError("LICENSE_BUNDLE_SPDX_DRIFT")
        for f in item["license_files"]:
            if not (notices / f).is_file():
                raise RuntimeError("LICENSE_BUNDLE_NOTICE_MISSING_" + f)
    for item in obj["native_libraries"]:
        if item["soname"] in BLOCKED_NATIVE:
            raise RuntimeError("LICENSE_BUNDLE_GPL_LIBRARY_DENIED")
        if not (notices / item["notice_path"]).is_file():
            raise RuntimeError("LICENSE_BUNDLE_NATIVE_NOTICE_MISSING")
    for required in ("NOTICE.md", "CPython-3.12-license.txt"):
        if not (notices / required).is_file():
            raise RuntimeError("LICENSE_BUNDLE_REQUIRED_NOTICE_MISSING_" + required)
    for blocked in BLOCKED_NATIVE:
        if (root / "python" / "lib" / blocked).exists():
            raise RuntimeError("LICENSE_BUNDLE_GPL_LIBRARY_PRESENT_" + blocked)
    for name in BLOCKED_MODULES:
        if list((root / "python/lib/python3.12/lib-dynload").glob(name + "*.so")):
            raise RuntimeError("LICENSE_BUNDLE_GNU_EXTENSION_PRESENT")
    return {"status": "PASS", "python_packages": len(found),
            "native_libraries": len(obj["native_libraries"])}
