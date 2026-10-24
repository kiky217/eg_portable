"""Non-root portable distribution must not inherit private build-environment modes."""
import stat

import pytest

from tools.build_portable_bundle import normalize_bundle_permissions


def _mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def test_normalization_is_scoped_to_staged_public_distribution(tmp_path):
    private=tmp_path/'private-build-site'
    package=private/'uvicorn'
    package.mkdir(parents=True)
    module=package/'__init__.py'
    module.write_text('PUBLIC_MODULE')
    private.chmod(0o700)
    package.chmod(0o700)
    module.chmod(0o600)

    root=tmp_path/'bundle'
    vendored=root/'python/lib/python3.12/site-packages/uvicorn'
    vendored.mkdir(parents=True)
    vendored_module=vendored/'__init__.py'
    vendored_module.write_text(module.read_text())
    root.chmod(0o700)
    for directory in (root/'python',root/'python/lib',root/'python/lib/python3.12',
                      root/'python/lib/python3.12/site-packages',vendored):
        directory.chmod(0o700)
    vendored_module.chmod(0o600)
    (root/'python/bin').mkdir()
    interpreter=root/'python/bin/python3.12'
    interpreter.write_bytes(b'PUBLIC_BINARY')
    interpreter.chmod(0o700)
    (root/'start.sh').write_text('#!/bin/sh\n')
    (root/'start.sh').chmod(0o600)
    (root/'README.md').write_text('PUBLIC DOC')
    (root/'README.md').chmod(0o600)

    normalize_bundle_permissions(root)

    assert all(_mode(directory)==0o755 for directory in
               (root,root/'python',root/'python/lib',vendored))
    assert _mode(vendored_module)==0o644
    assert _mode(root/'README.md')==0o644
    assert _mode(interpreter)==0o755
    assert _mode(root/'start.sh')==0o755
    # Never chmod the private input, signing keys or runtime state.
    assert _mode(private)==0o700
    assert _mode(package)==0o700
    assert _mode(module)==0o600


def test_staging_symlink_is_denied_before_chmod(tmp_path):
    root=tmp_path/'bundle'
    root.mkdir()
    secret=tmp_path/'notary-private.key'
    secret.write_text('PRIVATE')
    secret.chmod(0o600)
    (root/'linked-key').symlink_to(secret)
    with pytest.raises(RuntimeError,match='UNSAFE_PORTABLE_STAGE_SYMLINK'):
        normalize_bundle_permissions(root)
    assert _mode(secret)==0o600
