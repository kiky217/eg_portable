"""Runtime source identity is stable across relocation and changes with code."""
from pathlib import Path
import pytest
from tools.runtime_source_fingerprint import fingerprint


def make_runtime(root):
    for name in ('app','tools'):
        folder = root/name
        folder.mkdir(parents=True)
        (folder/'main.py').write_text('value=1\n')

def test_fingerprint_independent_of_install_path(tmp_path):
    one=tmp_path/'one'; two=tmp_path/'different-location'
    make_runtime(one);make_runtime(two)
    assert fingerprint(one)==fingerprint(two)
    (two/'tools'/'main.py').write_text('value=2\n')
    assert fingerprint(one)!=fingerprint(two)

def test_fingerprint_ignores_cache_but_tracks_new_module(tmp_path):
    root=tmp_path/'root'
    make_runtime(root)
    original=fingerprint(root)
    cache=root/'tools'/'__pycache__'
    cache.mkdir()
    (cache/'main.pyc').write_bytes(b'irrelevant')
    assert fingerprint(root)==original
    (root/'tools'/'another.py').write_text('def action(): pass\n')
    assert fingerprint(root)!=original

def test_missing_directory_rejected(tmp_path):
    (tmp_path/'app').mkdir()
    with pytest.raises(ValueError,match='RUNTIME_SOURCE_DIRECTORY_MISSING'):
        fingerprint(tmp_path)
