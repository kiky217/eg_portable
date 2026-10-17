"""Regression test for issue #11."""
import pytest
from tools.build_portable_bundle import copy_eg_source

def make_source(source):
    source.mkdir()
    for name in ('VERSION','LICENSE','README.md','Dockerfile','docker-compose.yml',
                 'requirements.txt','requirements.lock','.env.example'):
        (source/name).write_text('PUBLIC')
    for name in ('app','tools','tests','docs'):
        (source/name).mkdir()
    (source/'app/main.py').write_text('PUBLIC APP')
    (source/'docs/EXECUTOR_PROTOCOL.md').write_text('PUBLIC DOC')

def test_secret_sentinels_excluded(tmp_path):
    src=tmp_path/'source'
    make_source(src)
    for name in ('.env','runtime.env'):
        (src/name).write_text('SECRET-CANARY')
    (src/'evidence/session').mkdir(parents=True)
    (src/'evidence/session/state.json').write_text('SECRET-CANARY')
    (src/'backups').mkdir()
    (src/'backups/gateway.db').write_text('SECRET-CANARY')
    (src/'app/.env').write_text('SECRET-CANARY')
    (src/'docs/private.key').write_text('SECRET-CANARY')
    (src/'artifacts').mkdir()
    (src/'artifacts/legacy-report.json').write_text('HISTORICAL-ONLY-CANARY')
    out=tmp_path/'bundle'
    copy_eg_source(src,out)
    assert (out/'.env.example').is_file()
    assert (out/'app/main.py').is_file()
    assert not (out/'.env').exists()
    assert not (out/'evidence').exists()
    assert not (out/'artifacts').exists()
    assert all('SECRET-CANARY' not in f.read_text() for f in out.rglob('*') if f.is_file())

def test_source_symlink_denied(tmp_path):
    src=tmp_path/'source'
    make_source(src)
    secret=tmp_path/'secret.py'
    secret.write_text('SENSITIVE')
    (src/'app/leak.py').symlink_to(secret)
    with pytest.raises(RuntimeError,match='EG_SOURCE_SYMLINK_DENIED'):
        copy_eg_source(src,tmp_path/'bundle')
