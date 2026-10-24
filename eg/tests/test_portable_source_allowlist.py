"""Regression test for issue #11."""
import pytest
from tools.build_portable_bundle import copy_eg_source, copy_public_root_docs

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


def test_portable_root_operational_docs_included_without_runtime_secrets(tmp_path):
    source=tmp_path/'source'
    source.mkdir()
    for name in ('README.md','SKILL.md','SECURITY.md','LICENSE'):
        (source/name).write_text('PUBLIC DOC '+name)
    (source/'runtime.env').write_text('PRIVATE-CANARY')
    (source/'notary.key').write_text('PRIVATE-CANARY')
    out=tmp_path/'dist'
    out.mkdir()
    copy_public_root_docs(source,out)
    assert {p.name for p in out.iterdir()} == {'README.md','SKILL.md','SECURITY.md','LICENSE'}
    assert all('PRIVATE-CANARY' not in p.read_text() for p in out.iterdir())


def test_portable_root_docs_reject_symlinks(tmp_path):
    source=tmp_path/'source'
    source.mkdir()
    out=tmp_path/'dist'
    out.mkdir()
    for name in ('README.md','SKILL.md','SECURITY.md','LICENSE'):
        (source/name).write_text('PUBLIC')
    (source/'SKILL.md').unlink()
    (source/'SKILL.md').symlink_to(tmp_path/'secret')
    try:
        copy_public_root_docs(source,out)
    except RuntimeError as exc:
        assert 'MISSING_OR_UNSAFE_PUBLIC_ROOT_DOC SKILL.md' in str(exc)
    else:
        raise AssertionError('ROOT_DOC_SYMLINK_NOT_DENIED')


def test_source_public_docs_and_explicit_assets_are_packaged_in_bundle():
    from pathlib import Path
    from tools import build_portable_bundle as bundle
    base=Path(bundle.__file__).resolve().parents[2]
    for name in bundle.PORTABLE_ROOT_DOCS:
        assert (base/name).is_file()
    for name in ('eg-step-review.svg','eg-workflow.svg'):
        assert (base/'eg/docs/assets'/name).is_file()
