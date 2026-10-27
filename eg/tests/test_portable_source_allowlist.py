"""Regression test for issue #11."""
import pytest
from tools.build_portable_bundle import (copy_eg_source, copy_public_root_docs,
                                         copy_public_context_docs, PORTABLE_CONTEXT_DOCS)

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


def test_ai_context_allowlist_bundles_only_nine_reviewed_docs(tmp_path):
    root = tmp_path / 'repo'
    context = root / 'docs/context'
    context.mkdir(parents=True)
    for name in PORTABLE_CONTEXT_DOCS:
        page = context / name
        page.parent.mkdir(parents=True, exist_ok=True)
        page.write_text('# Public ' + name, encoding='utf-8')
    (context/'private.key').write_text('SECRET-CANARY')
    (context/'runtime.env').write_text('SECRET-CANARY')
    (context/'unreviewed.md').write_text('SECRET-CANARY')
    (context/'data.db').write_text('SECRET-CANARY')
    dest = tmp_path / 'bundle'
    copy_public_context_docs(root, dest)
    out = dest / 'docs/context'
    files = {p.relative_to(out).as_posix() for p in out.rglob('*') if p.is_file()}
    assert files == set(PORTABLE_CONTEXT_DOCS)
    assert all('SECRET-CANARY' not in p.read_text() for p in out.rglob('*.md'))


def test_ai_context_missing_required_doc_fails_closed(tmp_path):
    root = tmp_path / 'repo'
    context = root / 'docs/context'
    context.mkdir(parents=True)
    for name in PORTABLE_CONTEXT_DOCS[1:]:
        page = context / name
        page.parent.mkdir(parents=True, exist_ok=True)
        page.write_text('# Public', encoding='utf-8')
    with pytest.raises(RuntimeError, match='MISSING_OR_UNSAFE_PUBLIC_CONTEXT_DOC'):
        copy_public_context_docs(root, tmp_path / 'bundle')


def test_ai_context_symlinked_doc_and_parent_denied(tmp_path):
    root = tmp_path / 'repo'
    context = root / 'docs/context'
    context.mkdir(parents=True)
    for name in PORTABLE_CONTEXT_DOCS:
        page = context / name
        page.parent.mkdir(parents=True, exist_ok=True)
        page.write_text('# Public', encoding='utf-8')
    target = tmp_path / 'secret.md'
    target.write_text('PRIVATE-CANARY')
    page = context / PORTABLE_CONTEXT_DOCS[0]
    page.unlink()
    page.symlink_to(target)
    with pytest.raises(RuntimeError, match='UNSAFE_PUBLIC_CONTEXT_SYMLINK'):
        copy_public_context_docs(root, tmp_path / 'bundle')

    page.unlink()
    page.write_text('# Public')
    parent = context / 'components'
    for child in parent.iterdir():
        child.unlink()
    parent.rmdir()
    parent.symlink_to(tmp_path / 'secret-dir')
    with pytest.raises(RuntimeError, match='UNSAFE_PUBLIC_CONTEXT_SYMLINK'):
        copy_public_context_docs(root, tmp_path / 'bundle2')


def test_ai_context_allowlist_covers_live_index():
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    files = {(p.relative_to(root/'docs/context')).as_posix()
             for p in (root/'docs/context').rglob('*.md')}
    assert files == set(PORTABLE_CONTEXT_DOCS)
