"""Keep the active portable documentation honest and link-complete."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]


def test_operational_markdown_has_a_heading():
    for path in [ROOT/'README.md', ROOT/'SKILL.md', ROOT/'SECURITY.md',
                 ROOT/'eg/README.md', *(ROOT/'eg/docs').glob('*.md')]:
        content = path.read_text(encoding='utf-8')
        if path.name == 'SKILL.md':
            assert content.startswith('---\n') and '\n---\n# ' in content
        else:
            assert content.startswith('# '), path


def test_no_broken_local_markdown_links():
    for path in [ROOT/'README.md', ROOT/'SKILL.md', ROOT/'eg/README.md',
                 *(ROOT/'eg/docs').glob('*.md')]:
        content = path.read_text(encoding='utf-8')
        for match in re.finditer(r'\]\(([^)]+)\)', content):
            target = match.group(1).split('#', 1)[0].split('?', 1)[0]
            if not target or target.startswith(('https://', 'http://', 'mailto:', 'data:', '/')):
                continue
            destination = (path.parent / target).resolve()
            assert destination.is_relative_to(ROOT.resolve()) and destination.exists(), (
                path.relative_to(ROOT), target)


def test_active_guides_never_expose_internal_effect_class_codes():
    for name in ('README.md','SKILL.md','eg/README.md',
                 'eg/docs/PORTABLE_RUNBOOK.md','eg/docs/OPERATIONS.md',
                 'eg/docs/PRODUCTION_PROMOTION.md','eg/.env.example'):
        content = (ROOT/name).read_text(encoding='utf-8')
        assert not re.search(r'\bE[0-9]+\b', content), name
    # The immutable EXECUTOR_PROTOCOL.md is retained byte-for-byte for
    # existing audit-bound contracts, not presented as installation steps.


def test_current_entrypoints_do_not_require_retired_operator_workers():
    for name in ('README.md', 'SKILL.md', 'eg/README.md'):
        guide = (ROOT/name).read_text().splitlines()
        beginning = '\n'.join(guide[:25]).lower()
        assert 'register' in beginning and 'pre' in beginning
        assert 'post' in beginning and 'staging' in beginning
        assert 'provision/register/activate the **generic**' not in beginning
