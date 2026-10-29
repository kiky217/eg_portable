"""The active guides must describe EG-gated work, including staging."""
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[2]
ACTIVE_GUIDES = ('SKILL.md','README.md','eg/README.md','eg/docs/PORTABLE_RUNBOOK.md')

@pytest.mark.parametrize('name',ACTIVE_GUIDES)
def test_canonical_guides_require_ordered_verification(name):
    document = (ROOT/name).read_text(encoding='utf-8')
    first = document[:3500].lower()
    for phrase in ('register','pre','post','verified','staging'):
        assert phrase in first, (name,phrase)
    assert 'numbered process catalog workers' not in first
    assert 'inventory **numbered classes**' not in first
