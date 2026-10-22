"""Protect generic EG core from accidental project/provider-specific assumptions."""
import re
from pathlib import Path

CORE = Path(__file__).resolve().parents[1] / 'app'
PROVIDERS = re.compile(r'\b(?:solana|rustc|cargo|scanner|github|cafe|espresso|browser|chrome|shopify|wordpress)\b', re.I)
PRIVATE_PATHS = ('/root/', '/content/', 'C:\\', '/home/ubuntu/')


def test_generic_core_has_no_project_provider_literals():
    matches = [(p.name, i, line.strip())
               for p in CORE.glob('*.py')
               for i, line in enumerate(p.read_text().splitlines(), 1)
               if PROVIDERS.search(line)]
    assert not matches, matches


def test_generic_core_has_no_personal_machine_paths():
    matches = [(p.name, i, line.strip())
               for p in CORE.glob('*.py')
               for i, line in enumerate(p.read_text().splitlines(), 1)
               if any(value in line for value in PRIVATE_PATHS)]
    assert not matches, matches
