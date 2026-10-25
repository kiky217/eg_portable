"""Protect generic EG core from accidental project/provider-specific assumptions."""
import re
from pathlib import Path

CORE = Path(__file__).resolve().parents[1] / 'app'
PROVIDERS = re.compile(r'\b(?:knid|solana|rustc|cargo|scanner|github|cafe|espresso|browser|chrome|shopify|wordpress)\b', re.I)
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


def test_generic_operations_ship_without_provider_specific_executor_modules():
    tools = Path(__file__).resolve().parents[1] / "tools"
    explicit = [
        p.name for p in tools.glob("*.py")
        if p.name.startswith("github_")
        or p.name in ("trusted_github_effect.py", "staging_site_service.py",
                      "local_project_e2e.py")
    ]
    assert explicit == [], explicit
    assert (tools/"trusted_process_catalog.py").is_file()
    assert (tools/"governed_agent_dispatcher.py").is_file()
