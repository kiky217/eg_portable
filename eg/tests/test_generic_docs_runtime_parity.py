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
    # Historical protocol versions stay in Git history; this document is current.




def test_all_markdown_guides_exclude_retired_effect_codes():
    """No historical class codes in any shipped Markdown documentation."""
    for path in (ROOT/'README.md', ROOT/'SKILL.md', ROOT/'SECURITY.md',
                 ROOT/'eg/README.md', *(ROOT/'eg/docs').glob('*.md')):
        text=path.read_text(encoding='utf-8')
        assert not re.search(r'\bE[0-9]+\b', text), path


def test_historical_contract_resumes_without_replacing_original_digest():
    protocol=(ROOT/'eg/docs/EXECUTOR_PROTOCOL.md').read_text(encoding='utf-8')
    assert 'original protocol hash authenticated' in protocol
    assert 'Git history' in protocol
    assert 'New tasks MUST bind the current digest' in protocol
    assert 'historical task, evidence or ledger entry is rewritten' in (ROOT/'eg/docs/PORTABLE_RUNBOOK.md').read_text(encoding='utf-8')


def test_installation_guides_agree_on_worker_identity_and_audit_only_mode():
    skill=(ROOT/'SKILL.md').read_text(encoding='utf-8')
    ops=(ROOT/'eg/docs/OPERATIONS.md').read_text(encoding='utf-8')
    runbook=(ROOT/'eg/docs/PORTABLE_RUNBOOK.md').read_text(encoding='utf-8')
    assert 'audit-only `disabled` installation' in skill
    assert 'accepts an absent executor root' in skill
    for doc in (ops,runbook):
        assert 'root or non-root' in doc
    assert 'REGISTER' in runbook and 'POST' in runbook and 'staging' in runbook

def test_current_entrypoints_do_not_require_retired_operator_workers():
    for name in ('README.md', 'SKILL.md', 'eg/README.md'):
        guide = (ROOT/name).read_text().splitlines()
        beginning = '\n'.join(guide[:25]).lower()
        assert 'register' in beginning and 'pre' in beginning
        assert 'post' in beginning and 'staging' in beginning
        assert 'provision/register/activate the **generic**' not in beginning


def test_documented_local_python_commands_exist():
    guides = [ROOT/'README.md', ROOT/'SKILL.md', ROOT/'eg/README.md',
              *(ROOT/'eg/docs').glob('*.md')]
    for guide in guides:
        for relative in re.findall(r'(?:eg/)?(?:tools|tests)/[\w./-]+\.py',
                                   guide.read_text(encoding='utf-8')):
            source = ROOT/relative if relative.startswith('eg/') else ROOT/'eg'/relative
            assert source.is_file(), (guide.relative_to(ROOT), relative)


def test_no_retired_installation_paths_in_docs_or_ci():
    assert not (ROOT/'eg/tools/run_remedial_e2e.py').exists()
    assert not (ROOT/'eg/docker-compose.external-adapter.yml').exists()
    text = '\n'.join(p.read_text(encoding='utf-8')
                     for p in [ROOT/'README.md', ROOT/'SKILL.md', ROOT/'eg/README.md',
                               ROOT/'.github/workflows/release-validation.yml',
                               *(ROOT/'eg/docs').glob('*.md')])
    for obsolete in ('run_remedial_e2e.py', 'run_trusted_e2e.py',
                     'docker-compose.external-adapter.yml'):
        assert obsolete not in text, obsolete


def test_hash_bound_protocol_is_not_presented_as_installer():
    assert 'hash-bound' in (ROOT/'eg/docs/PORTABLE_RUNBOOK.md').read_text().lower()
    assert 'previous contracts remain in Git history' in (ROOT/'README.md').read_text()


def test_docker_image_has_all_gateway_runtime_modules():
    dockerfile = (ROOT/'eg/Dockerfile').read_text(encoding='utf-8')
    for name in ('high_effect_admission', 'signed_hitl_approval', 'adapter_liveness',
                 'runtime_source_fingerprint', 'capability_catalog',
                 'operator_runtime_registry', 'operator_adapter_binding'):
        assert f'tools/{name}.py' in dockerfile, name


def test_portable_host_identity_is_not_restricted_to_one_uid():
    from tools import rehearse_ledger_migration as rehearsal
    source = Path(rehearsal.__file__).read_text(encoding="utf-8")
    assert "STAGED_EG_MUST_USE_NONROOT_UID" not in source
    assert "HOST_CANNOT_SWITCH_TO_REQUESTED_IDENTITY" in source

    compose = (ROOT/"eg/docker-compose.yml").read_text(encoding="utf-8")
    docker = (ROOT/"eg/Dockerfile").read_text(encoding="utf-8")
    for setting in ("EVALUATION_GATEWAY_UID:-10001",
                    "EVALUATION_GATEWAY_GID:-10001",
                    "EVALUATION_GATEWAY_PORT:-18765",
                    "EVALUATION_GATEWAY_EVIDENCE_HOST_DIR"):
        assert setting in compose
    assert "EVALUATION_GATEWAY_TRUSTED_EVIDENCE_UID:-" + chr(36) + "{EVALUATION_GATEWAY_UID:-10001}" in compose
    assert "ARG EVALUATION_GATEWAY_IMAGE_USER=gateway" in docker
    assert "USER " + chr(36) + "{EVALUATION_GATEWAY_IMAGE_USER}" in docker
    for document in (ROOT/"README.md", ROOT/"SKILL.md",
                     ROOT/"eg/docs/OPERATIONS.md", ROOT/"eg/docs/PORTABLE_RUNBOOK.md"):
        assert "concurrent" in document.read_text(encoding="utf-8").lower(), document
    assert "same database" in (ROOT/"eg/docs/PORTABLE_RUNBOOK.md").read_text()


def test_no_numbered_effect_class_identifiers_in_active_repo():
    """Capabilities are described by their operations, not ordinal codes."""
    import re
    for path in ROOT.rglob("*"):
        if not path.is_file() or ".git" in path.parts:
            continue
        if path.suffix not in (".py", ".md", ".yml", ".yaml", ".toml", ".json", ".sh"):
            continue
        if path.name in ("requirements.lock",):
            continue
        content = path.read_text(encoding="utf-8")
        assert not re.search(r"\be[0-9]{1,2}(?=\b|[_-])", content, re.IGNORECASE), path
