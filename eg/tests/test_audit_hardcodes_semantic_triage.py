"""#104: all tracked text scanned; AST sites and risk carry explicit uncertainty."""
import subprocess
from pathlib import Path
from tools.audit_hardcodes import _review, _literal_category, inventory


def test_provider_specific_token_in_core_is_high_risk_not_approved():
    row = _review('eg/app/main.py', 78, 'APP_SPECIFIC', 'github')
    assert row['risk'] == 'HIGH'
    assert row['action'] == 'REVIEW_PROVIDER_COUPLING_IN_CORE'
    assert row['review_status'] == 'SEMANTIC_REVIEW_REQUIRED'
    assert _review('eg/tools/github_effect_scope.py', 13, 'APP_SPECIFIC', 'github')['risk'] == 'LOW'


def test_literal_and_security_triage_do_not_misreport_manual_completion():
    assert _literal_category('github') == 'APP_SPECIFIC'
    assert _literal_category('nonce') == 'SECURITY_REVIEW'
    assert _literal_category(524288) == 'PORTABLE_DEFAULT_REVIEW'
    assert _literal_category('arbitrary-message') == 'UNKNOWN_REVIEW'


def test_readonly_full_tracked_source_and_ast_site_inventory(tmp_path):
    root = tmp_path / 'source'
    (root / 'eg' / 'app').mkdir(parents=True)
    (root / 'eg' / 'tools').mkdir(parents=True)
    (root / 'eg' / 'app' / 'main.py').write_text(
        'SOURCE = "github"\nTIMEOUT = 60\nnonce = "signed-nonce"\n')
    (root / 'eg' / 'tools' / 'helper.py').write_text('LIMIT = 3\n')
    (root / 'README.md').write_text('Stable version: 1\n')
    subprocess.run(['git', 'init', '-q', str(root)], check=True)
    subprocess.run(['git', '-C', str(root), 'add', '.'], check=True)
    subprocess.run(['git', '-C', str(root), '-c', 'user.name=Test',
                    '-c', 'user.email=test@example.invalid',
                    'commit', '-q', '-m', 'fixture'], check=True)
    state_before = subprocess.check_output(['git', '-C', str(root), 'status', '--porcelain'])
    report = inventory(root)
    assert report['files_total'] == 3
    assert report['files_scanned'] == 3
    assert report['source_commit'] == subprocess.check_output(
        ['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
    assert report['semantic_review_complete'] is False
    assert any(site['literal'] == "'github'" and site['origin'] == 'GENERIC_EG_CORE'
               and site['risk'] == 'HIGH' for site in report['literal_sites'])
    assert any(site['category'] == 'PORTABLE_DEFAULT_REVIEW'
               for site in report['literal_sites'])
    assert all(row['review_status'] == 'SEMANTIC_REVIEW_REQUIRED'
               for row in report['candidates'] + report['literal_sites'])
    assert subprocess.check_output(['git', '-C', str(root), 'status', '--porcelain']) == state_before
