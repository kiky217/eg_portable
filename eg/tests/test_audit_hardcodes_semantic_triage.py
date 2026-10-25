"""#104: all tracked text scanned; AST sites and risk carry explicit uncertainty."""
import subprocess
from pathlib import Path
from tools.audit_hardcodes import _review, _literal_category, inventory, semantic_matrix, semantic_disposition


def test_provider_specific_token_in_core_is_high_risk_not_approved():
    row = _review('eg/app/main.py', 78, 'APP_SPECIFIC', 'github')
    assert row['risk'] == 'HIGH'
    assert row['action'] == 'REVIEW_PROVIDER_COUPLING_IN_CORE'
    assert row['review_status'] == 'SEMANTIC_REVIEW_REQUIRED'
    assert _review('eg/tools/trusted_process_catalog.py', 13, 'APP_SPECIFIC', 'github')['risk'] == 'LOW'


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



def test_full_matrix_is_source_sha_pinned_and_unsafe_core_provider_is_unknown(tmp_path):
    root=tmp_path/"project"
    (root/"eg/app").mkdir(parents=True)
    (root/"eg/app/main.py").write_text('VENDOR = "github"\nLIMIT = 64\n')
    subprocess.run(['git','init','-q',str(root)],check=True)
    subprocess.run(['git','-C',str(root),'add','.'],check=True)
    subprocess.run(['git','-C',str(root),'-c','user.name=Audit',
                    '-c','user.email=audit@example.invalid','commit','-qm','fixture'],check=True)
    inventory_result=inventory(root)
    matrix=semantic_matrix(inventory_result,root)
    assert len(matrix)==inventory_result['literal_sites_total']
    assert all(row['source_commit']==inventory_result['source_commit'] for row in matrix)
    assert all(row['file_sha256']==inventory_result['files'][0]['sha256'] for row in matrix)
    assert any(row['literal']=="'github'" and row['disposition']=="UNKNOWN"
               and row['risk']=="HIGH" for row in matrix)
    assert all(row['review_status']=="SOURCE_TRIAGE_NOT_SIGNOFF" for row in matrix)


def test_low_risk_scoped_review_never_masks_vendor_in_generic_core():
    generic={'origin':'GENERIC_EG_CORE','category':'UNKNOWN_REVIEW'}
    portable={'origin':'PORTABLE_OPERATIONS','category':'UNKNOWN_REVIEW'}
    assert semantic_disposition(generic)=='CONTRACT'
    assert semantic_disposition(portable)=='CONTRACT'
    assert semantic_disposition({**generic,'category':'APP_SPECIFIC'})=='UNKNOWN'
    assert semantic_disposition({**generic,'category':'SECURITY_REVIEW'})=='SECURITY_INVARIANT'


def test_inventory_rejects_staged_and_unstaged_worktree_changes(tmp_path):
    import pytest
    root = tmp_path / "source"
    root.mkdir()
    path = root / "main.py"
    path.write_text('VALUE = "canonical"\n')
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "add", "main.py"], check=True)
    subprocess.run(["git", "-C", str(root), "-c", "user.name=Audit",
                    "-c", "user.email=audit@example.invalid", "commit",
                    "-qm", "baseline"], check=True)
    head = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    assert inventory(root)["source_commit"] == head
    path.write_text('VALUE = "unstaged"\n')
    with pytest.raises(ValueError, match="SOURCE_TREE_DIFFERS_FROM_PINNED_HEAD"):
        inventory(root)
    subprocess.run(["git", "-C", str(root), "add", "main.py"], check=True)
    with pytest.raises(ValueError, match="SOURCE_TREE_DIFFERS_FROM_PINNED_HEAD"):
        inventory(root)


def test_inventory_rejects_tracked_symlink_outside_source(tmp_path):
    import pytest
    root = tmp_path / "source"
    root.mkdir()
    outside = tmp_path / "private-file.txt"
    outside.write_text("fixture-outside-repo\n")
    (root / "external.txt").symlink_to(outside)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "add", "external.txt"], check=True)
    subprocess.run(["git", "-C", str(root), "-c", "user.name=Audit",
                    "-c", "user.email=audit@example.invalid", "commit",
                    "-qm", "baseline"], check=True)
    with pytest.raises(ValueError, match="TRACKED_SYMLINK_CANNOT_BE_SOURCE_PINNED"):
        inventory(root)
