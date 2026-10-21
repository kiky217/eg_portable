"""A single agent may request only bounded, flat project files in local E2E."""
import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT=Path(__file__).resolve().parents[1] / 'tools' / 'local_project_e2e.py'
SPEC=importlib.util.spec_from_file_location('local_project_e2e',SCRIPT)
module=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def test_valid_website_manifest(tmp_path):
    f=tmp_path/'project.json'
    f.write_text(json.dumps({'name':'cafe','files':{'index.html':'<h1>Cafe</h1>',
                                                 'menu.json':'[{"price":20000}]'}}))
    assert module.validated_files(f)==[('index.html',b'<h1>Cafe</h1>'),
                                     ('menu.json',b'[{"price":20000}]')]


@pytest.mark.parametrize('name', ['../escape.html','folder/page.html','/etc/passwd',
                                   '.env','bad.sh','C:\\windows.js','index.HTML'])
def test_project_manifest_rejects_unsafe_paths_and_suffixes(tmp_path,name):
    f=tmp_path/'project.json'
    f.write_text(json.dumps({'name':'cafe','files':{name:'abc'}}))
    with pytest.raises(ValueError,match='UNSAFE_PROJECT_FILE'):
        module.validated_files(f)


def test_project_manifest_invalid_json_file(tmp_path):
    f=tmp_path/'project.json'
    f.write_text(json.dumps({'name':'cafe','files':{'menu.json':'{oops'}}))
    with pytest.raises(ValueError):module.validated_files(f)


def test_manifest_import_does_not_start_or_provision_worker():
    assert 'run_trusted_e2e' not in module.__dict__
