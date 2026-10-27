"""Generic installer preflight cannot mistake audit-only or source presence for readiness."""
from tools.install_preflight import inspect


def test_missing_authority_is_specific(tmp_path):
    (tmp_path/'eg').mkdir()
    (tmp_path/'eg'/'VERSION').write_text('3.1.133')
    (tmp_path/'SKILL.md').write_text('contract')
    result = inspect(tmp_path, {'EG_STATE_DIR': str(tmp_path/'state')})
    assert result['status'] == 'BLOCKED'
    codes = {item['code']: item for item in result['checks']}
    assert codes['SOURCE']['pass']
    assert not codes['DURABLE_STATE_EXISTS']['pass']
    assert not codes['NOTARY_ROOT']['pass']
    assert not codes['EXECUTOR_ROOT']['pass']
    assert result['scope'] == 'PREREQUISITES_ONLY_NOT_LIVE_E2E'


def test_audit_only_is_not_full_readiness(tmp_path):
    state = tmp_path/'state'
    state.mkdir()
    (tmp_path/'eg').mkdir()
    (tmp_path/'eg'/'VERSION').write_text('3.1.133')
    (tmp_path/'SKILL.md').write_text('contract')
    result = inspect(tmp_path, {'EG_STATE_DIR': str(state),
                                 'EVALUATION_GATEWAY_ADMISSION_MODE': 'disabled',
                                 'EG_NOTARY_PUBLIC_KEY_B64': 'public-key-present'})
    codes = {item['code']: item for item in result['checks']}
    assert codes['EXECUTOR_ROOT']['pass']
    assert not codes['FULL_ADMISSION']['pass']
    assert result['status'] == 'BLOCKED'


def test_state_inside_source_rejected(tmp_path):
    (tmp_path/'eg').mkdir()
    (tmp_path/'eg'/'VERSION').write_text('3.1.133')
    (tmp_path/'SKILL.md').write_text('contract')
    result = inspect(tmp_path, {'EG_STATE_DIR': str(tmp_path/'state')})
    assert not next(x for x in result['checks'] if x['code']=='EXTERNAL_STATE')['pass']
