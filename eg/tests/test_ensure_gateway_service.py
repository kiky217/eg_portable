"""Gateway restart helper must never duplicate a verified live instance."""
import base64
import hashlib
import io
import json
import pytest
from tools.ensure_gateway_service import ensure
from tools.high_effect_admission import AdapterCapability
from dataclasses import asdict


def sample_cap(public_key=None):
    if public_key is None:
        public_key = base64.b64encode(b'x'*32).decode()
    return {'adapter_id':'trusted-adapter-a','action_type':'bounded_process_run',
            'effect_class':'E3','target_prefix':'/tasks/a/',
            'maximum_payload_bytes':4096,'isolated':True,
            'public_key_b64':public_key,'ci_only':False}


def test_live_gateway_is_reused_without_spawn(tmp_path, monkeypatch):
    bundle = tmp_path / 'bundle'
    protocol = bundle / 'eg' / 'docs' / 'EXECUTOR_PROTOCOL.md'
    protocol.parent.mkdir(parents=True)
    protocol.write_text('protocol')
    state = tmp_path / 'state'
    state.mkdir()
    (state / 'runtime.env').write_text('EVALUATION_GATEWAY_API_KEY=private-test-key\n')
    expected = hashlib.sha256(b'protocol').hexdigest()
    def respond(request, timeout):
        assert request.get_header('X-evaluation-key') == 'private-test-key'
        if request.full_url.endswith('/v1/protocol'):
            return io.BytesIO(json.dumps({'hash': expected}).encode())
        assert request.full_url.endswith('/v1/agent/capabilities')
        return io.BytesIO(json.dumps({'admission_mode': 'enabled', 'capabilities': []}).encode())
    monkeypatch.setattr('urllib.request.urlopen', respond)
    monkeypatch.setattr('subprocess.Popen', lambda *a, **kw: pytest.fail('duplicate launch'))
    assert ensure(bundle, state, 18766)['action'] == 'REUSED'


@pytest.mark.parametrize('reported,configured', [
    ([], [sample_cap()]),
    ([sample_cap()], []),
])
def test_catalog_drift_refuses_false_reuse(tmp_path, monkeypatch, reported, configured):
    bundle = tmp_path / 'bundle'
    proto = bundle / 'eg' / 'docs' / 'EXECUTOR_PROTOCOL.md'
    proto.parent.mkdir(parents=True)
    proto.write_text('protocol')
    state = tmp_path / 'state'
    state.mkdir()
    (state / 'runtime.env').write_text(
        'EVALUATION_GATEWAY_API_KEY=private-test-key\n'
        'EVALUATION_GATEWAY_ADMISSION_MODE=enabled\n'
        'EVALUATION_GATEWAY_HIGH_EFFECT_CAPABILITIES_JSON='
        + json.dumps(configured) + '\n'
    )
    expected = hashlib.sha256(b'protocol').hexdigest()
    def respond(request, timeout):
        result = ({'hash': expected} if request.full_url.endswith('/v1/protocol')
                  else {'admission_mode': 'enabled', 'capabilities': reported})
        return io.BytesIO(json.dumps(result).encode())
    monkeypatch.setattr('urllib.request.urlopen', respond)
    monkeypatch.setattr('subprocess.Popen', lambda *a, **kw: pytest.fail('unexpected spawn'))
    with pytest.raises(RuntimeError, match='CONFIG_DRIFT_RESTART_REQUIRED'):
        ensure(bundle, state)



@pytest.mark.parametrize('changed', [None, 'public_key_b64', 'target_prefix', 'maximum_payload_bytes'])
def test_exact_catalog_fingerprint_required_for_reuse(tmp_path, monkeypatch, changed):
    bundle = tmp_path / 'bundle'
    protocol = bundle / 'eg' / 'docs' / 'EXECUTOR_PROTOCOL.md'
    protocol.parent.mkdir(parents=True)
    protocol.write_text('protocol')
    state = tmp_path / 'state'
    state.mkdir()
    original = sample_cap()
    configured = dict(original)
    if changed == 'public_key_b64':
        configured[changed] = base64.b64encode(b'y'*32).decode()
    elif changed == 'target_prefix':
        configured[changed] = '/tasks/changed/'
    elif changed == 'maximum_payload_bytes':
        configured[changed] = 2048
    (state / 'runtime.env').write_text(
        'EVALUATION_GATEWAY_API_KEY=private-test-key\n'
        'EVALUATION_GATEWAY_ADMISSION_MODE=enabled\n'
        'EVALUATION_GATEWAY_HIGH_EFFECT_CAPABILITIES_JSON='
        + json.dumps([configured]) + '\n'
    )
    digest = hashlib.sha256(json.dumps(asdict(AdapterCapability(**original)),
        sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
    def respond(request, timeout):
        payload = ({'hash': hashlib.sha256(b'protocol').hexdigest(),
                    'high_effect_capability_catalog': [{
                        'adapter_id': original['adapter_id'],
                        'action_type': original['action_type'],
                        'effect_class': original['effect_class'],
                        'capability_sha256': digest
                    }]}
                   if request.full_url.endswith('/v1/protocol')
                   else {'admission_mode': 'enabled', 'capabilities': [original]})
        return io.BytesIO(json.dumps(payload).encode())
    monkeypatch.setattr('urllib.request.urlopen', respond)
    monkeypatch.setattr('subprocess.Popen', lambda *a, **kw: pytest.fail('unexpected restart'))
    if changed is None:
        assert ensure(bundle, state)['action'] == 'REUSED'
    else:
        with pytest.raises(RuntimeError, match='CONFIG_DRIFT_RESTART_REQUIRED'):
            ensure(bundle, state)


def test_bad_port_denied_before_reading_state(tmp_path):
    with pytest.raises(ValueError, match='INVALID_PORT'):
        ensure(tmp_path, tmp_path, 12)


def test_missing_state_denied(tmp_path):
    bundle = tmp_path / 'bundle'
    bundle.mkdir()
    state = tmp_path / 'state'
    state.mkdir()
    with pytest.raises(ValueError, match='STATE_NOT_INITIALIZED'):
        ensure(bundle, state)
