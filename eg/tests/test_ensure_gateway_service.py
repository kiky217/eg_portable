"""Gateway restart helper must never duplicate a verified live instance."""
import hashlib
import io
import json
import pytest
from tools.ensure_gateway_service import ensure


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
        return io.BytesIO(json.dumps({'hash': expected}).encode())
    monkeypatch.setattr('urllib.request.urlopen', respond)
    monkeypatch.setattr('subprocess.Popen', lambda *a, **kw: pytest.fail('duplicate launch'))
    assert ensure(bundle, state, 18766)['action'] == 'REUSED'


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
