"""Idempotently ensure an existing portable EG gateway is serving on localhost.

Does not initialize identities, approve actions, or replace protected state.
"""
from __future__ import annotations
import argparse, hashlib, json, os, socket, subprocess, time, urllib.error, urllib.request
from dataclasses import asdict
from pathlib import Path
from tools.high_effect_admission import AdapterCapability
from tools.runtime_source_fingerprint import fingerprint as runtime_source_fingerprint


def ensure(bundle: Path, state: Path, port: int = 18766) -> dict:
    bundle = bundle.resolve(strict=True)
    state = state.resolve(strict=True)
    if not 1024 <= port <= 65535:
        raise ValueError('INVALID_PORT')
    env_file = state / 'runtime.env'
    if not env_file.is_file() or env_file.is_symlink():
        raise ValueError('STATE_NOT_INITIALIZED')
    config = dict(line.split('=', 1) for line in env_file.read_text().splitlines() if '=' in line)
    key = config.get('EVALUATION_GATEWAY_API_KEY')
    if not key:
        raise ValueError('NO_GATEWAY_API_KEY')
    expected = hashlib.sha256((bundle / 'eg' / 'docs' / 'EXECUTOR_PROTOCOL.md').read_bytes()).hexdigest()
    expected_runtime_sha = runtime_source_fingerprint(bundle / 'eg')
    url = f'http://127.0.0.1:{port}/v1/protocol'
    configured = json.loads(config.get('EVALUATION_GATEWAY_HIGH_EFFECT_CAPABILITIES_JSON') or '[]')
    if not isinstance(configured, list):
        raise ValueError('INVALID_CONFIGURED_CAPABILITY_CATALOG')
    def digest(cap):
        canonical = json.dumps(asdict(AdapterCapability(**cap)),
                               sort_keys=True, separators=(',', ':'), ensure_ascii=False)
        return hashlib.sha256(canonical.encode()).hexdigest()
    expected_caps = {
        (cap['adapter_id'], cap['action_type'], cap['effect_class'], digest(cap))
        for cap in configured
    }
    if len(expected_caps) != len(configured):
        raise ValueError('DUPLICATE_CONFIGURED_CAPABILITY')
    def check():
        headers = {'X-Evaluation-Key': key}
        request = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(request, timeout=2) as response:
            result = json.load(response)
        if result.get('hash') != expected:
            raise RuntimeError('RUNNING_GATEWAY_PROTOCOL_MISMATCH')
        if result.get('runtime_source_sha256') != expected_runtime_sha:
            raise RuntimeError('RUNNING_GATEWAY_RUNTIME_SOURCE_DRIFT_RESTART_REQUIRED')
        request = urllib.request.Request(f'http://127.0.0.1:{port}/v1/agent/capabilities', headers=headers)
        with urllib.request.urlopen(request, timeout=2) as response:
            live = json.load(response)
        actual_caps = {
            (item['adapter_id'], item['action_type'], item['effect_class'],
             item.get('capability_sha256'))
            for item in result.get('high_effect_capability_catalog', [])
        }
        listed = {
            (item['adapter_id'], item['action_type'], item['effect_class'])
            for item in live.get('capabilities', [])
            if item.get('effect_class') in ('E3', 'E4', 'E5')
        }
        if (live.get('admission_mode') != config.get('EVALUATION_GATEWAY_ADMISSION_MODE', 'enabled')
                or actual_caps != expected_caps
                or listed != {item[:3] for item in expected_caps}):
            raise RuntimeError('RUNNING_GATEWAY_CONFIG_DRIFT_RESTART_REQUIRED')
        return True
    try:
        check()
        return {'status': 'LIVE', 'action': 'REUSED', 'port': port}
    except urllib.error.HTTPError as exc:
        raise RuntimeError('PORT_OCCUPIED_BY_UNEXPECTED_AUTHORITY') from exc
    except (urllib.error.URLError, TimeoutError, ConnectionError):
        # A stalled authenticated endpoint may still own the listener. Avoid
        # duplicate gateway startup and preserve the original live lease.
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.5):
                raise RuntimeError('PORT_OCCUPIED_UNRESPONSIVE_NO_DUPLICATE_START')
        except OSError:
            pass
    log_path = state / 'gateway.log'
    env = dict(os.environ, EG_STATE_DIR=str(state), EG_PORT=str(port))
    with log_path.open('ab') as log:
        os.chmod(log_path, 0o600)
        child = subprocess.Popen([str(bundle / 'start.sh')], env=env, cwd=str(bundle),
                                 stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                 start_new_session=True, close_fds=True)
    for _ in range(100):
        if child.poll() is not None:
            raise RuntimeError(f'GATEWAY_EXITED_{child.returncode}')
        try:
            check()
            return {'status': 'LIVE', 'action': 'STARTED', 'port': port, 'pid': child.pid}
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            time.sleep(.1)
    child.terminate()
    raise RuntimeError('GATEWAY_START_TIMEOUT')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--port', type=int, default=18766)
    args = parser.parse_args()
    print(json.dumps(ensure(args.bundle, args.state, args.port), sort_keys=True))


if __name__ == '__main__':
    main()
