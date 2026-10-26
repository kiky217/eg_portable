"""Idempotently ensure an existing portable EG gateway is serving on localhost.

Does not initialize identities, approve actions, or replace protected state.
"""
from __future__ import annotations
import argparse, hashlib, json, os, subprocess, sys, time, urllib.error, urllib.request
from pathlib import Path


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
    url = f'http://127.0.0.1:{port}/v1/protocol'
    def check():
        request = urllib.request.Request(url, headers={'X-Evaluation-Key': key})
        with urllib.request.urlopen(request, timeout=2) as response:
            result = json.load(response)
        if result.get('hash') != expected:
            raise RuntimeError('RUNNING_GATEWAY_PROTOCOL_MISMATCH')
        return True
    try:
        check()
        return {'status': 'LIVE', 'action': 'REUSED', 'port': port}
    except urllib.error.HTTPError as exc:
        raise RuntimeError('PORT_OCCUPIED_BY_UNEXPECTED_AUTHORITY') from exc
    except (urllib.error.URLError, TimeoutError, ConnectionError):
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
