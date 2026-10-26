"""Read-only, provider-neutral host installation preflight.

No credentials or trust roots are generated. JSON output has stable check codes.
This tool does not admit actions or claim production readiness.
"""
from __future__ import annotations
import argparse
import base64
import binascii
import json
import os
import pathlib
import sys


def valid_public_key(value):
    if not value:
        return False
    try:
        return len(base64.b64decode(value, validate=True)) == 32
    except (ValueError, binascii.Error):
        return False


def inspect(root: pathlib.Path, environ=None):
    env = dict(os.environ if environ is None else environ)
    checks = []
    def check(code, ok, hint):
        checks.append({'code': code, 'pass': bool(ok), 'remediation': None if ok else hint})
    root = root.resolve()
    check('SOURCE', (root/'eg'/'VERSION').is_file() and (root/'SKILL.md').is_file(),
          'Install the complete canonical EG repository, not a partial source copy.')
    check('PYTHON', sys.version_info[:2] == (3, 12), 'Select a CPython 3.12 runtime.')
    state_name = env.get('EG_STATE_DIR', '')
    state = pathlib.Path(state_name).expanduser().resolve() if state_name else None
    check('EXTERNAL_STATE', bool(state and state != root and root not in state.parents),
          'Set EG_STATE_DIR outside the source directory on approved durable storage.')
    check('DURABLE_STATE_EXISTS', bool(state and state.is_dir()),
          'Initialize the persistent EG state using the canonical protected bootstrap.')
    check('HOST_IDENTITY', True, 'The portable gateway accepts root and non-root host identities.')
    mode = env.get('EVALUATION_GATEWAY_ADMISSION_MODE', 'enabled')
    check('MODE', mode in ('enabled', 'disabled'), 'Use enabled or explicit audit-only disabled.')
    notary = env.get('EG_NOTARY_PUBLIC_KEY_B64') or env.get('EVALUATION_GATEWAY_EVIDENCE_PUBLIC_KEY_B64')
    executor = env.get('EG_EXECUTOR_PUBLIC_KEY_B64') or env.get('EVALUATION_GATEWAY_EXECUTOR_PUBLIC_KEY_B64')
    check('NOTARY_ROOT', valid_public_key(notary),
          'Provide a valid independently administered 32-byte Ed25519 notary PUBLIC key.')
    check('EXECUTOR_ROOT', mode == 'disabled' or valid_public_key(executor),
          'Provision one reusable authorized worker and register its valid 32-byte Ed25519 PUBLIC key.')
    check('DISTINCT_TRUST_ROOTS', not executor or notary != executor,
          'Executor and evidence notary must use separate trusted signing identities.')
    check('FULL_ADMISSION', mode == 'enabled',
          'Audit-only mode is not operational effect admission; provision authenticated workers.')
    return {'status': 'PRECHECK_PASS' if all(x['pass'] for x in checks) else 'BLOCKED',
            'scope': 'PREREQUISITES_ONLY_NOT_LIVE_E2E', 'checks': checks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    result = inspect(args.root)
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] == 'PRECHECK_PASS' else 2


if __name__ == '__main__':
    raise SystemExit(main())
