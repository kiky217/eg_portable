"""Activate a pre-provisioned generic catalog using independent operator trust.

No credentials or signing keys are generated here. A trusted administrator must
first run operator_first_run, start the separately owned worker and HITL signer,
and pin the gateway high-effect trust roots. Activation is NOT canonical PRE.
"""
from __future__ import annotations
import argparse
import json
import os
import stat
from pathlib import Path
from tools.operator_adapter_binding import verify_operator_binding
from tools.operator_runtime_registry import OperatorAdapterRegistry
from tools.adapter_liveness import probe_unix


def _read_regular(path: Path, *, uid: int | None = None) -> bytes:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
        (uid is not None and info.st_uid != uid) or
        stat.S_IMODE(info.st_mode) & 0o022):
        raise ValueError('UNTRUSTED_OPERATOR_METADATA')
    return path.read_bytes()


def activate(root: Path, *, mode: str = 'inspect') -> dict:
    root = Path(root)
    ri = root.lstat()
    if (not root.is_absolute() or not stat.S_ISDIR(ri.st_mode) or
        ri.st_uid != 0 or stat.S_IMODE(ri.st_mode) & 0o022):
        raise ValueError('UNTRUSTED_INSTALLATION_ROOT')
    parent_info = root.parent.lstat()
    if (not stat.S_ISDIR(parent_info.st_mode) or
        parent_info.st_uid != 0 or stat.S_IMODE(parent_info.st_mode) & 0o022):
        raise ValueError('UNTRUSTED_OPERATOR_PARENT')
    if os.geteuid() == 0:
        raise ValueError('INDEPENDENT_NONROOT_CONTROLLER_REQUIRED')
    pin = root/'operator-public-key.b64'
    info = pin.lstat()
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o444:
        raise ValueError('ROOT_PINNED_OPERATOR_ROOT_REQUIRED')
    trusted_key = _read_regular(pin, uid=0).decode('ascii').strip()
    registry = root/'registry'
    public = json.loads(_read_regular(registry/'public.json', uid=os.geteuid()))
    binding = json.loads(_read_regular(registry/'binding.json', uid=os.geteuid()))
    if public.get('operator_public_key_b64') != trusted_key:
        raise ValueError('OPERATOR_PUBLIC_KEY_PIN_MISMATCH')
    cap = public.get('capability', {})
    adapter_id, capsha = public['adapter_id'], public['capability_sha256']
    if (cap.get('adapter_id') != adapter_id or
        cap.get('effect_class') not in ('E3','E4','E5')):
        raise ValueError('UNTRUSTED_TYPED_CAPABILITY')
    approved = verify_operator_binding(binding,
        operator_public_key_b64=trusted_key,
        adapter_id=adapter_id, capability_sha256=capsha)
    probe_unix(approved['socket_path'], adapter_id=adapter_id,
        capability_sha256=capsha,
        public_key_b64=approved['worker_public_key_b64'],
        task_id='operator-onboarding', step_key='00.01',
        gate_checkpoint_no=1, action_fingerprint=capsha,
        expected_worker_uid=approved['worker_uid'])
    state = 'SIGNED_BINDING_AND_LIVE_WORKER_VALID'
    if mode == 'activate':
        registry_db = OperatorAdapterRegistry(registry, trusted_key)
        state = registry_db.activate(binding, adapter_id=adapter_id,
                                     capability_sha256=capsha)['status']
    elif mode == 'verify':
        registry_db = OperatorAdapterRegistry(registry, trusted_key, read_only=True)
        registry_db.resolve(adapter_id)
        state = 'REGISTRY_ACTIVE_AND_WORKER_LIVE'
    elif mode != 'inspect':
        raise ValueError('UNKNOWN_MODE')
    return {'status': state, 'adapter_id': adapter_id,
            'effect_class': cap['effect_class'],
            'action_type': cap['action_type'],
            'operator_binding_verified': True, 'worker_liveness_verified': True,
            'independent_hitl_runtime_verified': False,
            'canonical_pre_post_verified': False,
            'admission': False,
            'next_action': 'VERIFY_SIGNER_AND_GATEWAY_PRE_RECEIPT_POST'}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('operator_install_root', type=Path)
    p.add_argument('--mode', choices=('inspect','activate','verify'), default='inspect')
    args = p.parse_args()
    try:
        print(json.dumps(activate(args.operator_install_root,mode=args.mode),sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({'status': 'NOT_ADMITTED',
                          'reason':type(exc).__name__+':'+str(exc),
                          'admission':False},sort_keys=True))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
