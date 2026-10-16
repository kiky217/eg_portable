#!/usr/bin/env python3
"""Build relocation-tested offline EG portable Linux/amd64 distribution.

No live data, private keys, tokens, source workspace paths or Colab mounts are
included. Immutable tarball and SHA-256 manifest. Supports CPython 3.12 Linux
x86_64 matching the build ABI; no pip, network or apt needed to launch.
"""
from __future__ import annotations
import argparse,hashlib,json,os,platform,re,shutil,subprocess,tarfile,tempfile,time,sys,sysconfig
from pathlib import Path

# Paths resolve from THIS single EG package and its selected Python runtime.
STAGE=Path(__file__).resolve().parents[1]
WORK=Path(os.environ.get('EG_PORTABLE_OUTPUT_DIR', str(STAGE.parent/'dist'))).expanduser().resolve()
SITE=Path(sysconfig.get_path('purelib')).resolve()
SYSTEM_PY=Path(sys._base_executable).resolve()
SYSTEM_STDLIB=Path(sysconfig.get_path('stdlib')).resolve()
PY_RUNTIME=f'{sys.version_info.major}.{sys.version_info.minor}'
FILTER={'__pycache__','.pytest_cache','.git','_runtime','data','secrets',
        'notary','e2e-instance','worker','journals','outputs','.venv'}
EXCLUDE_SUFFIX={'.pyc','.pyo','.pem','.db','.sqlite','.sqlite3','.jsonl','.sock','.key','.p12'}
def copy_source(source,target,ignore_large=False):
    def ignore(dirname,names):
        denied={v for v in names if v in FILTER or Path(v).suffix in EXCLUDE_SUFFIX}
        if ignore_large:
            denied|={v for v in names if v in {'test','tests','ensurepip','idlelib','tkinter','turtledemo'}}
        return denied
    shutil.copytree(source,target,ignore=ignore,dirs_exist_ok=False,symlinks=False)

def write_text(path,data):
    path.write_text(data);path.chmod(0o644)
def filehash(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()

def main():
    if platform.system()!='Linux' or platform.machine()!='x86_64' or PY_RUNTIME!='3.12':
        raise RuntimeError('UNSUPPORTED_PORTABLE_BUILD_TARGET_LINUX_AMD64_CPYTHON312_ONLY')
    if not SYSTEM_PY.is_file() or not SITE.is_dir() or not SYSTEM_STDLIB.is_dir():
        raise RuntimeError('INCOMPLETE_PYTHON_RUNTIME')
    WORK.mkdir(parents=True,exist_ok=True)
    bundle=WORK/'eg-portable-3.1.0-linux-amd64'
    if bundle.exists():shutil.rmtree(bundle)
    bundle.mkdir()
    root=bundle
    (root/'python/bin').mkdir(parents=True)
    shutil.copy2(SYSTEM_PY,root/'python/bin/python3.12')
    (root/'python/bin/python3.12').chmod(0o755)
    copy_source(SYSTEM_STDLIB,root/'python/lib/python3.12',ignore_large=True)
    copy_source(SITE,root/'python/lib/python3.12/site-packages')
    copy_source(STAGE,root/'eg')
    (root/'THIRD_PARTY_LICENSES').mkdir(exist_ok=True)
    license_candidates=[Path(os.getenv('EG_PYTHON_LICENSE_FILE','/nonexistent')),
                        SYSTEM_STDLIB.parent.parent/'LICENSE',
                        Path('/usr/share/doc/python3.12/copyright')]
    copyright_source=next((q for q in license_candidates if q.is_file()),None)
    if copyright_source is None:
        raise RuntimeError('PYTHON_RUNTIME_LICENSE_FILE_REQUIRED_SET_EG_PYTHON_LICENSE_FILE')
    shutil.copy2(copyright_source,root/'THIRD_PARTY_LICENSES/CPython-3.12-license.txt')
    # Strip all runtime/test-only state including cached bytecode and collocated auth
    # state, leave only source/test code.
    launcher='''#!/bin/sh
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
export PYTHONHOME="$ROOT/python"
export PYTHONPATH="$ROOT/python/lib/python3.12/site-packages:$ROOT/eg"
exec "$ROOT/python/bin/python3.12" "$@"
'''
    write_text(root/'python.sh',launcher);(root/'python.sh').chmod(0o755)
    runner='''#!/bin/sh
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
[ -n "${EG_STATE_DIR:-}" ] || { echo "DENIED: EG_STATE_DIR must be explicitly set to durable storage" >&2; exit 77; }
[ -n "${EG_PORT:-}" ] || EG_PORT=18766
[ -d "$EG_STATE_DIR" ] || { echo "DENIED: state directory missing; initialize securely" >&2; exit 77; }
if [ "$(id -u)" -eq 0 ]; then
  echo "DENIED: portable EG API service cannot run as root" >&2
  exit 77
fi
export EVALUATION_GATEWAY_DB_PATH="$EG_STATE_DIR/data/gateway.db"
export EVALUATION_GATEWAY_ANCHOR_PATH="$EG_STATE_DIR/anchor/audit.anchor"
export EVALUATION_GATEWAY_EVIDENCE_ROOT="$EG_STATE_DIR/evidence"
export EVALUATION_GATEWAY_TRUSTED_EVIDENCE_UID="$(id -u)"
exec "$ROOT/python.sh" -m uvicorn app.main:app --app-dir "$ROOT/eg" --host 127.0.0.1 --port "$EG_PORT" --no-access-log
'''
    write_text(root/'run.sh',runner);(root/'run.sh').chmod(0o755)
    installer='''#!/bin/sh
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
if [ "$(id -u)" -eq 0 ]; then
  echo "DENIED: initialize and run as dedicated non-root user" >&2
  exit 77
fi
[ -n "${EG_STATE_DIR:-}" ] || { echo "DENIED: set EG_STATE_DIR to durable persistent storage" >&2; exit 77; }
[ -n "${EG_EXECUTOR_PUBLIC_KEY_B64:-}" ] || { echo "DENIED: externally administered executor root required" >&2; exit 77; }
if [ -e "$EG_STATE_DIR" ]; then
  echo "DENIED: refuse to overwrite existing state or identity" >&2
  exit 77
fi
mkdir -m 700 "$EG_STATE_DIR"
for dir in data anchor evidence; do mkdir -m 700 "$EG_STATE_DIR/$dir"; done
"$ROOT/python.sh" - <<'PY'
import base64,os,secrets
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption,PublicFormat
d=Path(os.environ['EG_STATE_DIR'])
# Operator-supplied remote executor root; no worker signing key generated here.
executor=os.environ.get('EG_EXECUTOR_PUBLIC_KEY_B64','')
if not executor:
    raise SystemExit('DENIED: independent executor public key required')
assert len(base64.b64decode(executor,validate=True))==32
priv=Ed25519PrivateKey.generate()
p=priv.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption())
key=d/'notary-private.pem'
f=key.open('xb');f.write(p);f.close();key.chmod(0o600)
pub=base64.b64encode(priv.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
assert executor != pub
values={'EVALUATION_GATEWAY_API_KEY':secrets.token_urlsafe(48),
'EVALUATION_GATEWAY_HITL_KEY':secrets.token_urlsafe(48),
'EVALUATION_GATEWAY_AUDIT_HMAC_KEY':secrets.token_urlsafe(48),
'EVALUATION_GATEWAY_EVIDENCE_PUBLIC_KEY_B64':pub,
'EVALUATION_GATEWAY_EXECUTOR_PUBLIC_KEY_B64':executor}
with (d/'runtime.env').open('x') as stream:
  for key,value in values.items():stream.write(key+'='+value+'\\n')
(d/'runtime.env').chmod(0o600)
print('STATE_INITIALIZED_SEPARATE_EXECUTOR_TRUST_ROOT_REQUIRED')
PY
'''
    write_text(root/'init.sh',installer);(root/'init.sh').chmod(0o755)
    envrunner='''#!/bin/sh
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
[ -n "${EG_STATE_DIR:-}" ] || exit 77
if [ ! -f "$EG_STATE_DIR/runtime.env" ]; then
  echo "DENIED: runtime credentials not initialized" >&2
  exit 77
fi
set -a
. "$EG_STATE_DIR/runtime.env"
set +a
exec "$ROOT/run.sh"
'''
    write_text(root/'start.sh',envrunner);(root/'start.sh').chmod(0o755)
    doc='''# EG Offline Portable 3.1.0 (Linux x86-64)

Relocatable bundled Python 3.12, stdlib, all pinned runtime libraries and EG source.
Requires Linux x86-64 ABI compatible with the build environment (glibc-compatible).
No pip/apt/network required to execute, but not a cross-OS executable.

Use as a **dedicated non-root identity**, and set EG_STATE_DIR to secure,
durable and separately backed-up storage. It MUST be outside this immutable
installation directory. The executor signing root must be independently
administered: supply its raw 32-byte Ed25519 public key via
EG_EXECUTOR_PUBLIC_KEY_B64. This package NEVER generates the executor private
key, and execution is fail-closed without a configured trust root.

  export EG_STATE_DIR=/durable/eg/state
  export EG_EXECUTOR_PUBLIC_KEY_B64=<remote-verified-base64-public-key>
  ./init.sh
  ./start.sh

Start binds 127.0.0.1:18766. State and evidence remain outside the release
directory; do not publish or back up secrets without encryption. FUSE/Colab
mounts may not safely implement SQLite WAL; use local filesystem + authenticated
external backups and restore validation. A durable-looking filesystem path is
not sufficient proof that state survives Colab teardown.

Host root can control local processes. Protected executor keys require a
separate host/security domain. This release does NOT imply universal enforcement
on shell commands or a fully production-safe deployment.

No secret/private-key/runtime data is included in the archive.
'''
    write_text(root/'README_PORTABLE.md',doc)
    # Manifest only for contents actually inside bundle; no secrets.
    files=sorted(x for x in root.rglob('*') if x.is_file())
    manifest={str(x.relative_to(root)):filehash(x) for x in files}
    write_text(root/'MANIFEST.json',json.dumps({'version':'3.1.0','platform':'linux-amd64',
      'build_python':'CPython 3.12','files':manifest},sort_keys=True,indent=2))
    archive=WORK/(bundle.name+'.tar.gz')
    import gzip
    def deterministic_header(info):
        info.mtime=0
        info.uid=info.gid=0
        info.uname=info.gname=''
        return info
    with archive.open('wb') as fp:
        with gzip.GzipFile(fileobj=fp,mode='wb',filename='',mtime=0,compresslevel=6) as zipped:
            with tarfile.open(fileobj=zipped,mode='w') as tar:
                tar.add(bundle,arcname=bundle.name,recursive=True,filter=deterministic_header)
    print(json.dumps({'archive':str(archive),'sha256':filehash(archive),
                      'size_bytes':archive.stat().st_size,'entries':len(files),
                      'uncompressed_bytes':sum(x.stat().st_size for x in files)}))
if __name__=='__main__':main()
