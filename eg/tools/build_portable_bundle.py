#!/usr/bin/env python3
"""Build relocation-tested offline EG portable Linux/amd64 distribution.

No live data, private keys, tokens, source workspace paths or Colab mounts are
included. Immutable tarball and SHA-256 manifest. Supports CPython 3.12 Linux
x86_64 matching the build ABI; no pip, network or apt needed to launch.
"""
from __future__ import annotations
import hashlib,json,os,platform,re,shutil,subprocess,tarfile,sys,sysconfig
from pathlib import Path
from license_compliance import (wheel_closure, prune_optional_gnu_extensions,
                                native_notice, publish_notice_index,
                                verify_bundled_notices)

# Paths resolve from THIS single EG package and its selected Python runtime.
STAGE=Path(__file__).resolve().parents[1]
RELEASE_VERSION=(STAGE/'VERSION').read_text().strip()
if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',RELEASE_VERSION):
    raise RuntimeError('STABLE_RELEASE_VERSION_REQUIRED')
WORK=Path(os.environ.get('EG_PORTABLE_OUTPUT_DIR', str(STAGE.parent/'dist'))).expanduser().resolve()
SITE=Path(sysconfig.get_path('purelib')).resolve()
SYSTEM_PY=Path(sys._base_executable).resolve()
SYSTEM_STDLIB=Path(sysconfig.get_path('stdlib')).resolve()
PY_RUNTIME=f'{sys.version_info.major}.{sys.version_info.minor}'
FILTER={'__pycache__','.pytest_cache','.git','_runtime','data','secrets',
        'notary','e2e-instance','worker','journals','outputs','.venv'}
EXCLUDE_SUFFIX={'.pyc','.pyo','.pem','.db','.sqlite','.sqlite3','.jsonl','.sock','.key','.p12'}
EXCLUDE_NAMES={'.env','runtime.env','.env.local','.npmrc','.pypirc','id_rsa','id_ed25519'}
def copy_source(source,target,ignore_large=False,merge=False):
    def ignore(dirname,names):
        denied={v for v in names if v in FILTER or v in EXCLUDE_NAMES or Path(v).suffix in EXCLUDE_SUFFIX}
        if ignore_large:
            denied|={v for v in names if v in {'test','tests','ensurepip','idlelib','tkinter','turtledemo','site-packages'}}
        return denied
    shutil.copytree(source,target,ignore=ignore,dirs_exist_ok=merge,symlinks=False)

# Public source allowlist: never bundle runtime evidence, credentials, backups,
# arbitrary source sidecars, or symlinks.
EG_PUBLIC_FILES={'VERSION','LICENSE','README.md','Dockerfile','docker-compose.yml',
                 'requirements.txt','requirements.lock','.env.example'}
EG_PUBLIC_DIRS={'app':{'.py','.json'},'tools':{'.py'},
                'tests':{'.py'},'docs':{'.md','.json'}}
def copy_eg_source(source,target):
    target.mkdir()
    for name in sorted(EG_PUBLIC_FILES):
        f=source/name
        if not f.is_file() or f.is_symlink():
            raise RuntimeError('MISSING_OR_UNSAFE_EG_SOURCE '+name)
        shutil.copy2(f,target/name)
    for dirname,suffixes in EG_PUBLIC_DIRS.items():
        directory=source/dirname
        if not directory.is_dir() or directory.is_symlink():
            raise RuntimeError('MISSING_OR_UNSAFE_EG_DIRECTORY '+dirname)
        for f in sorted(directory.rglob('*')):
            if f.is_symlink():
                raise RuntimeError('EG_SOURCE_SYMLINK_DENIED '+str(f.relative_to(source)))
            if not f.is_file() or f.name.startswith('.') or f.suffix not in suffixes:
                continue
            out=target/f.relative_to(source)
            out.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(f,out)

# Root documentation is public and referenced by eg/README.md and eg/docs.
# Shipping only eg/ breaks the SKILL and main README links after relocation.
PORTABLE_ROOT_DOCS=('README.md','SKILL.md','SECURITY.md','LICENSE')
def copy_public_root_docs(source_root,target_root):
    for name in PORTABLE_ROOT_DOCS:
        f=source_root/name
        if not f.is_file() or f.is_symlink():
            raise RuntimeError('MISSING_OR_UNSAFE_PUBLIC_ROOT_DOC '+name)
        shutil.copy2(f,target_root/name)

# Only explicitly reviewed AI context files are public portable docs. Never recurse
# blindly over docs/context: sidecars may hold private runtime/task material.
PORTABLE_CONTEXT_DOCS = (
    'project-overview.md',
    'context-engineering-progress.md',
    'architecture/system-design.md',
    'architecture/decisions/adr-001-generic-gateway-bounded-worker.md',
    'components/gateway-evaluator-context.md',
    'components/trusted-worker-receipts-context.md',
    'components/evidence-audit-context.md',
    'workflows/development.md',
    'workflows/context-maintenance.md',
    'workflows/error-handling-and-logging.md',
)


def copy_public_context_docs(source_root, target_root):
    source_root = Path(source_root)
    target_root = Path(target_root)
    context = source_root / 'docs' / 'context'
    if not context.is_dir() or context.is_symlink():
        raise RuntimeError('MISSING_OR_UNSAFE_PUBLIC_CONTEXT_ROOT')
    for name in PORTABLE_CONTEXT_DOCS:
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts or relative.suffix != '.md':
            raise RuntimeError('INVALID_PUBLIC_CONTEXT_PATH ' + name)
        path = context / relative
        if path.is_symlink():
            raise RuntimeError('UNSAFE_PUBLIC_CONTEXT_SYMLINK ' + name)
        for parent in (context, *path.parents):
            if parent == context.parent:
                break
            if parent.is_symlink():
                raise RuntimeError('UNSAFE_PUBLIC_CONTEXT_SYMLINK ' + name)
        if not path.is_file() or path.is_symlink():
            raise RuntimeError('MISSING_OR_UNSAFE_PUBLIC_CONTEXT_DOC ' + name)
        dest = target_root / 'docs' / 'context' / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dest)


# Normalize only the already-allowlisted, public distribution staging tree.
# shutil.copy2/copytree preserve source modes, which can make a valid archive
# unreadable to the required independent non-root runtime identity.
PORTABLE_EXECUTABLES=frozenset({
    'python/bin/python3.12','python.sh','run.sh','init.sh','start.sh'})
def normalize_bundle_permissions(root):
    for path in (root,*root.rglob('*')):
        if path.is_symlink():
            raise RuntimeError('UNSAFE_PORTABLE_STAGE_SYMLINK '+str(path.relative_to(root)))
        if path.is_dir():
            path.chmod(0o755)
        elif path.is_file():
            rel=path.relative_to(root).as_posix()
            path.chmod(0o755 if rel in PORTABLE_EXECUTABLES else 0o644)
        else:
            raise RuntimeError('UNSAFE_PORTABLE_STAGE_ENTRY '+str(path.relative_to(root)))

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
    bundle=WORK/f'eg-portable-{RELEASE_VERSION}-linux-amd64'
    if bundle.exists():shutil.rmtree(bundle)
    bundle.mkdir()
    root=bundle
    (root/'python/bin').mkdir(parents=True)
    shutil.copy2(SYSTEM_PY,root/'python/bin/python3.12')
    (root/'python/bin/python3.12').chmod(0o755)
    copy_source(SYSTEM_STDLIB,root/'python/lib/python3.12',ignore_large=True)
    prune_optional_gnu_extensions(root/'python/lib/python3.12')
    notice_root=root/'THIRD_PARTY_LICENSES'
    python_licenses=wheel_closure(SITE,root/'python/lib/python3.12/site-packages',
                                  notice_root,STAGE/'requirements.lock')
    native_licenses=[]
    libdir=sysconfig.get_config_var('LIBDIR')
    library=sysconfig.get_config_var('LDLIBRARY')
    if not libdir or not library:
        raise RuntimeError('PORTABLE_LIBPYTHON_NOT_IDENTIFIED')
    libpython=(Path(libdir)/library).resolve()
    if not libpython.is_file() or '.so' not in libpython.name:
        raise RuntimeError('PORTABLE_SHARED_LIBPYTHON_REQUIRED')
    shutil.copy2(libpython,root/'python/lib'/libpython.name)
    # Selectively bundle ELF dependencies from the Debian build environment.
    # Never bundle glibc/the dynamic linker; those define the target ABI.
    allowed_native={'libssl.so.3','libcrypto.so.3','libsqlite3.so.0',
                    'libffi.so.8','libbz2.so.1.0','liblzma.so.5',
                    'libz.so.1','libexpat.so.1',
                    'libncursesw.so.6','libtinfo.so.6','libuuid.so.1'}
    binary_files=[SYSTEM_PY,libpython]
    binary_files.extend(x for x in (root/'python/lib/python3.12').rglob('*.so')
                        if x.is_file())
    for binary in binary_files:
        result=subprocess.run(['ldd',str(binary)],capture_output=True,text=True,check=False)
        for line in result.stdout.splitlines():
            if '=> not found' in line:
                # CPython's optional Tk test extension is not shipped as an EG
                # capability; fail only for the audited required native set.
                missing=line.split('=>',1)[0].strip()
                if missing in allowed_native:
                    raise RuntimeError('UNRESOLVED_NATIVE_LIBRARY '+line.strip())
                continue
            parts=line.strip().split()
            if len(parts)<3 or parts[1]!='=>' or parts[0] not in allowed_native:
                continue
            source=Path(parts[2])
            if not source.is_file():
                raise RuntimeError('MISSING_NATIVE_LIBRARY '+parts[0])
            destination=root/'python/lib'/parts[0]
            if not destination.exists():
                shutil.copy2(source.resolve(),destination)
                native_licenses.append(native_notice(parts[0],source.resolve(),notice_root))
    copy_eg_source(STAGE,root/'eg')
    copy_public_root_docs(STAGE.parent,root)
    copy_public_context_docs(STAGE.parent,root)
    # Include only explicitly reviewed public documentation artwork, never
    # arbitrary SVG or private sidecars from the source tree.
    for name in ('eg-step-review.svg','eg-workflow.svg'):
        source=STAGE/'docs/assets'/name
        if not source.is_file() or source.is_symlink():
            raise RuntimeError('MISSING_OR_UNSAFE_PUBLIC_DOC_ASSET '+name)
        destination=root/'eg/docs/assets'/name
        destination.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(source,destination)
    (root/'THIRD_PARTY_LICENSES').mkdir(exist_ok=True)
    license_candidates=[Path(os.getenv('EG_PYTHON_LICENSE_FILE','/nonexistent')),
                        STAGE/'docs/CPYTHON_LICENSE.md',
                        SYSTEM_STDLIB.parent.parent/'LICENSE',
                        Path('/usr/share/doc/python3.12/copyright')]
    copyright_source=next((q for q in license_candidates if q.is_file()),None)
    if copyright_source is None:
        raise RuntimeError('PYTHON_RUNTIME_LICENSE_FILE_REQUIRED_SET_EG_PYTHON_LICENSE_FILE')
    shutil.copy2(copyright_source,notice_root/'CPython-3.12-license.txt')
    publish_notice_index(notice_root,python_licenses,native_licenses,
                         notice_root/'CPython-3.12-license.txt',root/'LICENSE')
    verify_bundled_notices(root,STAGE/'requirements.lock')
    # Strip all runtime/test-only state including cached bytecode and collocated auth
    # state, leave only source/test code.
    launcher='''#!/bin/sh
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
export PYTHONHOME="$ROOT/python"
export LD_LIBRARY_PATH="$ROOT/python/lib"
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
# Gateway identity follows the host operator; no arbitrary UID prerequisite.
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
# Initialization is identity-neutral; access is governed by state permissions.
[ -n "${EG_STATE_DIR:-}" ] || { echo "DENIED: set EG_STATE_DIR to durable persistent storage" >&2; exit 77; }
case "${EVALUATION_GATEWAY_ADMISSION_MODE:-enabled}" in
 enabled) [ -n "${EG_EXECUTOR_PUBLIC_KEY_B64:-}" ] || { echo "DENIED: externally administered executor root required" >&2; exit 77; } ;;
 disabled) : ;; # Explicit audit-only bootstrap; all concrete effects stay denied.
 *) echo "DENIED: invalid admission mode" >&2; exit 77 ;;
esac
[ -n "${EG_NOTARY_PUBLIC_KEY_B64:-}" ] || { echo "DENIED: independently administered evidence notary public key required" >&2; exit 77; }
# Validate all trust inputs BEFORE making the persistent state directory.
# A typo must never leave a half-created installation that blocks retry.
"$ROOT/python.sh" - <<'PYVALIDATE'
import base64, os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
mode=os.environ.get('EVALUATION_GATEWAY_ADMISSION_MODE','enabled')
executor=os.environ.get('EG_EXECUTOR_PUBLIC_KEY_B64','')
notary=os.environ.get('EG_NOTARY_PUBLIC_KEY_B64','')
def valid(value):
    try:
        data=base64.b64decode(value,validate=True)
        if len(data)!=32:return False
        Ed25519PublicKey.from_public_bytes(data)
        return True
    except Exception:return False
if not valid(notary) or (mode=='enabled' or executor) and not valid(executor):
    raise SystemExit('DENIED: invalid independent public trust root')
if executor and executor == notary:
    raise SystemExit('DENIED: identical executor and notary trust roots')
PYVALIDATE
if [ -e "$EG_STATE_DIR" ]; then
  echo "DENIED: refuse to overwrite existing state or identity" >&2
  exit 77
fi
mkdir -m 700 "$EG_STATE_DIR"
for dir in data anchor evidence; do mkdir -m 700 "$EG_STATE_DIR/$dir"; done
"$ROOT/python.sh" - <<'PY'
import base64,os,secrets
from pathlib import Path
d=Path(os.environ['EG_STATE_DIR'])
executor=os.environ.get('EG_EXECUTOR_PUBLIC_KEY_B64','')
notary=os.environ.get('EG_NOTARY_PUBLIC_KEY_B64','')
audit_only=os.environ.get('EVALUATION_GATEWAY_ADMISSION_MODE','enabled') == 'disabled'
try:
    if (not audit_only or executor) and len(base64.b64decode(executor,validate=True))!=32:
        raise ValueError('executor public key invalid')
    if len(base64.b64decode(notary,validate=True))!=32:
        raise ValueError('notary public key invalid')
except (ValueError,TypeError) as exc:
    raise SystemExit('DENIED: independent public keys invalid') from exc
if executor and executor == notary:
    raise SystemExit('DENIED: executor and evidence notary trust roots must be distinct')
if (d/'notary-private.pem').exists():
    raise SystemExit('DENIED: evidence notary private key accessible in EG state')
pub=notary
values={'EVALUATION_GATEWAY_API_KEY':secrets.token_urlsafe(48),
'EVALUATION_GATEWAY_HITL_KEY':secrets.token_urlsafe(48),
'EVALUATION_GATEWAY_AUDIT_HMAC_KEY':secrets.token_urlsafe(48),
'EVALUATION_GATEWAY_EVIDENCE_PUBLIC_KEY_B64':pub,
'EVALUATION_GATEWAY_EXECUTOR_PUBLIC_KEY_B64':executor,
'EVALUATION_GATEWAY_ADMISSION_MODE':'disabled' if audit_only else 'enabled'}
with (d/'runtime.env').open('x') as stream:
  for key,value in values.items():stream.write(key+'='+value+'\\n')
(d/'runtime.env').chmod(0o600)
print('STATE_INITIALIZED_AUDIT_ONLY' if audit_only else 'STATE_INITIALIZED_INDEPENDENT_ROOTS')
PY
'''
    write_text(root/'init.sh',installer);(root/'init.sh').chmod(0o755)
    envrunner='''#!/bin/sh
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
[ -n "${EG_STATE_DIR:-}" ] || exit 77
if [ -e "$EG_STATE_DIR/notary-private.pem" ]; then
  echo "DENIED: notary private key must not be accessible to EG runtime" >&2
  exit 77
fi
if [ ! -f "$EG_STATE_DIR/runtime.env" ]; then
  echo "DENIED: runtime credentials not initialized" >&2
  exit 77
fi
exec "$ROOT/python.sh" - "$ROOT" <<'PYENV'
import os, re, stat, sys
from pathlib import Path
root = Path(sys.argv[1])
path = Path(os.environ['EG_STATE_DIR']) / 'runtime.env'
if path.is_symlink() or stat.S_IMODE(path.stat().st_mode) & 0o077:
    raise SystemExit('DENIED: insecure runtime configuration')
values = {}
for line in path.read_text().splitlines():
    if not line or '=' not in line:
        raise SystemExit('DENIED: malformed runtime configuration')
    key, value = line.split('=', 1)
    if not re.fullmatch(r'EVALUATION_GATEWAY_[A-Z0-9_]+', key) or key in values:
        raise SystemExit('DENIED: invalid runtime configuration key')
    values[key] = value
env = dict(os.environ, **values)
os.execve(str(root / 'run.sh'), [str(root / 'run.sh')], env)
PYENV
'''
    write_text(root/'start.sh',envrunner);(root/'start.sh').chmod(0o755)
    doc=f'''# EG Offline Portable {RELEASE_VERSION} (Linux x86-64)

Relocatable bundled Python 3.12, stdlib, all pinned runtime libraries and EG source.
Requires Linux x86-64 ABI compatible with the build environment (glibc-compatible).
No pip/apt/network required to execute, but not a cross-OS executable.

Run as the operator-selected host identity (root or non-root), and set
EG_STATE_DIR to secure, durable and separately backed-up storage. It MUST be outside this immutable
installation directory. The executor signing root must be independently
administered: supply its raw 32-byte Ed25519 public key via
EG_EXECUTOR_PUBLIC_KEY_B64. The evidence notary private key must also live in
a separate independent signer/UID or domain; supply ONLY its public key through
EG_NOTARY_PUBLIC_KEY_B64. Neither signing key is generated or stored by EG.
Execution and evidence verification fail closed without both trust roots.

  export EG_STATE_DIR=/durable/eg/state
  export EG_EXECUTOR_PUBLIC_KEY_B64=<remote-verified-base64-public-key>
  export EG_NOTARY_PUBLIC_KEY_B64=<independent-notary-base64-public-key>
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
    # Explicit public modes must not depend on the builder's umask.
    normalize_bundle_permissions(root)
    # Manifest only for contents actually inside bundle; no secrets.
    files=sorted(x for x in root.rglob('*') if x.is_file())
    manifest={str(x.relative_to(root)):filehash(x) for x in files}
    write_text(root/'MANIFEST.json',json.dumps({'version':RELEASE_VERSION,'platform':'linux-amd64',
      'build_python':'CPython 3.12','files':manifest},sort_keys=True,indent=2))
    archive=WORK/(bundle.name+'.tar.gz')
    import gzip
    def deterministic_header(info):
        if not (info.isdir() or info.isfile()):
            raise RuntimeError('UNSAFE_PORTABLE_ARCHIVE_ENTRY '+info.name)
        rel=info.name.split('/',1)[-1]
        info.mode=0o755 if info.isdir() or rel in PORTABLE_EXECUTABLES else 0o644
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
