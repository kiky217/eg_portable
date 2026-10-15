#!/usr/bin/env bash
set -euo pipefail
ROOT=/content/workspace
SRC="$(cd "$(dirname "$0")" && pwd)"
test -f "$ROOT/eg/local-v3.0.1/runtime/docs/EXECUTOR_PROTOCOL.md" || { echo "EG portable runtime missing" >&2; exit 77; }
test -f "$SRC/EG_PORTABLE_POLICY.md" || exit 77
cd "$SRC"
sha256sum -c MANIFEST.sha256 >/dev/null || { echo "Portable policy integrity check failed" >&2; exit 77; }
mkdir -p "$ROOT/bin" "$ROOT/eg"
cp "$SRC"/bin/*.py "$ROOT/bin/"
cp "$SRC/test_portable_eg_policy.py" "$ROOT/eg/"
cp "$SRC/EG_PORTABLE_POLICY.md" "$ROOT/eg/"
"$ROOT/eg/.venv/bin/python" "$ROOT/eg/test_portable_eg_policy.py"
echo "PORTABLE_EG_POLICY_VERIFIED"
