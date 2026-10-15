#!/usr/bin/env python3
"""Offline operator tool: re-establish the external audit anchor after a deliberate database restore.

Usage (gateway stopped, same environment variables as the gateway):
  reanchor.py --confirm

The ledger is fully verified first (hash chain, HMAC, materialized state). Only if it is valid is the
anchor rewritten to the current ledger head. This is the ONLY supported way to move the anchor backwards,
and it must be an explicit, recorded operator decision (see docs/OPERATIONS.md).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app.main as gw  # noqa: E402


def main() -> int:
    if sys.argv[1:] != ["--confirm"]:
        print("refusing: pass --confirm after reading docs/OPERATIONS.md", file=sys.stderr)
        return 2
    gw.require_config()
    c = gw.conn()
    try:
        c.execute("BEGIN")
        if not gw.verify_audit_chain(c):
            print("ledger chain/HMAC verification FAILED; anchor not changed", file=sys.stderr)
            return 1
        if not gw.verify_materialized_state(c):
            print("materialized state verification FAILED; anchor not changed", file=sys.stderr)
            return 1
        seq, head = gw.db_head(c)
    finally:
        c.close()
    gw.write_anchor(seq, head, allow_regress=True)
    print(f"anchor set: seq={seq} head={head}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
