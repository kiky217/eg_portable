"""Protected, single-use HITL nonce ledger for isolated adapters.

A durable claim is NOT proof of physical execution. After a crash it remains
UNKNOWN and must be independently reconciled; never auto-reissue the grant.
"""
from __future__ import annotations
import os
import sqlite3
from pathlib import Path
from tools.signed_hitl_approval import verify_approval

class ApprovalClaimDenied(RuntimeError):
    pass

class ApprovalLedger:
    def __init__(self, directory):
        self.directory=Path(directory)
        if not self.directory.is_dir() or self.directory.is_symlink():
            raise ApprovalClaimDenied("LEDGER_DIRECTORY_MISSING")
        mode=self.directory.stat().st_mode & 0o777
        if mode & 0o077:
            raise ApprovalClaimDenied("LEDGER_DIRECTORY_NOT_PRIVATE")
        self.db=self.directory/"hitl-consumption.sqlite3"
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("CREATE TABLE IF NOT EXISTS claims (nonce TEXT PRIMARY KEY, task_id TEXT NOT NULL, step_key TEXT NOT NULL, gate_no INTEGER NOT NULL, action_fp TEXT NOT NULL, adapter_id TEXT NOT NULL, status TEXT NOT NULL CHECK(status='UNKNOWN'))")
        os.chmod(self.db,0o600)

    def _connect(self):
        conn=sqlite3.connect(self.db,timeout=10,isolation_level=None)
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def consume(self, approval, key, *, task_id, step_key, gate_checkpoint_no, action_fingerprint, adapter_id, now=None):
        result=verify_approval(approval,key,task_id=task_id,step_key=step_key,
                               gate_checkpoint_no=gate_checkpoint_no,
                               action_fingerprint=action_fingerprint,adapter_id=adapter_id,now=now)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute("INSERT INTO claims VALUES (?,?,?,?,?,?,?)",
                    (result["nonce"],task_id,step_key,gate_checkpoint_no,
                     action_fingerprint,adapter_id,"UNKNOWN"))
                conn.commit()
            except sqlite3.IntegrityError as exc:
                conn.rollback()
                raise ApprovalClaimDenied("HITL_ALREADY_CONSUMED_OR_UNKNOWN_NO_REPLAY") from exc
        return {"status":"CLAIM_DURABLE_EFFECT_NOT_AUTHORIZED",
                "nonce":result["nonce"]}
