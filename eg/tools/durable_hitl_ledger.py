"""Protected, single-use HITL nonce ledger for isolated adapters.

A durable claim is NOT proof of physical execution. After a crash it remains
UNKNOWN and must be independently reconciled; never auto-reissue the grant.
Signed revocations are durable and race atomically with approval consumption.
"""
from __future__ import annotations
import os
import json
import sqlite3
from pathlib import Path
from tools.signed_hitl_approval import verify_approval,verify_revocation

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
            conn.execute("CREATE TABLE IF NOT EXISTS revocations (nonce TEXT PRIMARY KEY, task_id TEXT NOT NULL, step_key TEXT NOT NULL, gate_no INTEGER NOT NULL, action_fp TEXT NOT NULL, adapter_id TEXT NOT NULL)")
        os.chmod(self.db,0o600)
        with self._connect() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS sealed_receipts (nonce TEXT PRIMARY KEY, task_id TEXT NOT NULL, step_key TEXT NOT NULL, gate_no INTEGER NOT NULL, action_fp TEXT NOT NULL, adapter_id TEXT NOT NULL, receipt_json TEXT NOT NULL)")
        with self._connect() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS executed_effects (target TEXT PRIMARY KEY, task_id TEXT NOT NULL, gate_no INTEGER NOT NULL, action_fp TEXT NOT NULL, adapter_id TEXT NOT NULL, digest TEXT NOT NULL)")
        with self._connect() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS no_effect_retired (nonce TEXT PRIMARY KEY, task_id TEXT NOT NULL, step_key TEXT NOT NULL, gate_no INTEGER NOT NULL, action_fp TEXT NOT NULL, adapter_id TEXT NOT NULL)")
        with self._connect() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS compensation_completed (nonce TEXT PRIMARY KEY, task_id TEXT NOT NULL, step_key TEXT NOT NULL, gate_no INTEGER NOT NULL, action_fp TEXT NOT NULL, adapter_id TEXT NOT NULL)")

    def _connect(self):
        conn=sqlite3.connect(self.db,timeout=10,isolation_level=None)
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def revoke(self, revocation, key, *, task_id, step_key, gate_checkpoint_no, action_fingerprint, adapter_id, now=None):
        result=verify_revocation(revocation,key,task_id=task_id,step_key=step_key,
                                 gate_checkpoint_no=gate_checkpoint_no,
                                 action_fingerprint=action_fingerprint,adapter_id=adapter_id,now=now)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if conn.execute("SELECT 1 FROM claims WHERE nonce=?",(result["nonce"],)).fetchone():
                conn.rollback()
                raise ApprovalClaimDenied("HITL_ALREADY_CONSUMED_REVOCATION_TOO_LATE")
            try:
                conn.execute("INSERT INTO revocations VALUES (?,?,?,?,?,?)",
                    (result["nonce"],task_id,step_key,gate_checkpoint_no,action_fingerprint,adapter_id))
                conn.commit()
            except sqlite3.IntegrityError:
                conn.rollback()
                raise ApprovalClaimDenied("HITL_ALREADY_REVOKED")
        return {"status":"REVOCATION_DURABLE_EFFECT_DENIED","nonce":result["nonce"]}

    def claim_status(self, nonce, *, task_id, step_key, gate_checkpoint_no, action_fingerprint, adapter_id):
        with self._connect() as conn:
            row=conn.execute("SELECT task_id,step_key,gate_no,action_fp,adapter_id,status FROM claims WHERE nonce=?",(nonce,)).fetchone()
        if row is None:
            return None
        if row[:5]!=(task_id,step_key,gate_checkpoint_no,action_fingerprint,adapter_id):
            raise ApprovalClaimDenied("HITL_CLAIM_SCOPE_MISMATCH")
        return row[5]

    def consume(self, approval, key, *, task_id, step_key, gate_checkpoint_no, action_fingerprint, adapter_id, now=None):
        result=verify_approval(approval,key,task_id=task_id,step_key=step_key,
                               gate_checkpoint_no=gate_checkpoint_no,
                               action_fingerprint=action_fingerprint,adapter_id=adapter_id,now=now)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if conn.execute("SELECT 1 FROM no_effect_retired WHERE nonce=?",(result["nonce"],)).fetchone():
                conn.rollback()
                raise ApprovalClaimDenied("HITL_GATE_RETIRED_NO_EFFECT")
            if conn.execute("SELECT 1 FROM revocations WHERE nonce=?",(result["nonce"],)).fetchone():
                conn.rollback()
                raise ApprovalClaimDenied("HITL_REVOKED_NO_EXECUTION")
            try:
                conn.execute("INSERT INTO claims VALUES (?,?,?,?,?,?,?)",
                    (result["nonce"],task_id,step_key,gate_checkpoint_no,
                     action_fingerprint,adapter_id,"UNKNOWN"))
                conn.commit()
            except sqlite3.IntegrityError as exc:
                conn.rollback()
                raise ApprovalClaimDenied("HITL_ALREADY_CONSUMED_OR_UNKNOWN_NO_REPLAY") from exc
        return {"status":"CLAIM_DURABLE_EFFECT_NOT_AUTHORIZED","nonce":result["nonce"]}

    def compensation_status(self, nonce, *, task_id, step_key, gate_checkpoint_no, action_fingerprint, adapter_id):
        scope=(task_id,step_key,gate_checkpoint_no,action_fingerprint,adapter_id)
        with self._connect() as conn:
            row=conn.execute("SELECT task_id,step_key,gate_no,action_fp,adapter_id FROM compensation_completed WHERE nonce=?",(nonce,)).fetchone()
        if row is None:
            return False
        if row!=scope:
            raise ApprovalClaimDenied("COMPENSATION_COMPLETION_SCOPE_MISMATCH")
        return True

    def complete_compensation(self, nonce, *, task_id, step_key, gate_checkpoint_no, action_fingerprint, adapter_id):
        scope=(task_id,step_key,gate_checkpoint_no,action_fingerprint,adapter_id)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            claim=conn.execute("SELECT task_id,step_key,gate_no,action_fp,adapter_id FROM claims WHERE nonce=?",(nonce,)).fetchone()
            if claim!=scope:
                conn.rollback()
                raise ApprovalClaimDenied("COMPENSATION_CLAIM_NOT_DURABLE_OR_SCOPE_MISMATCH")
            try:
                conn.execute("INSERT INTO compensation_completed VALUES (?,?,?,?,?,?)",(nonce,*scope))
                conn.commit()
            except sqlite3.IntegrityError as exc:
                conn.rollback()
                raise ApprovalClaimDenied("COMPENSATION_COMPLETION_ALREADY_DURABLE") from exc
        return "COMPENSATION_COMPLETION_DURABLE"

    def retire_no_effect(self, nonce, *, task_id, step_key, gate_checkpoint_no, action_fingerprint, adapter_id):
        scope=(task_id,step_key,gate_checkpoint_no,action_fingerprint,adapter_id)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if conn.execute("SELECT 1 FROM claims WHERE nonce=?",(nonce,)).fetchone():
                conn.rollback()
                raise ApprovalClaimDenied("UNKNOWN_EFFECT_CLAIM_EXISTS_NO_RETIRE")
            existing=conn.execute("SELECT task_id,step_key,gate_no,action_fp,adapter_id FROM no_effect_retired WHERE nonce=?",(nonce,)).fetchone()
            if existing is not None:
                if existing!=scope:
                    conn.rollback()
                    raise ApprovalClaimDenied("RETIRED_SCOPE_MISMATCH")
                conn.commit()
                return "NO_EFFECT_ALREADY_RETIRED"
            conn.execute("INSERT INTO no_effect_retired VALUES (?,?,?,?,?,?)",(nonce,*scope))
            conn.commit()
        return "NO_EFFECT_RETIRED_DURABLE"

    def record_executed_effect(self, target, *, task_id, gate_checkpoint_no, action_fingerprint, adapter_id, digest):
        scope=(task_id,gate_checkpoint_no,action_fingerprint,adapter_id,digest)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row=conn.execute("SELECT task_id,gate_no,action_fp,adapter_id,digest FROM executed_effects WHERE target=?",(target,)).fetchone()
            if row is None:
                conn.execute("INSERT INTO executed_effects VALUES (?,?,?,?,?,?)",(target,*scope))
            elif row!=scope:
                conn.rollback()
                raise ApprovalClaimDenied("EXECUTED_EFFECT_PROVENANCE_MISMATCH")
            conn.commit()

    def require_original_effect(self, target, *, task_id, gate_checkpoint_no, action_fingerprint, adapter_id):
        with self._connect() as conn:
            row=conn.execute("SELECT task_id,gate_no,action_fp,adapter_id FROM executed_effects WHERE target=?",(target,)).fetchone()
        if row!=(task_id,gate_checkpoint_no,action_fingerprint,adapter_id):
            raise ApprovalClaimDenied("COMPENSATION_ORIGINAL_EFFECT_NOT_PROVEN")

    def seal_receipt(self, nonce, receipt, *, task_id, step_key, gate_checkpoint_no,
                     action_fingerprint, adapter_id):
        """Keep the *same* signed receipt across crashes/restarts, never re-sign a sealed effect."""
        scope=(task_id,step_key,gate_checkpoint_no,action_fingerprint,adapter_id)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            claim=conn.execute("SELECT task_id,step_key,gate_no,action_fp,adapter_id FROM claims WHERE nonce=?",(nonce,)).fetchone()
            if claim!=scope:
                conn.rollback()
                raise ApprovalClaimDenied("RECEIPT_WITHOUT_SCOPE_BOUND_DURABLE_CLAIM")
            previous=conn.execute("SELECT task_id,step_key,gate_no,action_fp,adapter_id,receipt_json FROM sealed_receipts WHERE nonce=?",(nonce,)).fetchone()
            if previous is not None:
                if previous[:5]!=scope:
                    conn.rollback()
                    raise ApprovalClaimDenied("SEALED_RECEIPT_SCOPE_MISMATCH")
                conn.commit()
                return json.loads(previous[5])
            conn.execute("INSERT INTO sealed_receipts VALUES (?,?,?,?,?,?,?)",
                         (nonce,*scope,json.dumps(receipt,sort_keys=True,separators=(",",":"))))
            conn.commit()
            return receipt
