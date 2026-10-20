"""Operator-owned durable adapter activation state, separate from EG effect authority.

Signed binding + pinned OS peer UID/liveness are required before activation.
No agent-generated descriptor can authorize its own worker or canonical PRE.
"""
from __future__ import annotations
import json,os,sqlite3,stat,time,base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pathlib import Path
from tools.operator_adapter_binding import verify_operator_binding,BindingDenied
from tools.adapter_liveness import probe_unix

class RegistryDenied(RuntimeError):pass

class OperatorAdapterRegistry:
    def __init__(self, directory, operator_public_key_b64):
        directory=Path(directory)
        if (not directory.is_dir() or directory.is_symlink()
            or directory.stat().st_uid!=os.getuid()
            or stat.S_IMODE(directory.stat().st_mode)&0o077
            or not isinstance(operator_public_key_b64,str) or not operator_public_key_b64):
            raise RegistryDenied("PRIVATE_OPERATOR_REGISTRY_REQUIRED")
        self.path=directory/"adapter-activation.sqlite3"
        self.operator_key=operator_public_key_b64
        with self._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS adapters ("
              "adapter_id TEXT PRIMARY KEY,cap_sha TEXT NOT NULL,nonce TEXT NOT NULL,"
              "binding_json TEXT NOT NULL,status TEXT NOT NULL "
              "CHECK(status IN ('ACTIVE','REVOKED')))")
        os.chmod(self.path,0o600)

    def _connect(self):
        db=sqlite3.connect(self.path,timeout=10,isolation_level=None)
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA journal_mode=WAL")
        return db

    def activate(self, binding, *, adapter_id, capability_sha256, probe=probe_unix):
        approved=verify_operator_binding(binding,operator_public_key_b64=self.operator_key,
                          adapter_id=adapter_id,capability_sha256=capability_sha256)
        with self._connect() as db:
            row=db.execute("SELECT nonce,status FROM adapters WHERE adapter_id=?",
                           (adapter_id,)).fetchone()
        if row:
            if row[0]==binding["operator_nonce"] and row[1]=="ACTIVE":
                return {"status":"ALREADY_ACTIVE","adapter_id":adapter_id,"admission":False}
            raise RegistryDenied("ADAPTER_ALREADY_BOUND_OR_REVOKED")
        probe(approved["socket_path"],adapter_id=adapter_id,
              capability_sha256=capability_sha256,
              public_key_b64=approved["worker_public_key_b64"],
              task_id="operator-onboarding",step_key="00.01",
              gate_checkpoint_no=1,action_fingerprint=capability_sha256,
              expected_worker_uid=approved["worker_uid"])
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM adapters WHERE adapter_id=?",(adapter_id,)).fetchone():
                db.rollback();raise RegistryDenied("ACTIVATION_RACE_DENIED")
            db.execute("INSERT INTO adapters VALUES (?,?,?,?,?)",
                (adapter_id,capability_sha256,binding["operator_nonce"],
                 json.dumps(binding,sort_keys=True,separators=(",",":")),"ACTIVE"))
            db.commit()
        return {"status":"ACTIVE_CONFIG_ONLY","adapter_id":adapter_id,"admission":False,
                "next_action":"LIVE_PRE_AND_INDEPENDENT_SIGNED_HITL"}

    def revoke(self, envelope, *, adapter_id, now=None):
        instant=time.time() if now is None else now
        fields={"version","adapter_id","capability_sha256","binding_nonce",
                "decision","issued_at","expires_at","reason"}
        if not isinstance(envelope,dict) or set(envelope)!=fields|{"signature_b64"}:
            raise RegistryDenied("INVALID_OPERATOR_REVOCATION")
        doc={k:envelope[k] for k in fields}
        if (doc["version"]!=1 or doc["adapter_id"]!=adapter_id
            or doc["decision"]!="REVOKED" or not isinstance(doc["reason"],str)
            or not 1<=len(doc["reason"])<=256
            or type(doc["issued_at"]) not in (int,float)
            or type(doc["expires_at"]) not in (int,float)
            or not doc["issued_at"]<=instant<doc["expires_at"]
            or doc["expires_at"]-doc["issued_at"]>300):
            raise RegistryDenied("INVALID_OPERATOR_REVOCATION_SCOPE")
        try:
            pub=base64.b64decode(self.operator_key,validate=True)
            sig=base64.b64decode(envelope["signature_b64"],validate=True)
            if len(pub)!=32 or len(sig)!=64:raise ValueError("key size")
            Ed25519PublicKey.from_public_bytes(pub).verify(sig,
                json.dumps(doc,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode())
        except Exception as exc:
            raise RegistryDenied("UNTRUSTED_OPERATOR_REVOCATION") from exc
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row=db.execute("SELECT cap_sha,nonce,status FROM adapters WHERE adapter_id=?",
                           (adapter_id,)).fetchone()
            if not row or row[:2]!=(doc["capability_sha256"],doc["binding_nonce"]):
                db.rollback();raise RegistryDenied("REVOCATION_BINDING_MISMATCH")
            if row[2]=="REVOKED":
                db.commit()
                return {"status":"ALREADY_REVOKED","admission":False}
            db.execute("UPDATE adapters SET status='REVOKED' WHERE adapter_id=?",(adapter_id,))
            db.commit()
        return {"status":"REVOKED_NO_NEW_ADMISSION","adapter_id":adapter_id,"admission":False}

    def resolve(self,adapter_id,*,now=None):
        with self._connect() as db:
            row=db.execute("SELECT cap_sha,binding_json,status FROM adapters WHERE adapter_id=?",
                           (adapter_id,)).fetchone()
        if not row or row[2]!="ACTIVE":
            raise RegistryDenied("ADAPTER_NOT_ACTIVE")
        binding=json.loads(row[1])
        try:
            approved=verify_operator_binding(binding,operator_public_key_b64=self.operator_key,
                adapter_id=adapter_id,capability_sha256=row[0],now=now)
        except BindingDenied as exc:
            raise RegistryDenied("ADAPTER_BINDING_EXPIRED_OR_INVALID") from exc
        return {**approved,"status":"CONFIGURED_LIVENESS_RECHECK_REQUIRED","admission":False}
