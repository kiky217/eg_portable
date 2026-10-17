from __future__ import annotations
import base64, hashlib, hmac, json, logging, math, os, re, sqlite3, stat, threading, time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Literal, NamedTuple
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from starlette.responses import JSONResponse
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, model_validator
from app.execution_receipts import verify as verify_execution_receipt
from app.no_effect_receipts import verify_no_effect
from tools.high_effect_admission import AdapterCapability, AdmissionDenied, admit_high_effect, target_within_scope

LOG = logging.getLogger("evaluation_gateway")

BASE = Path(__file__).resolve().parents[1]
APP_VERSION = (BASE / "VERSION").read_text(encoding="utf-8").strip()
PROTOCOL_VERSION = "3.1"
MANIFEST_VERSION = 4
PROTOCOL_PATH = BASE / "docs" / "EXECUTOR_PROTOCOL.md"
ZERO_HASH = "0" * 64


def env_int(name: str, default: int, lo: int, hi: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if not lo <= value <= hi:
        raise RuntimeError(f"{name} must be within {lo}..{hi}")
    return value


# ---- configuration (every tunable is an explicit, bounded, named setting) ----
DB_PATH = Path(os.getenv("EVALUATION_GATEWAY_DB_PATH", "")).expanduser()
EVIDENCE_ROOT = Path(os.getenv("EVALUATION_GATEWAY_EVIDENCE_ROOT", "")).expanduser()
_anchor_env = os.getenv("EVALUATION_GATEWAY_ANCHOR_PATH", "")
ANCHOR_PATH: Path | None = Path(_anchor_env) if _anchor_env else None
API_KEY = os.getenv("EVALUATION_GATEWAY_API_KEY", "")
HITL_KEY = os.getenv("EVALUATION_GATEWAY_HITL_KEY", "")
AUDIT_HMAC_KEY = os.getenv("EVALUATION_GATEWAY_AUDIT_HMAC_KEY", "")
NOTARY_PUBLIC_KEY_B64 = os.getenv("EVALUATION_GATEWAY_EVIDENCE_PUBLIC_KEY_B64", "")
LEGACY_NOTARY_KEYS_JSON = os.getenv("EVALUATION_GATEWAY_LEGACY_NOTARY_KEYS_JSON", "")
EXECUTOR_PUBLIC_KEY_B64 = os.getenv("EVALUATION_GATEWAY_EXECUTOR_PUBLIC_KEY_B64", "")
# Explicit fail-closed deployment mode. Disabled admission serves only
# historical task reconciliation and authenticated audit.
ADMISSION_MODE = os.getenv("EVALUATION_GATEWAY_ADMISSION_MODE", "enabled")
EXECUTOR_OUTPUT_ROOT = os.getenv("EVALUATION_GATEWAY_EXECUTOR_OUTPUT_ROOT", "")
HIGH_EFFECT_CAPABILITIES_JSON = os.getenv("EVALUATION_GATEWAY_HIGH_EFFECT_CAPABILITIES_JSON", "")
# Internal test switch, deliberately unavailable as an environment override.
# A configured JSON manifest and signed HITL do not prove an independent worker.
HIGH_EFFECT_CI_FIXTURE_ENABLED = False
HITL_PUBLIC_KEY_B64 = os.getenv("EVALUATION_GATEWAY_HITL_PUBLIC_KEY_B64", "")
TRUSTED_UID = env_int("EVALUATION_GATEWAY_TRUSTED_EVIDENCE_UID", os.getuid(), 0, 2**31 - 1)
EVIDENCE_MAX_AGE_SECONDS = env_int("EVALUATION_GATEWAY_EVIDENCE_MAX_AGE_SECONDS", 300, 1, 86400)
CLOCK_SKEW_SECONDS = env_int("EVALUATION_GATEWAY_CLOCK_SKEW_SECONDS", 30, 0, 300)
ANCHOR_SETTLE_ATTEMPTS = 10
ANCHOR_SETTLE_INTERVAL_SECONDS = 0.01
INTEGRITY_CACHE_SECONDS = env_int("EVALUATION_GATEWAY_INTEGRITY_CACHE_SECONDS", 15, 0, 300)

MAX_REQUEST_BYTES = 1_000_000
MAX_EVIDENCE_FILE_BYTES = 2_000_000
MAX_MATCHER_VALUE_CHARS = 10_000
MAX_BINDINGS_PER_MANIFEST = 200
MAX_LOCAL_REMEDIATION_FAILURES = 3
MAX_REMEDIAL_STEP_FAILURES = 3
MIN_SECRET_LENGTH = 32
MIN_SECRET_DISTINCT_CHARS = 10
MIN_SECRET_ENTROPY_BITS = 3.5

TERMINAL_STATUSES = ("SATISFIED", "UNRESOLVED", "ABORTED")
MATCHER_KINDS = ("contains", "not_contains", "equals")
SECRET_RE = re.compile(r"^[A-Za-z0-9_\-+/=.~]+$")
SECRET_PLACEHOLDER_WORDS = ("generate", "changeme", "change_me", "example", "placeholder", "password")
EVAL_RESPONSE_KEYS = (
    "checkpoint_no", "step_key", "verdict", "step_verified", "evidence_digest", "contract_status",
    "completed_at", "remedial_outcome", "recovery_strategy", "hitl_approved", "action_fingerprint",
    "gate_checkpoint_no", "high_effect_pin",
)

REMEDIAL_CORE_TITLES = {
    "01": "Diagnose causal state",
    "01.01": "Confirm blocker and trigger step",
    "01.02": "Identify causal step and last-known-good state",
    "01.03": "Determine recoverability and recovery strategy",
    "02": "Recover",
    "02.01": "Execute recovery action or establish it cannot be safely completed",
    "02.02": "Verify recovered state or confirm no verified recovery state exists",
    "03": "Resume decision",
    "03.01": "Verify original trigger step can proceed or confirm it remains impossible",
    "03.02": "Final remedial outcome",
}
STEP_RE = re.compile(r"^[0-9]{2}(?:\.[0-9]{2}){0,5}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
HASH_RE = re.compile(r"^[a-f0-9]{64}$")


def ct(a: Any, b: Any) -> bool:
    """Constant-time comparison that is safe for any Unicode input (bytes are compared, never ASCII-only str)."""
    return hmac.compare_digest(str(a).encode("utf-8"), str(b).encode("utf-8"))


class IntegrityFailure(RuntimeError):
    pass


# ---- application lifecycle ----
@asynccontextmanager
async def lifespan(_app):
    require_config()
    init_db()
    if not integrity_ok(force=True):
        raise RuntimeError("audit/state/anchor integrity broken")
    yield


class BoundedRequestBodyMiddleware:
    """Fail closed on declared or actual HTTP request bodies above MAX_REQUEST_BYTES.

    The body is bounded before FastAPI/Pydantic parsing so chunked/streamed requests
    cannot bypass the Content-Length guard. At most MAX_REQUEST_BYTES plus one
    incoming ASGI chunk is retained before a 413 response is emitted.
    """
    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)
        headers = {k.lower(): v for k, v in scope.get("headers", [])}
        raw = headers.get(b"content-length")
        if raw is not None:
            try:
                declared = int(raw.decode("ascii"))
                if declared < 0:
                    raise ValueError
            except (ValueError, UnicodeDecodeError):
                return await JSONResponse(status_code=400, content={"detail": "invalid content-length"})(scope, receive, send)
            if declared > self.max_bytes:
                return await JSONResponse(status_code=413, content={"detail": "request too large"})(scope, receive, send)

        total = 0
        chunks: list[bytes] = []
        disconnected = False
        while True:
            message = await receive()
            if message.get("type") == "http.disconnect":
                disconnected = True
                break
            if message.get("type") != "http.request":
                continue
            chunk = message.get("body", b"") or b""
            total += len(chunk)
            if total > self.max_bytes:
                return await JSONResponse(status_code=413, content={"detail": "request too large"})(scope, receive, send)
            if chunk:
                chunks.append(chunk)
            if not message.get("more_body", False):
                break

        if disconnected:
            return
        body = b"".join(chunks)
        delivered = False

        async def replay_receive():
            nonlocal delivered
            if delivered:
                return {"type": "http.request", "body": b"", "more_body": False}
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await self.app(scope, replay_receive, send)


app = FastAPI(title="Evaluation Gateway Local Hardened", version=APP_VERSION, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(BoundedRequestBodyMiddleware, max_bytes=MAX_REQUEST_BYTES)


@app.exception_handler(sqlite3.OperationalError)
async def database_busy_handler(_request: Request, exc: sqlite3.OperationalError):
    LOG.error("database operational error: %s", exc)
    return JSONResponse(status_code=503, content={"detail": "database unavailable or busy"}, headers={"Retry-After": "1"})


# ---- request models (extra fields are rejected: no silently ignored security-relevant input) ----
class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Verdict(str, Enum):
    VERIFIED_PASS = "VERIFIED_PASS"; VERIFIED_FAIL = "VERIFIED_FAIL"; READY_TO_EXECUTE = "READY_TO_EXECUTE"
    UNVERIFIED = "UNVERIFIED"; CONFLICT = "CONFLICT"; STALE_EVIDENCE = "STALE_EVIDENCE"
    REQUIRES_HITL = "REQUIRES_HITL"; BLOCKED = "BLOCKED"


class Evidence(Strict):
    """Pointer to producer-notarized evidence. Freshness, matcher and criterion binding are NOT client-controlled."""
    source_type: Literal["knid_task", "manual"]
    reference: str | None = None


class Claim(Strict):
    criterion_index: int = Field(ge=0, le=999)
    claim: str = Field(min_length=1, max_length=20000)
    evidence: list[Evidence] = Field(min_length=1, max_length=20)


class ActionProof(Strict):
    purpose: Literal["sandbox_pass", "rollback_ready", "reversible"]
    evidence: Evidence


class Action(Strict):
    action_type: str = Field(min_length=1, max_length=200)
    target: str = Field(min_length=1, max_length=500)
    effect_class: Literal["E0", "E1", "E2", "E3", "E4", "E5"]
    reversible: bool = False
    real_world_effect: bool = False
    payload_sha256: str | None = Field(default=None, pattern=HASH_RE.pattern)
    payload_bytes: int | None = Field(default=None, ge=1, le=512*1024)
    proofs: list[ActionProof] = Field(default_factory=list, max_length=20)

    @model_validator(mode="after")
    def unique_proof_purposes(self):
        purposes = [p.purpose for p in self.proofs]
        if len(purposes) != len(set(purposes)):
            raise ValueError("duplicate action proof purpose")
        return self


class PlanStep(Strict):
    step_key: str = Field(pattern=STEP_RE.pattern)
    title: str = Field(min_length=1, max_length=500)
    acceptance_criteria: list[str] = Field(min_length=1, max_length=100)
    required: bool = True
    execution_required: bool = False  # Immutable step contract; legacy plans remain logical.
    preconditions: list[str] | None = Field(default=None, min_length=1, max_length=100)
    invariants: list[str] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def strict_required(self):
        if not self.required:
            raise ValueError("all hierarchy nodes must be required")
        if any(not x.strip() for x in self.acceptance_criteria):
            raise ValueError("blank acceptance criterion")
        if self.preconditions is not None and any(not x.strip() for x in self.preconditions):
            raise ValueError("blank precondition")
        if any(not x.strip() for x in self.invariants):
            raise ValueError("blank invariant")
        if self.execution_required and not self.preconditions:
            raise ValueError("execution-required step must define separate PRE preconditions")
        return self


class RegisterRequest(Strict):
    event_id: str
    task_id: str
    protocol_hash: str
    task_kind: Literal["NORMAL", "REMEDIAL"] = "NORMAL"
    remedial_for_task_id: str | None = None
    remedial_trigger_step_key: str | None = None
    causal_step_key: str | None = None
    remedial_origin_checkpoint_no: int | None = Field(default=None, ge=0)
    remedial_attempt: int | None = Field(default=None, ge=1)
    agent: str = Field(min_length=1, max_length=100)
    original_instruction: str = Field(min_length=1, max_length=100000)
    acceptance_criteria: list[str] = Field(min_length=1, max_length=200)
    steps: list[PlanStep] = Field(min_length=1, max_length=200)

    @model_validator(mode="after")
    def validate_ids(self):
        for v in (self.event_id, self.task_id):
            if not ID_RE.fullmatch(v):
                raise ValueError("invalid identifier")
        if not HASH_RE.fullmatch(self.protocol_hash):
            raise ValueError("invalid protocol hash")
        if len({s.step_key for s in self.steps}) != len(self.steps):
            raise ValueError("duplicate step_key")
        if any("execution_required" not in step.model_fields_set for step in self.steps):
            raise ValueError("every step must explicitly declare execution_required")
        links = (self.remedial_for_task_id, self.remedial_trigger_step_key, self.remedial_origin_checkpoint_no, self.remedial_attempt)
        if self.task_kind == "NORMAL" and any(v is not None for v in links + (self.causal_step_key,)):
            raise ValueError("remedial link fields forbidden on NORMAL task")
        if self.task_kind == "REMEDIAL" and any(v is None for v in links):
            raise ValueError("remedial link fields required")
        return self


class EvalRequest(Strict):
    event_id: str
    task_id: str
    contract_hash: str
    protocol_hash: str
    checkpoint_no: int = Field(ge=0)
    step_key: str = Field(pattern=STEP_RE.pattern)
    agent: str = Field(min_length=1, max_length=100)
    phase: Literal["PRE_EXECUTION", "POST_EXECUTION", "FACT_CHECK"]
    finalize_task: bool = False
    remedial_disposition: Literal["RETRY", "EXHAUSTED"] | None = None
    remedial_outcome: Literal["RECOVERED", "UNRESOLVED"] | None = None
    recovery_strategy: Literal["LOCAL_REPAIR", "ROLLBACK", "COMPENSATION", "REPLAN", "EXHAUSTED"] | None = None
    claims: list[Claim] = Field(min_length=1, max_length=200)
    task_claims: list[Claim] = Field(default_factory=list, max_length=200)
    action: Action | None = None
    execution_receipt: dict[str, Any] | None = None
    hitl_approval: dict[str, Any] | None = None

    @model_validator(mode="after")
    def strict(self):
        for v in (self.event_id, self.task_id):
            if not ID_RE.fullmatch(v):
                raise ValueError("invalid identifier")
        if not HASH_RE.fullmatch(self.contract_hash):
            raise ValueError("invalid contract hash")
        if not HASH_RE.fullmatch(self.protocol_hash):
            raise ValueError("invalid protocol hash")
        if self.finalize_task and self.phase != "POST_EXECUTION":
            raise ValueError("finalize only POST_EXECUTION")
        return self


class SuspensionRequest(Strict):
    event_id: str
    contract_hash: str
    protocol_hash: str
    checkpoint_no: int = Field(ge=0)
    reason: str = Field(min_length=1, max_length=2000)

    @model_validator(mode="after")
    def strict_ids(self):
        if not ID_RE.fullmatch(self.event_id):
            raise ValueError("invalid event id")
        if not HASH_RE.fullmatch(self.contract_hash):
            raise ValueError("invalid contract hash")
        if not HASH_RE.fullmatch(self.protocol_hash):
            raise ValueError("invalid protocol hash")
        return self


class ReconcileRequest(Strict):
    event_id: str
    contract_hash: str
    protocol_hash: str
    checkpoint_no: int = Field(ge=0)
    step_key: str = Field(pattern=STEP_RE.pattern)
    action: Action
    proof: dict[str, Any]
    executor_public_key_b64: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_reconcile_ids(self):
        if not ID_RE.fullmatch(self.event_id) or not HASH_RE.fullmatch(self.contract_hash) or not HASH_RE.fullmatch(self.protocol_hash):
            raise ValueError("invalid reconciliation identifier or hash")
        return self


class AbortRequest(Strict):
    event_id: str
    contract_hash: str
    protocol_hash: str
    checkpoint_no: int = Field(ge=0)
    reason: str = Field(min_length=1, max_length=2000)

    @model_validator(mode="after")
    def strict(self):
        if not ID_RE.fullmatch(self.event_id):
            raise ValueError("invalid identifier")
        if not HASH_RE.fullmatch(self.contract_hash) or not HASH_RE.fullmatch(self.protocol_hash):
            raise ValueError("invalid hash")
        if not self.reason.strip():
            raise ValueError("blank abort reason")
        return self


# ---- primitives ----
def canon(v: Any) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha(v: bytes | str) -> str:
    if isinstance(v, str):
        v = v.encode()
    return hashlib.sha256(v).hexdigest()


def protocol_hash() -> str:
    return sha(PROTOCOL_PATH.read_bytes())


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA synchronous=FULL")
    return c


SCHEMA = """
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,seq INTEGER NOT NULL UNIQUE,created_at TEXT NOT NULL,task_id TEXT NOT NULL,event_id TEXT NOT NULL UNIQUE,event_type TEXT NOT NULL,contract_hash TEXT NOT NULL,request_hash TEXT NOT NULL,request_json TEXT NOT NULL,response_json TEXT NOT NULL,prev_hash TEXT NOT NULL,record_hash TEXT NOT NULL UNIQUE,record_mac TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS task_registry(task_id TEXT PRIMARY KEY,contract_hash TEXT NOT NULL,agent TEXT NOT NULL,original_instruction TEXT NOT NULL,acceptance_criteria_json TEXT NOT NULL,task_kind TEXT NOT NULL DEFAULT 'NORMAL',remedial_for_task_id TEXT,remedial_trigger_step_key TEXT,causal_step_key TEXT,remedial_origin_checkpoint_no INTEGER,remedial_attempt INTEGER,remedial_outcome TEXT,recovery_strategy TEXT,status TEXT NOT NULL,contract_status TEXT NOT NULL,checkpoint_no INTEGER NOT NULL DEFAULT 0,failure_reset_checkpoint INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL,completed_at TEXT);
CREATE TABLE IF NOT EXISTS task_registry_steps(step_id INTEGER PRIMARY KEY AUTOINCREMENT,task_id TEXT NOT NULL REFERENCES task_registry(task_id),step_no INTEGER NOT NULL,step_key TEXT NOT NULL,title TEXT NOT NULL,criteria_json TEXT NOT NULL,required INTEGER NOT NULL,verified INTEGER NOT NULL DEFAULT 0,status TEXT NOT NULL DEFAULT 'PLANNED',last_verdict TEXT,UNIQUE(task_id,step_key),UNIQUE(task_id,step_no));
CREATE TABLE IF NOT EXISTS task_registry_checkpoints(checkpoint_id INTEGER PRIMARY KEY AUTOINCREMENT,task_id TEXT NOT NULL REFERENCES task_registry(task_id),checkpoint_no INTEGER NOT NULL,step_key TEXT NOT NULL,event_id TEXT NOT NULL,verdict TEXT NOT NULL,verified INTEGER NOT NULL,evidence_digest TEXT NOT NULL,created_at TEXT NOT NULL,UNIQUE(task_id,checkpoint_no));
CREATE TABLE IF NOT EXISTS evidence_records(evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,task_id TEXT NOT NULL,step_key TEXT NOT NULL,criterion_index INTEGER NOT NULL,purpose TEXT NOT NULL,source_type TEXT NOT NULL,reference TEXT NOT NULL,matcher_kind TEXT NOT NULL,matcher_value_sha256 TEXT NOT NULL,stdout_sha256 TEXT NOT NULL,evidence_fingerprint TEXT NOT NULL UNIQUE,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS execution_gates(gate_id INTEGER PRIMARY KEY AUTOINCREMENT,task_id TEXT NOT NULL REFERENCES task_registry(task_id),step_key TEXT NOT NULL,pre_checkpoint_no INTEGER NOT NULL,post_checkpoint_no INTEGER,action_fingerprint TEXT NOT NULL,pre_verdict TEXT NOT NULL,hitl_approved INTEGER NOT NULL DEFAULT 0,consumed INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL,UNIQUE(task_id,pre_checkpoint_no));
CREATE INDEX IF NOT EXISTS ix_steps_task_verified ON task_registry_steps(task_id,verified,step_no);
CREATE INDEX IF NOT EXISTS ix_evidence_task_step ON evidence_records(task_id,step_key,criterion_index);
CREATE INDEX IF NOT EXISTS ix_gates_task_step ON execution_gates(task_id,step_key,gate_id);
"""


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = conn()
    try:
        c.executescript(SCHEMA)
        # WAL gives verification a consistent read snapshot without blocking writers.
        if c.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() != "wal":
            raise RuntimeError("SQLite WAL mode unavailable")
    finally:
        c.close()
    os.chmod(DB_PATH, 0o600)


# ---- configuration validation ----
def shannon_bits_per_char(value: str) -> float:
    n = len(value)
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum((k / n) * math.log2(k / n) for k in counts.values())


def validate_secret(name: str, value: str) -> None:
    if len(value) < MIN_SECRET_LENGTH:
        raise RuntimeError(f"{name} missing/weak")
    if not SECRET_RE.fullmatch(value):
        raise RuntimeError(f"{name} has unsupported characters or placeholder markup")
    lowered = value.lower()
    if any(w in lowered for w in SECRET_PLACEHOLDER_WORDS):
        raise RuntimeError(f"{name} looks like a placeholder")
    if len(set(value)) < MIN_SECRET_DISTINCT_CHARS or shannon_bits_per_char(value) < MIN_SECRET_ENTROPY_BITS:
        raise RuntimeError(f"{name} has insufficient entropy")


def legacy_notary_keys() -> list[tuple[str,float]]:
    """Historical evidence roots with explicit signed-evidence timestamp ceilings.

    A retired root is never authorized for new evidence after its cutoff.
    Old audit and task contracts remain immutable.
    """
    if not LEGACY_NOTARY_KEYS_JSON:
        return []
    try:
        entries=json.loads(LEGACY_NOTARY_KEYS_JSON)
        if not isinstance(entries,list) or not 1<=len(entries)<=8:
            raise ValueError("legacy evidence root count invalid")
        out=[];seen={NOTARY_PUBLIC_KEY_B64,EXECUTOR_PUBLIC_KEY_B64}
        for entry in entries:
            if not isinstance(entry,dict) or set(entry)!={"public_b64","valid_before"}:
                raise ValueError("legacy evidence root schema invalid")
            pub=entry["public_b64"];end=entry["valid_before"]
            if not isinstance(pub,str) or pub in seen or type(end) not in (int,float) or not math.isfinite(end) or end<=0:
                raise ValueError("legacy evidence root duplicate or cutoff invalid")
            raw=base64.b64decode(pub,validate=True)
            if len(raw)!=32:raise ValueError("legacy evidence public key invalid")
            Ed25519PublicKey.from_public_bytes(raw)
            out.append((pub,float(end)));seen.add(pub)
        return out
    except (ValueError,TypeError,KeyError) as exc:
        raise RuntimeError("INVALID_LEGACY_NOTARY_TRUST_CONFIGURATION") from exc


def require_config() -> None:
    if ADMISSION_MODE not in ("enabled", "disabled"):
        raise RuntimeError("invalid EG admission mode")
    if not os.getenv("EVALUATION_GATEWAY_DB_PATH") or not os.getenv("EVALUATION_GATEWAY_EVIDENCE_ROOT"):
        raise RuntimeError("external canonical DB/evidence configuration required")
    validate_secret("API key", API_KEY)
    validate_secret("HITL key", HITL_KEY)
    validate_secret("audit HMAC key", AUDIT_HMAC_KEY)
    if ct(API_KEY, HITL_KEY):
        raise RuntimeError("HITL key must differ from API key")
    if ct(AUDIT_HMAC_KEY, API_KEY) or ct(AUDIT_HMAC_KEY, HITL_KEY):
        raise RuntimeError("audit HMAC key must differ from API/HITL keys")
    if not NOTARY_PUBLIC_KEY_B64:
        raise RuntimeError("evidence notary public key missing")
    try:
        raw = base64.b64decode(NOTARY_PUBLIC_KEY_B64, validate=True)
        Ed25519PublicKey.from_public_bytes(raw)
    except Exception as exc:
        raise RuntimeError("invalid evidence notary public key") from exc
    legacy_notary_keys()  # reject malformed historical trust roots at startup
    if ADMISSION_MODE == "enabled" and not EXECUTOR_PUBLIC_KEY_B64:
        raise RuntimeError("independent executor public key missing: fail closed")
    if EXECUTOR_PUBLIC_KEY_B64:
        try:
            raw_exec = base64.b64decode(EXECUTOR_PUBLIC_KEY_B64, validate=True)
            if len(raw_exec) != 32:
                raise ValueError("invalid executor trust root")
            Ed25519PublicKey.from_public_bytes(raw_exec)
            if ct(NOTARY_PUBLIC_KEY_B64, EXECUTOR_PUBLIC_KEY_B64):
                raise ValueError("executor and evidence notary trust roots must differ")
        except Exception as exc:
            raise RuntimeError("invalid or shared independent executor trust root") from exc
    if not PROTOCOL_PATH.is_file():
        raise RuntimeError("protocol missing")
    EVIDENCE_ROOT.mkdir(parents=True, exist_ok=True)
    if stat.S_IMODE(EVIDENCE_ROOT.stat().st_mode) & 0o022:
        raise RuntimeError("evidence root must not be group/other writable")
    if ANCHOR_PATH is None:
        raise RuntimeError("audit anchor path missing (EVALUATION_GATEWAY_ANCHOR_PATH)")
    ANCHOR_PATH.parent.mkdir(parents=True, exist_ok=True)
    if ANCHOR_PATH.parent.resolve() == DB_PATH.parent.resolve():
        raise RuntimeError("audit anchor must live in a different directory/volume than the database")


def require_key(x_evaluation_key: str | None = Header(default=None)):
    if not API_KEY:
        raise HTTPException(503, "gateway key unavailable")
    if x_evaluation_key is None or not ct(x_evaluation_key, API_KEY):
        raise HTTPException(401, "invalid evaluation key")


def require_hitl_key(x_evaluation_hitl_key: str | None) -> bool:
    return x_evaluation_hitl_key is not None and ct(x_evaluation_hitl_key, HITL_KEY)


# ---- hierarchy ----
def hierarchy(steps: list[dict[str, Any]]) -> list[str]:
    keys = [s["step_key"] for s in steps]
    if not keys or any(not STEP_RE.fullmatch(k) for k in keys):
        raise ValueError("invalid hierarchy")
    if any(not bool(s["required"]) for s in steps):
        raise ValueError("optional hierarchy node forbidden")
    keyset = set(keys)
    children: dict[str | None, list[str]] = {}
    for k in keys:
        p = k.rsplit(".", 1)[0] if "." in k else None
        if p and p not in keyset:
            raise ValueError(f"missing parent {p}")
        children.setdefault(p, []).append(k)
    for p, vals in children.items():
        ordered = sorted(vals, key=lambda x: int(x.rsplit(".", 1)[-1]))
        nums = [int(x.rsplit(".", 1)[-1]) for x in ordered]
        if nums != list(range(1, len(nums) + 1)):
            raise ValueError("non-contiguous siblings")
        children[p] = ordered
    roots = children.get(None, [])
    if not roots:
        raise ValueError("no root")
    for r in roots:
        if not children.get(r):
            raise ValueError("top-level step requires substep")
    preorder: list[str] = []
    post: list[str] = []

    def walk(k: str):
        preorder.append(k)
        for ch in children.get(k, []):
            walk(ch)
        post.append(k)
    for r in roots:
        walk(r)
    if keys != preorder:
        raise ValueError("registration must be canonical pre-order")
    return post


def validate_remedial_plan(steps: list[dict[str, Any]]) -> None:
    hierarchy(steps)
    by = {s["step_key"]: s for s in steps}
    roots = [s["step_key"] for s in steps if "." not in s["step_key"]]
    if roots != ["01", "02", "03"]:
        raise ValueError("remedial task must have top-level phases 01,02,03")
    for key, title in REMEDIAL_CORE_TITLES.items():
        if key not in by or by[key]["title"] != title:
            raise ValueError(f"remedial core step/title mismatch: {key}")


# ---- notarized evidence (manifest v4) ----
class EvalContext(NamedTuple):
    """Execution context every piece of evidence is bound to.

    checkpoint_ref: PRE_EXECUTION/FACT_CHECK -> request checkpoint_no; POST_EXECUTION -> pre_checkpoint_no of the gate.
    not_before: POST only -> creation time of that gate; evidence finished earlier is rejected.
    """
    phase: str
    checkpoint_ref: int
    not_before: float | None


class EvidenceResult(NamedTuple):
    ok: bool
    refuted: bool
    note: str
    fingerprint: str
    stdout_sha256: str
    matcher_kind: str
    matcher_value: str


def _reject(note: str, stdout_sha256: str = "") -> EvidenceResult:
    return EvidenceResult(False, False, note, "", stdout_sha256, "", "")


def step_identity(task_id: str, step_key: str, criterion_index: int, criterion: str, phase: str, checkpoint_ref: int) -> dict[str, Any]:
    return {"kind": "step_criterion", "eg_task_id": task_id, "step_key": step_key, "criterion_index": criterion_index, "criterion": criterion, "phase": phase, "checkpoint_no": checkpoint_ref}


def task_identity(task_id: str, criterion_index: int, criterion: str, phase: str, checkpoint_ref: int) -> dict[str, Any]:
    return {"kind": "task_criterion", "eg_task_id": task_id, "criterion_index": criterion_index, "criterion": criterion, "phase": phase, "checkpoint_no": checkpoint_ref}


def action_intent_fingerprint(action: Action | None) -> str:
    if action is None:
        return sha(canon(None))
    intent={"action_type":action.action_type,"target":action.target,
            "effect_class":action.effect_class,"reversible":action.reversible,
            "real_world_effect":action.real_world_effect}
    if action.payload_sha256 is not None:
        intent["payload_sha256"]=action.payload_sha256
    if action.payload_bytes is not None:
        intent["payload_bytes"]=action.payload_bytes
    return sha(canon(intent))


def proof_identity(task_id: str, step_key: str, purpose: str, action: Action, checkpoint_ref: int) -> dict[str, Any]:
    return {"kind": "action_proof", "eg_task_id": task_id, "step_key": step_key, "purpose": purpose, "action_intent_fingerprint": action_intent_fingerprint(action), "phase": "PRE_EXECUTION", "checkpoint_no": checkpoint_ref}


def valid_matcher(m: Any) -> bool:
    return (isinstance(m, dict) and set(m) == {"kind", "value"} and m["kind"] in MATCHER_KINDS
            and isinstance(m["value"], str) and m["value"].strip() != "" and len(m["value"]) <= MAX_MATCHER_VALUE_CHARS)


def secure_dir(p: Path, root: Path) -> bool:
    try:
        rp = p.resolve(strict=True); rr = root.resolve(strict=True); st = rp.stat()
    except OSError:
        return False
    if rr not in rp.parents or p.is_symlink() or not rp.is_dir():
        return False
    return st.st_uid == TRUSTED_UID and not (stat.S_IMODE(st.st_mode) & 0o022)


def secure_file(p: Path, directory: Path) -> bool:
    try:
        rp = p.resolve(strict=True); rd = directory.resolve(strict=True); st = rp.stat()
    except OSError:
        return False
    if rp.parent != rd or not rp.is_file() or p.is_symlink():
        return False
    return st.st_uid == TRUSTED_UID and not (stat.S_IMODE(st.st_mode) & 0o022)


def read_bounded(p: Path, limit: int) -> bytes | None:
    try:
        with open(p, "rb") as fh:
            data = fh.read(limit + 1)
    except OSError:
        return None
    return data if len(data) <= limit else None


def verify_evidence(ev: Evidence, identity: dict[str, Any], not_before: float | None = None) -> EvidenceResult:
    """Verify one notarized evidence bundle against the exact identity the gateway requires.

    The signed binding set must contain exactly one binding whose non-matcher fields equal `identity`
    (task, step, criterion text, phase, checkpoint/gate reference). The assertion applied to stdout.log is the
    matcher carried inside that signed binding; nothing about it is client-controlled.
    """
    if ev.source_type != "knid_task":
        return _reject("manual/self-declared evidence is non-authoritative")
    if not ev.reference or not ID_RE.fullmatch(ev.reference):
        return _reject("missing trusted reference")
    d = EVIDENCE_ROOT / ev.reference
    if not secure_dir(d, EVIDENCE_ROOT):
        return _reject("evidence directory missing or unsafe")
    statep, outp, metap = d / "state.json", d / "stdout.log", d / "evidence.json"
    if not all(secure_file(p, d) for p in (statep, outp, metap)):
        return _reject("evidence ownership/mode/path check failed")
    state_raw = read_bounded(statep, MAX_EVIDENCE_FILE_BYTES)
    if state_raw is None:
        return _reject("evidence state too large or unreadable")
    stdout_raw = read_bounded(outp, MAX_EVIDENCE_FILE_BYTES)
    if stdout_raw is None:
        return _reject("evidence stdout too large or unreadable")
    meta_raw = read_bounded(metap, MAX_EVIDENCE_FILE_BYTES)
    if meta_raw is None:
        return _reject("evidence metadata too large or unreadable")
    try:
        state = json.loads(state_raw); meta = json.loads(meta_raw)
    except ValueError:
        return _reject("evidence parse failed")
    if not isinstance(state, dict) or not isinstance(meta, dict):
        return _reject("evidence parse failed")
    if meta.get("manifest_version") != MANIFEST_VERSION:
        return _reject(f"legacy or unsupported evidence manifest; signed binding v{MANIFEST_VERSION} required")
    if meta.get("task_id") != ev.reference or state.get("task_id") != ev.reference:
        return _reject("evidence identity mismatch")
    sh, oh = sha(state_raw), sha(stdout_raw)
    if not ct(meta.get("state_sha256", ""), sh) or not ct(meta.get("stdout_sha256", ""), oh):
        return _reject("evidence content hash mismatch", oh)
    finished = state.get("finished_at")
    if isinstance(finished, bool) or not isinstance(finished, (int, float)) or not math.isfinite(finished):
        return _reject("completion timestamp missing", oh)
    if meta.get("finished_at") != finished:
        return _reject("signed completion timestamp mismatch", oh)
    age = datetime.now(timezone.utc).timestamp() - float(finished)
    if age < -CLOCK_SKEW_SECONDS or age > EVIDENCE_MAX_AGE_SECONDS:
        return _reject("stale evidence", oh)
    if not_before is not None and float(finished) < not_before - CLOCK_SKEW_SECONDS:
        return _reject("evidence predates execution gate", oh)
    if state.get("status") != "PASS" or state.get("exit_code") != 0:
        return _reject("source task not PASS", oh)
    bindings = meta.get("bindings")
    if not isinstance(bindings, list) or not bindings or len(bindings) > MAX_BINDINGS_PER_MANIFEST or any(not isinstance(x, dict) for x in bindings):
        return _reject("signed evidence bindings missing/invalid", oh)
    tokens = [canon(x) for x in bindings]
    if len(tokens) != len(set(tokens)):
        return _reject("duplicate signed evidence binding", oh)
    signed_payload = {"manifest_version": MANIFEST_VERSION, "task_id": ev.reference, "state_sha256": sh, "stdout_sha256": oh, "finished_at": finished, "bindings": bindings}
    sig_b64 = str(meta.get("notary_ed25519_signature_b64", ""))
    try:
        signature=base64.b64decode(sig_b64,validate=True)
        signed_bytes=canon(signed_payload).encode()
        valid_signature=False
        for key_b64,cutoff in [(NOTARY_PUBLIC_KEY_B64,None),*legacy_notary_keys()]:
            if cutoff is not None and float(finished)>cutoff:
                continue
            try:
                pub=Ed25519PublicKey.from_public_bytes(base64.b64decode(key_b64,validate=True))
                pub.verify(signature,signed_bytes)
                valid_signature=True
                break
            except Exception:
                pass
        if not valid_signature:
            raise ValueError("notary trust root does not match signature or retirement cutoff")
    except Exception:
        return _reject("invalid notary signature", oh)
    matches = [b for b in bindings if {k: v for k, v in b.items() if k != "matcher"} == identity]
    if not matches:
        return _reject("signed evidence binding mismatch", oh)
    if len(matches) != 1:
        return _reject("ambiguous signed evidence binding", oh)
    matcher = matches[0].get("matcher")
    if not valid_matcher(matcher):
        return _reject("signed matcher missing/invalid", oh)
    text = stdout_raw.decode("utf-8", errors="replace")
    if matcher["kind"] == "contains":
        supports = matcher["value"] in text
    elif matcher["kind"] == "not_contains":
        supports = matcher["value"] not in text
    else:
        supports = text.strip() == matcher["value"].strip()
    fp = sha(canon(signed_payload) + "|" + sig_b64 + "|" + canon(identity))
    return EvidenceResult(supports, not supports, "verified" if supports else "trusted evidence refutes signed matcher", fp, oh, matcher["kind"], matcher["value"])


# ---- authenticated audit ledger ----
def audit_record_mac(seq: int, record_hash: str) -> str:
    return hmac.new(AUDIT_HMAC_KEY.encode(), f"audit-record-v3|{seq}|{record_hash}".encode(), hashlib.sha256).hexdigest()


def anchor_mac(seq: int, head: str) -> str:
    return hmac.new(AUDIT_HMAC_KEY.encode(), f"audit-anchor-v1|{seq}|{head}".encode(), hashlib.sha256).hexdigest()


def db_head(c: sqlite3.Connection) -> tuple[int, str]:
    r = c.execute("SELECT seq,record_hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
    return (int(r["seq"]), r["record_hash"]) if r else (0, ZERO_HASH)


def append_audit(c: sqlite3.Connection, task_id: str, event_id: str, event_type: str, contract_hash: str, request_hash: str, request: dict[str, Any], response: dict[str, Any]) -> tuple[int, str]:
    prev_seq, ph = db_head(c)
    seq = prev_seq + 1
    created = now_iso()
    payload = {"seq": seq, "created_at": created, "task_id": task_id, "event_id": event_id, "event_type": event_type, "contract_hash": contract_hash, "request_hash": request_hash, "request": request, "response": response, "prev_hash": ph}
    rh = sha(ph + canon(payload))
    c.execute("INSERT INTO audit(seq,created_at,task_id,event_id,event_type,contract_hash,request_hash,request_json,response_json,prev_hash,record_hash,record_mac) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
              (seq, created, task_id, event_id, event_type, contract_hash, request_hash, canon(request), canon(response), ph, rh, audit_record_mac(seq, rh)))
    return seq, rh


def verify_audit_chain(c: sqlite3.Connection) -> bool:
    prev = ZERO_HASH
    expected_seq = 1
    try:
        for r in c.execute("SELECT * FROM audit ORDER BY seq"):
            request = json.loads(r["request_json"]); response = json.loads(r["response_json"])
            if int(r["seq"]) != expected_seq:
                return False
            payload = {"seq": r["seq"], "created_at": r["created_at"], "task_id": r["task_id"], "event_id": r["event_id"], "event_type": r["event_type"], "contract_hash": r["contract_hash"], "request_hash": r["request_hash"], "request": request, "response": response, "prev_hash": r["prev_hash"]}
            expected_hash = sha(prev + canon(payload))
            if r["prev_hash"] != prev or not ct(r["record_hash"], expected_hash):
                return False
            if not ct(r["record_mac"], audit_record_mac(expected_seq, expected_hash)):
                return False
            prev = r["record_hash"]
            expected_seq += 1
    except Exception:
        return False
    return True


# ---- external audit anchor: detects whole-database rollback and tail truncation ----
_ANCHOR_LOCK = threading.Lock()


def read_anchor() -> tuple[int, str] | None:
    assert ANCHOR_PATH is not None
    try:
        raw = ANCHOR_PATH.read_bytes()
    except FileNotFoundError:
        return None
    try:
        obj = json.loads(raw)
        seq, head, mac = obj["seq"], obj["head"], obj["mac"]
        if obj.get("version") != 1 or isinstance(seq, bool) or not isinstance(seq, int) or seq < 0 or not isinstance(head, str) or not isinstance(mac, str):
            raise ValueError
    except (ValueError, KeyError, TypeError) as exc:
        raise IntegrityFailure("audit anchor malformed") from exc
    if not ct(mac, anchor_mac(seq, head)):
        raise IntegrityFailure("audit anchor authentication failed")
    return seq, head


def write_anchor(seq: int, head: str, allow_regress: bool = False) -> None:
    assert ANCHOR_PATH is not None
    with _ANCHOR_LOCK:
        current = read_anchor()
        if current is not None and seq <= current[0] and not allow_regress:
            return
        body = canon({"version": 1, "seq": seq, "head": head, "mac": anchor_mac(seq, head)}).encode()
        tmp = ANCHOR_PATH.with_name(ANCHOR_PATH.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, body); os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, ANCHOR_PATH)
        dfd = os.open(ANCHOR_PATH.parent, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)


_UNSET: Any = object()


def check_anchor(c: sqlite3.Connection, anchor: Any = _UNSET) -> None:
    """Compare the ledger with the external anchor.

    `anchor` may be pre-read BEFORE the caller's read snapshot was taken: the anchor is only ever written after
    a commit, so a pre-read anchor can never be ahead of a later snapshot unless history was rolled back.
    """
    seq, head = db_head(c)
    if anchor is _UNSET:
        anchor = read_anchor()
    if anchor is None:
        if seq != 0:
            raise IntegrityFailure("audit anchor missing for non-empty ledger")
        write_anchor(0, ZERO_HASH)
        return
    aseq, ahead = anchor
    if aseq > seq:
        raise IntegrityFailure("audit rollback or truncation detected")
    if aseq == 0:
        if not ct(ahead, ZERO_HASH):
            raise IntegrityFailure("audit anchor inconsistent")
    else:
        r = c.execute("SELECT record_hash FROM audit WHERE seq=?", (aseq,)).fetchone()
        if r is None or not ct(r["record_hash"], ahead):
            raise IntegrityFailure("audit history diverges from anchor")
    if seq > aseq:
        raise IntegrityFailure("audit anchor lags committed ledger; offline recovery required")


def guard_anchor(c: sqlite3.Connection) -> None:
    """Fail closed on the SAME SQLite write transaction used for authorization.

    Do not rely on health's time-bounded cache or a different connection:
    anchor-only checks cannot detect an altered materialized task row.
    """
    try:
        check_anchor(c)
        if not verify_audit_chain(c) or not verify_materialized_state(c):
            raise IntegrityFailure("full authenticated audit/materialized state invalid")
    except (IntegrityFailure, OSError, sqlite3.DatabaseError) as exc:
        LOG.error("EG mutation integrity guard failed: %s", exc)
        raise HTTPException(503, {"code": "EG_INTEGRITY_FAILED_NO_MUTATION"}) from exc


def guard_integrity_read(c: sqlite3.Connection) -> None:
    """Read worker-admission state only from an integrity-checked snapshot."""
    try:
        check_anchor(c)
        if not verify_audit_chain(c) or not verify_materialized_state(c):
            raise IntegrityFailure("untrusted task state projection")
    except (IntegrityFailure, OSError, sqlite3.DatabaseError) as exc:
        LOG.error("EG admission read integrity guard failed: %s", exc)
        raise HTTPException(503, {"code": "EG_INTEGRITY_FAILED_NO_ADMISSION"}) from exc


def commit_audited(c: sqlite3.Connection, task_id: str, event_id: str, event_type: str, contract_hash: str, request_hash: str, request: dict[str, Any], response: dict[str, Any]) -> dict[str, Any]:
    seq, rh = append_audit(c, task_id, event_id, event_type, contract_hash, request_hash, request, response)
    c.commit()
    try:
        write_anchor(seq, rh)
    except Exception as exc:
        LOG.exception("audit anchor write failed after database commit; offline recovery required")
        _integrity_cache.update(ok=False, at=time.monotonic())
        raise HTTPException(503, "audit anchor persistence failed; commit outcome requires reconciliation") from exc
    return response


# ---- integrity verification (single-flight, time-bounded cache) ----
_INTEGRITY_LOCK = threading.Lock()
_integrity_cache: dict[str, Any] = {"ok": False, "at": None}


def _full_verification() -> bool:
    for attempt in range(ANCHOR_SETTLE_ATTEMPTS):
        try:
            require_config()
            pre_anchor = read_anchor()
            c = conn()
            try:
                c.execute("BEGIN")
                c.execute("SELECT 1 FROM audit LIMIT 1").fetchall()
                if not verify_audit_chain(c):
                    return False
                try:
                    check_anchor(c, anchor=pre_anchor)
                except IntegrityFailure:
                    # A concurrent commit may be between DB commit and durable anchor write.
                    if attempt + 1 == ANCHOR_SETTLE_ATTEMPTS:
                        raise
                    time.sleep(ANCHOR_SETTLE_INTERVAL_SECONDS)
                    continue
                return verify_materialized_state(c)
            finally:
                c.close()
        except Exception as exc:
            LOG.error("integrity verification failed: %s", exc)
            return False
    return False


def integrity_ok(force: bool = False) -> bool:
    with _INTEGRITY_LOCK:
        at = _integrity_cache["at"]
        if not force and at is not None and (time.monotonic() - at) < INTEGRITY_CACHE_SECONDS:
            return bool(_integrity_cache["ok"])
        ok = _full_verification()
        _integrity_cache.update(ok=ok, at=time.monotonic())
        return ok


# ---- materialized-state verification ----
def verify_materialized_state(c: sqlite3.Connection) -> bool:
    try:
        return _verify_materialized_state(c)
    except Exception:
        LOG.exception("materialized-state verification error")
        return False


def _verify_materialized_state(c: sqlite3.Connection) -> bool:
    intake: dict[str, tuple[str, dict[str, Any]]] = {}
    evals: dict[str, list[tuple[int, str, dict[str, Any], dict[str, Any]]]] = {}
    eval_stream: list[tuple[int, str, dict[str, Any], dict[str, Any]]] = []
    aborts: dict[str, tuple[int, dict[str, Any]]] = {}
    suspensions: dict[str, list[tuple[int, str, dict[str, Any], dict[str, Any]]]] = {}
    reconciliations: dict[str, list[tuple[int, dict[str, Any], dict[str, Any]]]] = {}
    expected_evidence: dict[str, dict[str, Any]] = {}
    for row in c.execute("SELECT seq,event_id,task_id,event_type,contract_hash,request_json,response_json FROM audit ORDER BY seq"):
        rq = json.loads(row["request_json"]); rs = json.loads(row["response_json"]); et = row["event_type"]; tid = row["task_id"]
        if et == "TASK_INTAKE":
            if tid in intake:
                return False
            intake[tid] = (row["contract_hash"], rq)
        elif et == "EVALUATION":
            mats = rs.get("materialized_evidence", [])
            if not isinstance(mats, list):
                return False
            for m in mats:
                if not isinstance(m, dict) or "evidence_fingerprint" not in m:
                    return False
                fp = m["evidence_fingerprint"]
                if fp in expected_evidence and expected_evidence[fp] != m:
                    return False
                expected_evidence[fp] = m
            item = (int(row["seq"]), row["event_id"], {"phase": rq.get("phase"), "step_key": rq.get("step_key"), "checkpoint_no": rq.get("checkpoint_no")}, {k: rs.get(k) for k in EVAL_RESPONSE_KEYS})
            evals.setdefault(tid, []).append(item)
            eval_stream.append((int(row["seq"]), tid, item[2], item[3]))
        elif et == "FACT_CHECK":
            if rs.get("checkpoint_no") != rq.get("checkpoint_no") or rs.get("step_verified") is not False:
                return False
        elif et == "TASK_ABORT":
            if tid in aborts:
                return False
            aborts[tid] = (int(row["seq"]), rs)
        elif et == "TASK_RECONCILE":
            if (not rq.get("executor_public_key_b64") or rq.get("task_id")!=tid or rq.get("step_key")!=rs.get("step_key")
                or rq.get("checkpoint_no")!=rs.get("checkpoint_no")
                or rs.get("status")!="IN_PROGRESS"
                or rs.get("reconciled_effect")!="NOT_EXECUTED"):
                return False
            reconciliations.setdefault(tid,[]).append((int(row["seq"]),rq,rs))
        elif et in ("TASK_PAUSE", "TASK_RESUME"):
            if (rq.get("task_id") != tid
                    or rq.get("checkpoint_no") != rs.get("checkpoint_no")
                    or not isinstance(rs.get("status"), str)
                    or rs.get("status") not in ("PAUSED","RECOVERY_PENDING","IN_PROGRESS")):
                return False
            suspensions.setdefault(tid,[]).append((int(row["seq"]),et,rq,rs))
        else:
            return False

    tasks = c.execute("SELECT * FROM task_registry ORDER BY task_id").fetchall()
    task_rows = {t["task_id"]: t for t in tasks}
    if set(task_rows) != set(intake):
        return False

    # Immutable task contract + immutable plan.
    for task_id, t in task_rows.items():
        contract_hash, rq = intake[task_id]
        steps = rq["steps"]
        contract = {"task_id": rq["task_id"], "agent": rq["agent"], "original_instruction": rq["original_instruction"], "acceptance_criteria": rq["acceptance_criteria"], "steps": steps, "protocol_hash": rq["protocol_hash"], "task_kind": rq.get("task_kind", "NORMAL"), "remedial_for_task_id": rq.get("remedial_for_task_id"), "remedial_trigger_step_key": rq.get("remedial_trigger_step_key"), "causal_step_key": rq.get("causal_step_key"), "remedial_origin_checkpoint_no": rq.get("remedial_origin_checkpoint_no"), "remedial_attempt": rq.get("remedial_attempt")}
        if contract_hash != t["contract_hash"] or sha(canon(contract)) != t["contract_hash"]:
            return False
        immutable = {"agent": rq["agent"], "original_instruction": rq["original_instruction"], "task_kind": rq.get("task_kind", "NORMAL"), "remedial_for_task_id": rq.get("remedial_for_task_id"), "remedial_trigger_step_key": rq.get("remedial_trigger_step_key"), "causal_step_key": rq.get("causal_step_key"), "remedial_origin_checkpoint_no": rq.get("remedial_origin_checkpoint_no"), "remedial_attempt": rq.get("remedial_attempt")}
        if any(t[k] != v for k, v in immutable.items()):
            return False
        if json.loads(t["acceptance_criteria_json"]) != rq["acceptance_criteria"]:
            return False
        material = [dict(r) for r in c.execute("SELECT step_key,title,criteria_json,required FROM task_registry_steps WHERE task_id=? ORDER BY step_no", (task_id,))]
        expected = [{"step_key": x["step_key"], "title": x["title"], "criteria_json": canon(x["acceptance_criteria"]), "required": 1} for x in steps]
        if material != expected:
            return False

    # Checkpoints must be an exact projection of authenticated EVALUATION audit responses.
    for task_id, t in task_rows.items():
        evs = evals.get(task_id, [])
        cps = c.execute("SELECT * FROM task_registry_checkpoints WHERE task_id=? ORDER BY checkpoint_no", (task_id,)).fetchall()
        if len(cps) != len(evs):
            return False
        for expected_no, ((_seq, event_id, rq, rs), cp) in enumerate(zip(evs, cps), 1):
            if rq["phase"] not in ("PRE_EXECUTION", "POST_EXECUTION"):
                return False
            if rq["checkpoint_no"] != expected_no - 1 or rs["checkpoint_no"] != expected_no:
                return False
            if int(cp["checkpoint_no"]) != expected_no or cp["event_id"] != event_id or cp["task_id"] != task_id:
                return False
            if cp["step_key"] != rs["step_key"] or cp["verdict"] != rs["verdict"] or bool(cp["verified"]) != bool(rs["step_verified"]):
                return False
            if cp["evidence_digest"] != rs["evidence_digest"]:
                return False
        if int(t["checkpoint_no"]) != len(cps):
            return False

        # Historical step state is derived from checkpoints and cannot be rolled back or rewritten.
        for st in c.execute("SELECT * FROM task_registry_steps WHERE task_id=? ORDER BY step_no", (task_id,)):
            scps = [cp for cp in cps if cp["step_key"] == st["step_key"]]
            verified_cps = [cp for cp in scps if cp["verified"]]
            if len(verified_cps) > 1:
                return False
            expected_verified = 1 if verified_cps else 0
            if int(st["verified"]) != expected_verified:
                return False
            if st["status"] != ("VERIFIED" if expected_verified else "PLANNED"):
                return False
            expected_last = scps[-1]["verdict"] if scps else None
            if st["last_verdict"] != expected_last:
                return False
            if verified_cps and verified_cps[0]["verdict"] != "VERIFIED_PASS":
                return False
            if verified_cps and scps[-1]["checkpoint_no"] != verified_cps[0]["checkpoint_no"]:
                return False

    # Evidence table must equal the authenticated materialization summaries exactly.
    actual_evidence = {r["evidence_fingerprint"]: {
        "task_id": r["task_id"], "step_key": r["step_key"], "criterion_index": int(r["criterion_index"]), "purpose": r["purpose"], "source_type": r["source_type"],
        "reference": r["reference"], "matcher_kind": r["matcher_kind"], "matcher_value_sha256": r["matcher_value_sha256"], "stdout_sha256": r["stdout_sha256"], "evidence_fingerprint": r["evidence_fingerprint"],
    } for r in c.execute("SELECT * FROM evidence_records")}
    if actual_evidence != expected_evidence:
        return False

    # Execution gates: exact projection of PRE audit records and the verified POST that consumed each gate.
    expected_gates: list[dict[str, Any]] = []
    gate_index: dict[tuple[str, str, int], dict[str, Any]] = {}
    for _seq, tid, rq, rs in eval_stream:
        if rq["phase"] == "PRE_EXECUTION":
            g = {"task_id": tid, "step_key": rq["step_key"], "pre_checkpoint_no": int(rs["checkpoint_no"]), "post_checkpoint_no": None, "action_fingerprint": rs["action_fingerprint"], "pre_verdict": rs["verdict"], "hitl_approved": 1 if rs["hitl_approved"] else 0, "consumed": 0}
            gate_index[(tid, rq["step_key"], g["pre_checkpoint_no"])] = g
            expected_gates.append(g)
        elif rs["step_verified"] is True:
            g = gate_index.get((tid, rq["step_key"], rs["gate_checkpoint_no"]))
            if g is None or g["consumed"] or g["pre_verdict"] != "READY_TO_EXECUTE":
                return False
            g["consumed"] = 1
            g["post_checkpoint_no"] = int(rs["checkpoint_no"])
    for tid, events in reconciliations.items():
        for _seq, rq, rs in events:
            gate_key=(tid,rq["step_key"],rs["gate_checkpoint_no"])
            g=gate_index.get(gate_key)
            if (g is None or g["consumed"] or g["pre_verdict"]!="READY_TO_EXECUTE"
                or g["action_fingerprint"]!=rs.get("action_fingerprint")
                or rq.get("action") is None
                or action_fingerprint(Action(**rq["action"]))!=g["action_fingerprint"]):
                return False
            saved=c.execute("SELECT created_at FROM execution_gates WHERE task_id=? AND step_key=? AND pre_checkpoint_no=?",gate_key).fetchone()
            if (not saved or not verify_no_effect(rq.get("proof"),
                    public_b64=rq["executor_public_key_b64"],task_id=tid,
                    step_key=rq["step_key"],gate_checkpoint_no=g["pre_checkpoint_no"],
                    action_fingerprint=g["action_fingerprint"],target=rq["action"]["target"],
                    gate_created_at=saved[0])):
                return False
            g["consumed"]=1
    actual_gates = [{"task_id": r["task_id"], "step_key": r["step_key"], "pre_checkpoint_no": int(r["pre_checkpoint_no"]), "post_checkpoint_no": int(r["post_checkpoint_no"]) if r["post_checkpoint_no"] is not None else None, "action_fingerprint": r["action_fingerprint"], "pre_verdict": r["pre_verdict"], "hitl_approved": int(r["hitl_approved"]), "consumed": int(r["consumed"])} for r in c.execute("SELECT * FROM execution_gates ORDER BY gate_id")]
    if actual_gates != expected_gates:
        return False

    # Derived task lifecycle, including effects from linked remedial tasks and explicit aborts.
    derived: dict[str, dict[str, Any]] = {}
    for task_id, t in task_rows.items():
        evs = evals.get(task_id, [])
        latest_rs = evs[-1][3] if evs else None
        contract_status = (latest_rs.get("contract_status") or "OPEN") if latest_rs else "OPEN"
        status = "REGISTERED" if not evs else ("COMPLETED" if contract_status == "SATISFIED" else ("TASK_TERMINATED_UNRESOLVED" if contract_status == "UNRESOLVED" else "IN_PROGRESS"))
        completed_at = latest_rs.get("completed_at") if latest_rs and contract_status in ("SATISFIED", "UNRESOLVED") else None
        remedial_outcome = None; recovery_strategy = None
        if t["task_kind"] == "REMEDIAL" and latest_rs and contract_status in ("SATISFIED", "UNRESOLVED"):
            remedial_outcome = latest_rs.get("remedial_outcome"); recovery_strategy = latest_rs.get("recovery_strategy")
        derived[task_id] = {"contract_status": contract_status, "status": status, "completed_at": completed_at, "failure_reset_checkpoint": 0, "remedial_outcome": remedial_outcome, "recovery_strategy": recovery_strategy}

    remedials = sorted((t for t in tasks if t["task_kind"] == "REMEDIAL"), key=lambda x: (x["remedial_for_task_id"] or "", int(x["remedial_attempt"] or 0)))
    for r in remedials:
        d = derived[r["task_id"]]
        orig = r["remedial_for_task_id"]
        if not orig or orig not in derived:
            return False
        if d["contract_status"] == "SATISFIED" and d["remedial_outcome"] == "RECOVERED":
            derived[orig]["failure_reset_checkpoint"] = int(r["remedial_origin_checkpoint_no"])
        elif d["contract_status"] == "UNRESOLVED" and d["remedial_outcome"] == "UNRESOLVED":
            derived[orig]["contract_status"] = "UNRESOLVED"; derived[orig]["status"] = "TASK_TERMINATED_UNRESOLVED"; derived[orig]["completed_at"] = d["completed_at"]

    last_eval_seq = {tid: items[-1][0] for tid, items in evals.items()}
    # Pausing never changes acceptance/checkpoints; only the newest audited
    # lifecycle event after the last evaluation may alter materialized status.
    for tid, events in suspensions.items():
        if tid not in derived:
            return False
        phase="ACTIVE"
        for seq, kind, rq, rs in events:
            if kind=="TASK_PAUSE":
                if phase=="PAUSED" or rs.get("status")!="PAUSED":
                    return False
                phase="PAUSED"
            else:
                if phase!="PAUSED" or rs.get("status") not in ("IN_PROGRESS","RECOVERY_PENDING"):
                    return False
                phase="ACTIVE"
        last_seq,kind,rq,rs=events[-1]
        if last_seq > last_eval_seq.get(tid,0):
            if derived[tid]["contract_status"] != "OPEN":
                return False
            if rs["status"]=="RECOVERY_PENDING":
                gates=[g for g in expected_gates if g["task_id"]==tid and
                       not g["consumed"] and g["pre_verdict"]=="READY_TO_EXECUTE"]
                if not gates and not any(ev[0] > last_seq for ev in reconciliations.get(tid, [])):
                    return False
            derived[tid]["status"]=rs["status"]
        elif (rs["status"] == "RECOVERY_PENDING"
              and derived[tid]["contract_status"] == "OPEN"):
            # A signed resume remains in RECOVERY_PENDING across any number of
            # failed POST checks on the SAME gate; only VERIFIED POST consumes it.
            # Rebuild this from the append-only audit, never trust mutable status.
            subsequent=[event for event in evals.get(tid,[]) if event[0]>last_seq]
            if subsequent and all(
                event[2]["phase"]=="POST_EXECUTION"
                and event[3]["step_verified"] is False
                for event in subsequent
            ):
                derived[tid]["status"]="RECOVERY_PENDING"
    for tid, events in reconciliations.items():
        if tid not in derived: return False
        latest_seq=events[-1][0]
        last_suspend=max((e[0] for e in suspensions.get(tid,[])),default=0)
        if latest_seq>max(last_eval_seq.get(tid,0),last_suspend):
            if derived[tid]["contract_status"]!="OPEN":return False
            derived[tid]["status"]="IN_PROGRESS"
    for tid, (aseq, ars) in aborts.items():
        if tid not in derived or derived[tid]["contract_status"] in ("SATISFIED", "UNRESOLVED"):
            return False
        if last_eval_seq.get(tid, 0) > aseq or ars.get("contract_status") != "ABORTED":
            return False
        derived[tid].update(contract_status="ABORTED", status="TASK_ABORTED", completed_at=ars.get("completed_at"), remedial_outcome=None, recovery_strategy=None)

    for task_id, t in task_rows.items():
        d = derived[task_id]
        if t["contract_status"] != d["contract_status"] or t["status"] != d["status"] or t["completed_at"] != d["completed_at"]:
            return False
        if int(t["failure_reset_checkpoint"]) != int(d["failure_reset_checkpoint"]):
            return False
        if t["remedial_outcome"] != d["remedial_outcome"] or t["recovery_strategy"] != d["recovery_strategy"]:
            return False
        if t["contract_status"] == "SATISFIED":
            if c.execute("SELECT COUNT(*) FROM task_registry_steps WHERE task_id=? AND verified=0", (task_id,)).fetchone()[0] != 0:
                return False
            criteria = json.loads(t["acceptance_criteria_json"])
            got = {r[0] for r in c.execute("SELECT DISTINCT criterion_index FROM evidence_records WHERE task_id=? AND step_key='__TASK__' AND purpose LIKE 'task_criterion:%'", (task_id,))}
            if got != set(range(len(criteria))):
                return False
    return True


# ---- task helpers ----
def latest_linked_remedial(c: sqlite3.Connection, original_task_id: str):
    return c.execute("SELECT * FROM task_registry WHERE task_kind='REMEDIAL' AND remedial_for_task_id=? ORDER BY remedial_attempt DESC LIMIT 1", (original_task_id,)).fetchone()


def failed_attempts(c: sqlite3.Connection, task_id: str, step_key: str, after_checkpoint: int = 0) -> int:
    return c.execute("SELECT COUNT(*) FROM task_registry_checkpoints WHERE task_id=? AND step_key=? AND checkpoint_no>? AND verified=0 AND verdict IN ('UNVERIFIED','VERIFIED_FAIL','BLOCKED','CONFLICT')", (task_id, step_key, after_checkpoint)).fetchone()[0]


def replay(c: sqlite3.Connection, event_id: str, request_hash: str):
    r = c.execute("SELECT request_hash,response_json FROM audit WHERE event_id=?", (event_id,)).fetchone()
    if not r:
        return None
    if not ct(r["request_hash"], request_hash):
        raise HTTPException(409, "event_id reused with different request")
    out = json.loads(r["response_json"]); out["idempotent_replay"] = True
    return out


def current_step(c: sqlite3.Connection, task_id: str) -> tuple[list[sqlite3.Row], list[str], str | None]:
    rows = c.execute("SELECT * FROM task_registry_steps WHERE task_id=? ORDER BY step_no", (task_id,)).fetchall()
    post = hierarchy([{"step_key": r["step_key"], "required": bool(r["required"])} for r in rows])
    verified = {r["step_key"] for r in rows if r["verified"]}
    return rows, post, next((k for k in post if k not in verified), None)


def action_fingerprint(action: Action | None) -> str:
    # Excluding absent v3.1.7 fields retains the *original* fingerprint for
    # historical signed pending PRE gates; never backfill an old authorization.
    return sha(canon(action.model_dump(mode="json",exclude_none=True) if action is not None else None))


def action_check(task_id: str, step_key: str, action: Action | None, checkpoint_ref: int) -> tuple[Verdict, str, list[tuple[str, Evidence, EvidenceResult]]]:
    if action is None:
        return Verdict.READY_TO_EXECUTE, "pre-execution verified; no material action", []
    effect = int(action.effect_class[1])
    if effect >= 3 or action.real_world_effect:
        return Verdict.REQUIRES_HITL, "material/real-world action requires human authorization", []
    if effect <= 1:
        return Verdict.READY_TO_EXECUTE, "low-effect action with verified factual criteria", []
    if not action.reversible:
        return Verdict.REQUIRES_HITL, "E2 must be reversible for automatic readiness", []
    by = {p.purpose: p.evidence for p in action.proofs}
    needed = {"sandbox_pass", "rollback_ready", "reversible"}
    if set(by) != needed:
        return Verdict.UNVERIFIED, "E2 requires exactly one notarized sandbox, rollback, and reversibility proof", []
    rec: list[tuple[str, Evidence, EvidenceResult]] = []
    for purpose in sorted(needed):
        ev = by[purpose]
        res = verify_evidence(ev, proof_identity(task_id, step_key, purpose, action, checkpoint_ref))
        if not res.ok:
            return Verdict.UNVERIFIED, f"action proof {purpose} failed: {res.note}", []
        rec.append((purpose, ev, res))
    return Verdict.READY_TO_EXECUTE, "E2 independently proved reversible with action-bound sandbox and rollback evidence", rec


def validate_claim_coverage(criteria: list[str], claims: list[Claim], code: str) -> None:
    indices = [cl.criterion_index for cl in claims]
    if sorted(indices) != list(range(len(criteria))) or len(indices) != len(set(indices)):
        raise HTTPException(409, {"code": code, "expected": list(range(len(criteria))), "provided": indices})
    for cl in claims:
        if cl.claim != criteria[cl.criterion_index]:
            raise HTTPException(409, {"code": "CLAIM_CRITERION_MISMATCH", "criterion_index": cl.criterion_index})


def verify_claim_set(task_id: str, step_key: str, criteria: list[str], claims: list[Claim], scope: str, ctx: EvalContext) -> tuple[bool, list[dict[str, Any]], list[tuple[int, Evidence, EvidenceResult]]]:
    all_pass = True
    notes: list[dict[str, Any]] = []
    rows: list[tuple[int, Evidence, EvidenceResult]] = []
    for cl in claims:
        support = False; refute = False; trusted_seen = False
        if scope == "step":
            identity = step_identity(task_id, step_key, cl.criterion_index, criteria[cl.criterion_index], ctx.phase, ctx.checkpoint_ref)
        else:
            identity = task_identity(task_id, cl.criterion_index, criteria[cl.criterion_index], ctx.phase, ctx.checkpoint_ref)
        for ev in cl.evidence:
            if ev.source_type == "knid_task":
                trusted_seen = True
            res = verify_evidence(ev, identity, ctx.not_before)
            notes.append({"scope": scope, "criterion": cl.criterion_index, "reference": ev.reference, "note": res.note})
            if res.ok:
                support = True; rows.append((cl.criterion_index, ev, res))
            elif res.refuted:
                refute = True
        if not trusted_seen or not support or refute:
            all_pass = False
    return all_pass, notes, rows


def materialize_evidence(c: sqlite3.Connection, task_id: str, step_key: str, criterion_index: int, purpose: str, ev: Evidence, res: EvidenceResult, created_at: str) -> dict[str, Any]:
    materialized_fp = sha(canon({"task_id": task_id, "step_key": step_key, "criterion_index": criterion_index, "purpose": purpose, "evidence_fp": res.fingerprint}))
    summary = {"task_id": task_id, "step_key": step_key, "criterion_index": criterion_index, "purpose": purpose, "source_type": ev.source_type, "reference": ev.reference, "matcher_kind": res.matcher_kind, "matcher_value_sha256": sha(res.matcher_value), "stdout_sha256": res.stdout_sha256, "evidence_fingerprint": materialized_fp}
    c.execute("INSERT OR IGNORE INTO evidence_records(task_id,step_key,criterion_index,purpose,source_type,reference,matcher_kind,matcher_value_sha256,stdout_sha256,evidence_fingerprint,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
              (task_id, step_key, criterion_index, purpose, ev.source_type, ev.reference, res.matcher_kind, summary["matcher_value_sha256"], res.stdout_sha256, materialized_fp, created_at))
    actual = c.execute("SELECT task_id,step_key,criterion_index,purpose,source_type,reference,matcher_kind,matcher_value_sha256,stdout_sha256,evidence_fingerprint FROM evidence_records WHERE evidence_fingerprint=?", (materialized_fp,)).fetchone()
    if not actual or dict(actual) != summary:
        raise RuntimeError("evidence materialization collision/inconsistency")
    return summary


def iso_epoch(value: str) -> float:
    return datetime.fromisoformat(value).timestamp()


def latest_gate(c: sqlite3.Connection, task_id: str, step_key: str):
    return c.execute("SELECT * FROM execution_gates WHERE task_id=? AND step_key=? ORDER BY gate_id DESC LIMIT 1", (task_id, step_key)).fetchone()


def task_guidance(c: sqlite3.Connection, t: sqlite3.Row, current: str | None) -> dict[str, Any]:
    """Machine-readable next action for reconciliation; mirrors the preconditions enforced by /v1/evaluate."""
    terminal = t["contract_status"] in TERMINAL_STATUSES
    g: dict[str, Any] = {"terminal": terminal, "next_action": "STOP" if terminal else "EXECUTE_OR_EVALUATE", "blocked_reason": None, "remedial_task_id": None}
    if terminal or current is None:
        return g
    if t["status"] == "PAUSED":
        g.update(next_action="RESUME_AFTER_RECONCILIATION",
                 blocked_reason="TASK_PAUSED")
        return g
    if t["status"] == "RECOVERY_PENDING":
        g.update(next_action="RECONCILE_EXISTING_EXECUTION",
                 blocked_reason="EFFECT_UNKNOWN_NO_REEXECUTION")
        return g
    if t["task_kind"] == "NORMAL":
        linked = latest_linked_remedial(c, t["task_id"])
        if linked and linked["contract_status"] == "OPEN":
            g.update(next_action="COMPLETE_REMEDIAL", blocked_reason="ORIGINAL_TASK_BLOCKED_BY_REMEDIAL", remedial_task_id=linked["task_id"])
        elif failed_attempts(c, t["task_id"], current, int(t["failure_reset_checkpoint"])) >= MAX_LOCAL_REMEDIATION_FAILURES:
            g.update(next_action="REGISTER_REMEDIAL", blocked_reason="REMEDIAL_ESCALATION_REQUIRED")
    elif failed_attempts(c, t["task_id"], current, 0) >= MAX_REMEDIAL_STEP_FAILURES:
        g.update(next_action="SUBMIT_EXHAUSTED_DISPOSITION", blocked_reason="REMEDIAL_STEP_EXHAUSTED")
    return g


# ---- API ----
@app.get("/health")
def health():
    """Unauthenticated liveness + integrity gate. Reveals nothing beyond PASS/FAIL; cost is bounded by the single-flight cache."""
    if not integrity_ok():
        raise HTTPException(503, "integrity check failed")
    return {"status": "PASS"}


@app.get("/v1/protocol", dependencies=[Depends(require_key)])
def protocol():
    return {"version": PROTOCOL_VERSION, "hash": protocol_hash(),
            "admission_mode": ADMISSION_MODE,
            "executor_capabilities": ([{"action_type":"read","effect_class":"E0"},
                                       {"action_type":"write","effect_class":"E2"}]
                                      if ADMISSION_MODE=="enabled" and EXECUTOR_OUTPUT_ROOT else []),
            "executor_target_root_provisioned":bool(EXECUTOR_OUTPUT_ROOT),
            "executor_target_suffixes":[".txt",".json"],
            "document": PROTOCOL_PATH.read_text(encoding="utf-8")}


def _registered_protocol_hash(c: sqlite3.Connection, task_id: str) -> str | None:
    """Only the original authenticated registration can authorize an old hash."""
    row = c.execute(
        "SELECT request_json FROM audit WHERE task_id=? AND event_type='TASK_INTAKE' "
        "ORDER BY seq ASC LIMIT 1", (task_id,)).fetchone()
    if row is None:
        return None
    try:
        request = json.loads(row["request_json"])
        return request["protocol_hash"]
    except (KeyError, ValueError, TypeError):
        return None


def _require_registered_protocol(
    c: sqlite3.Connection, task_id: str, supplied_hash: str
) -> None:
    """One validation engine, immutable task-specific protocol provenance.

    The user task's original protocol is a signed registration field.
    Old hashes never grant access to an alternate/older code path.
    """
    original = _registered_protocol_hash(c, task_id)
    if original is None or not ct(supplied_hash, original):
        raise HTTPException(428, {"code": "IMMUTABLE_TASK_PROTOCOL_MISMATCH"})


def configured_high_effect_capabilities() -> list[AdapterCapability]:
    """One typed registry; never equate configured records with live admission."""
    if not HIGH_EFFECT_CAPABILITIES_JSON:
        return []
    try:
        entries=json.loads(HIGH_EFFECT_CAPABILITIES_JSON)
        if not isinstance(entries,list) or len(entries)>16:
            return []
        caps=[AdapterCapability(**entry) for entry in entries]
        for cap in caps: cap.validate()
        identifiers=[(cap.adapter_id,cap.action_type,cap.effect_class,cap.target_prefix) for cap in caps]
        if len(identifiers)!=len(set(identifiers)):
            return []
        return caps
    except Exception:
        return []


def high_effect_catalog() -> list[dict]:
    """Diagnostic metadata only, never advertise an online E3-E5 executor."""
    return [{"adapter_id":cap.adapter_id,"effect_class":cap.effect_class,
             "action_type":cap.action_type,"availability":"CI_ONLY_NOT_PRODUCTION"
             if HIGH_EFFECT_CI_FIXTURE_ENABLED else "UNPROVISIONED"}
            for cap in configured_high_effect_capabilities()]


def high_effect_capability(action: Action) -> AdapterCapability | None:
    # The sole repository adapter is in-process and CI-only. A production
    # provisioned transport must provide independent authenticated liveness
    # before this can be enabled for real external effects (see Issue #26).
    if not HIGH_EFFECT_CI_FIXTURE_ENABLED or action.effect_class not in ("E3","E4","E5"):
        return None
    matches=[cap for cap in configured_high_effect_capabilities()
             if cap.action_type==action.action_type and cap.effect_class==action.effect_class
             and target_within_scope(action.target,cap.target_prefix)]
    return matches[0] if len(matches)==1 else None



def pinned_high_effect_gate(c: sqlite3.Connection, task_id: str,
                            step_key: str, checkpoint_no: int, action: Action) -> dict:
    """Get original HMAC-audited, immutable PRE signer; never use mutable registry."""
    for row in c.execute("SELECT response_json FROM audit WHERE task_id=? AND event_type='EVALUATION' ORDER BY seq",
                         (task_id,)):
        response=json.loads(row["response_json"])
        if response.get("checkpoint_no")!=checkpoint_no or response.get("step_key")!=step_key:
            continue
        pin=response.get("high_effect_pin")
        if (response.get("verdict")!="READY_TO_EXECUTE" or not isinstance(pin,dict)
            or set(pin)!={"adapter_id","public_key_b64","action_fingerprint","approval_nonce"}
            or pin.get("action_fingerprint")!=action_fingerprint(action)):
            raise HTTPException(409,{"code":"HIGH_EFFECT_PRE_SIGNER_NOT_PINNED"})
        try:
            raw=base64.b64decode(pin["public_key_b64"],validate=True)
            if len(raw)!=32 or not isinstance(pin["adapter_id"],str):
                raise ValueError("bad pinned key/adapter")
            Ed25519PublicKey.from_public_bytes(raw)
        except (ValueError,TypeError,KeyError) as exc:
            raise HTTPException(409,{"code":"HIGH_EFFECT_PRE_SIGNER_INVALID"}) from exc
        return pin
    raise HTTPException(409,{"code":"HIGH_EFFECT_PRE_SIGNER_MISSING"})


def worker_capability(action: Action) -> tuple[bool,str]:
    """Bounded capabilities of independently provisioned workers/adapters."""
    if action.effect_class in ("E3","E4","E5"):
        cap=high_effect_capability(action)
        if cap is None:
            return False,"UNSUPPORTED_ACTION_CAPABILITY_FAIL_CLOSED"
        if action.payload_sha256 is None or action.payload_bytes is None:
            return False,"EXECUTION_PAYLOAD_NOT_BOUND_TO_PRE"
        return True,"HIGH_EFFECT_ADAPTER_CAPABILITY_ADMITTED"
    if (action.action_type,action.effect_class,action.reversible,
            action.real_world_effect) not in (
            ("read","E0",False,False),("write","E2",True,False)):
        return False,"UNSUPPORTED_ACTION_CAPABILITY_FAIL_CLOSED"
    if not EXECUTOR_OUTPUT_ROOT:
        return False,"EXECUTOR_OUTPUT_ROOT_NOT_PROVISIONED"
    root=Path(EXECUTOR_OUTPUT_ROOT)
    target=Path(action.target)
    if (not root.is_absolute() or not target.is_absolute()
            or root.is_symlink()
            or target.suffix not in (".txt",".json")
            or os.path.normpath(str(target.parent))!=os.path.normpath(str(root))):
        return False,"EXECUTOR_TARGET_OUTSIDE_PROVISIONED_BOUNDS"
    return True,"TRUSTED_WORKER_CAPABILITY_ADMITTED"


def _require_action_admission(action: Action | None, phase: str) -> None:
    if action is None:return
    if ADMISSION_MODE != "enabled":
        raise HTTPException(409, {"code": "TRUSTED_EXECUTOR_UNAVAILABLE_FAIL_CLOSED"})
    # POST for existing signed historical gates does not authorize new effects.
    if phase=="PRE_EXECUTION":
        ok,reason=worker_capability(action)
        if not ok:raise HTTPException(409,{"code":reason})
        if action.effect_class in ("E2","E3","E4","E5") and (
            action.payload_sha256 is None or action.payload_bytes is None):
            raise HTTPException(409,{"code":"EXECUTION_PAYLOAD_NOT_BOUND_TO_PRE"})


@app.post("/v1/tasks/register", dependencies=[Depends(require_key)])
def register(req: RegisterRequest):
    if not ct(req.protocol_hash, protocol_hash()):
        raise HTTPException(428, "protocol bootstrap required")
    steps = [s.model_dump() for s in req.steps]
    try:
        hierarchy(steps)
        if req.task_kind == "REMEDIAL":
            validate_remedial_plan(steps)
    except ValueError as e:
        raise HTTPException(409, str(e))
    contract = {"task_id": req.task_id, "agent": req.agent, "original_instruction": req.original_instruction, "acceptance_criteria": req.acceptance_criteria, "steps": steps, "protocol_hash": req.protocol_hash, "task_kind": req.task_kind, "remedial_for_task_id": req.remedial_for_task_id, "remedial_trigger_step_key": req.remedial_trigger_step_key, "causal_step_key": req.causal_step_key, "remedial_origin_checkpoint_no": req.remedial_origin_checkpoint_no, "remedial_attempt": req.remedial_attempt}
    ch = sha(canon(contract)); rh = sha(canon(req.model_dump(mode="json")))
    c = conn()
    try:
        c.execute("BEGIN IMMEDIATE")
        guard_anchor(c)
        rep = replay(c, req.event_id, rh)
        if rep is not None:
            c.commit(); return rep
        existing = c.execute("SELECT contract_hash FROM task_registry WHERE task_id=?", (req.task_id,)).fetchone()
        if existing:
            if existing[0] != ch:
                raise HTTPException(409, "immutable task contract mismatch")
            raise HTTPException(409, "task already registered; use original event for idempotent replay")
        if req.task_kind == "REMEDIAL":
            original = c.execute("SELECT * FROM task_registry WHERE task_id=?", (req.remedial_for_task_id,)).fetchone()
            if not original:
                raise HTTPException(409, {"code": "REMEDIAL_ORIGINAL_TASK_NOT_FOUND"})
            if original["task_kind"] != "NORMAL":
                raise HTTPException(409, {"code": "NESTED_REMEDIAL_FORBIDDEN"})
            if original["contract_status"] in TERMINAL_STATUSES:
                raise HTTPException(409, {"code": "ORIGINAL_TASK_TERMINAL"})
            _, _, orig_step = current_step(c, req.remedial_for_task_id)
            if orig_step != req.remedial_trigger_step_key:
                raise HTTPException(409, {"code": "REMEDIAL_TRIGGER_NOT_CURRENT_STEP", "expected": orig_step})
            if original["checkpoint_no"] != req.remedial_origin_checkpoint_no:
                raise HTTPException(409, {"code": "REMEDIAL_ORIGIN_CHECKPOINT_STALE", "expected": original["checkpoint_no"]})
            if failed_attempts(c, req.remedial_for_task_id, orig_step, int(original["failure_reset_checkpoint"])) < MAX_LOCAL_REMEDIATION_FAILURES:
                raise HTTPException(409, {"code": "LOCAL_REMEDIATION_NOT_EXHAUSTED"})
            open_r = latest_linked_remedial(c, req.remedial_for_task_id)
            if open_r and open_r["contract_status"] == "OPEN":
                raise HTTPException(409, {"code": "REMEDIAL_ALREADY_OPEN"})
            expected_attempt = c.execute("SELECT COUNT(*) FROM task_registry WHERE task_kind='REMEDIAL' AND remedial_for_task_id=?", (req.remedial_for_task_id,)).fetchone()[0] + 1
            if req.remedial_attempt != expected_attempt:
                raise HTTPException(409, {"code": "REMEDIAL_ATTEMPT_SEQUENCE_INVALID", "expected": expected_attempt})
            if req.causal_step_key:
                causal = c.execute("SELECT verified FROM task_registry_steps WHERE task_id=? AND step_key=?", (req.remedial_for_task_id, req.causal_step_key)).fetchone()
                if not causal or not causal[0]:
                    raise HTTPException(409, {"code": "CAUSAL_STEP_MUST_BE_HISTORICAL_VERIFIED_PASS"})
        now = now_iso()
        c.execute("INSERT INTO task_registry(task_id,contract_hash,agent,original_instruction,acceptance_criteria_json,task_kind,remedial_for_task_id,remedial_trigger_step_key,causal_step_key,remedial_origin_checkpoint_no,remedial_attempt,status,contract_status,checkpoint_no,failure_reset_checkpoint,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,'REGISTERED','OPEN',0,0,?)",
                  (req.task_id, ch, req.agent, req.original_instruction, canon(req.acceptance_criteria), req.task_kind, req.remedial_for_task_id, req.remedial_trigger_step_key, req.causal_step_key, req.remedial_origin_checkpoint_no, req.remedial_attempt, now))
        for i, s in enumerate(req.steps, 1):
            c.execute("INSERT INTO task_registry_steps(task_id,step_no,step_key,title,criteria_json,required) VALUES(?,?,?,?,?,1)", (req.task_id, i, s.step_key, s.title, canon(s.acceptance_criteria)))
        out = {"gateway_version": APP_VERSION, "task_id": req.task_id, "contract_hash": ch, "status": "REGISTERED", "contract_status": "OPEN", "checkpoint_no": 0, "idempotent_replay": False}
        return commit_audited(c, req.task_id, req.event_id, "TASK_INTAKE", ch, rh, req.model_dump(mode="json"), out)
    except BaseException:
        c.rollback(); raise
    finally:
        c.close()


@app.post("/v1/evaluate", dependencies=[Depends(require_key)])
def evaluate(req: EvalRequest, x_evaluation_hitl_key: str | None = Header(default=None)):
    rh = sha(canon(req.model_dump(mode="json")))
    c = conn()
    try:
        c.execute("BEGIN IMMEDIATE")
        guard_anchor(c)
        rep = replay(c, req.event_id, rh)
        if rep is not None:
            c.commit(); return rep
        t = c.execute("SELECT * FROM task_registry WHERE task_id=?", (req.task_id,)).fetchone()
        if not t:
            raise HTTPException(404, "task not registered")
        _require_registered_protocol(c, req.task_id, req.protocol_hash)
        if t["contract_status"] in TERMINAL_STATUSES:
            raise HTTPException(409, "task terminal")
        if t["status"] == "PAUSED":
            raise HTTPException(409, {"code": "TASK_PAUSED_RESUME_REQUIRED"})
        if t["status"] == "RECOVERY_PENDING" and req.phase != "POST_EXECUTION":
            raise HTTPException(409, {"code": "RECOVERY_PENDING_NO_NEW_EXECUTION"})
        if t["contract_hash"] != req.contract_hash or t["agent"] != req.agent:
            raise HTTPException(409, "immutable contract/agent mismatch")
        if t["checkpoint_no"] != req.checkpoint_no:
            raise HTTPException(409, {"code": "STALE_CHECKPOINT", "expected": t["checkpoint_no"]})
        rows, _post, expected = current_step(c, req.task_id)
        if expected is None:
            raise HTTPException(409, "all steps already verified")
        if req.step_key != expected:
            raise HTTPException(409, {"code": "STEP_SEQUENCE_VIOLATION", "expected": expected})
        step = next(r for r in rows if r["step_key"] == expected)
        criteria = json.loads(step["criteria_json"])
        # Execution classification comes from the signed immutable TASK_INTAKE,
        # never from client-supplied evaluate.action. Legacy contracts retain
        # their historical logical semantics until explicitly migrated.
        intake = c.execute("SELECT request_json FROM audit WHERE task_id=? AND event_type='TASK_INTAKE' ORDER BY seq LIMIT 1", (req.task_id,)).fetchone()
        if intake is None:
            raise HTTPException(409, {"code": "IMMUTABLE_STEP_CONTRACT_MISSING"})
        original_steps = json.loads(intake["request_json"])["steps"]
        step_contract = next((item for item in original_steps if item["step_key"] == expected), None)
        if step_contract is None:
            raise HTTPException(409, {"code": "IMMUTABLE_STEP_CONTRACT_MISSING"})
        if step_contract.get("execution_required", False) and req.phase != "FACT_CHECK" and req.action is None:
            raise HTTPException(409, {"code": "IMMUTABLE_STEP_REQUIRES_ACTION"})
        if req.phase == "PRE_EXECUTION" and step_contract.get("preconditions") is not None:
            criteria = step_contract["preconditions"]
        # Invariants remain mandatory in BOTH PRE and POST; they cannot be
        # silently dropped as the workflow crosses the execution boundary.
        criteria = [*criteria, *step_contract.get("invariants", [])]
        validate_claim_coverage(criteria, req.claims, "ACCEPTANCE_COVERAGE_INCOMPLETE")

        if req.phase == "FACT_CHECK":
            if req.action is not None or req.finalize_task or req.task_claims or any(x is not None for x in (req.remedial_disposition, req.remedial_outcome, req.recovery_strategy)):
                raise HTTPException(409, {"code": "FACT_CHECK_READ_ONLY"})
            step_pass, notes, _rows = verify_claim_set(req.task_id, expected, criteria, req.claims, "step", EvalContext("FACT_CHECK", req.checkpoint_no, None))
            verdict = Verdict.VERIFIED_PASS if step_pass else Verdict.UNVERIFIED
            out = {"gateway_version": APP_VERSION, "task_id": req.task_id, "step_key": expected, "verdict": verdict.value, "reason": "current-step facts verified without state advancement" if step_pass else "one or more current-step facts remain unverified", "step_verified": False, "contract_status": t["contract_status"], "checkpoint_no": int(t["checkpoint_no"]), "evidence_notes": notes, "hitl_approved": False, "action_fingerprint": None, "action_intent_fingerprint": None, "gate_checkpoint_no": None, "evidence_digest": None, "materialized_evidence": [], "completed_at": t["completed_at"], "remedial_outcome": t["remedial_outcome"], "recovery_strategy": t["recovery_strategy"], "idempotent_replay": False}
            return commit_audited(c, req.task_id, req.event_id, "FACT_CHECK", req.contract_hash, rh, req.model_dump(mode="json"), out)

        if req.phase != "POST_EXECUTION" and req.execution_receipt is not None:
            raise HTTPException(409, {"code": "EXECUTION_RECEIPT_POST_ONLY"})
        if req.task_claims and not req.finalize_task:
            raise HTTPException(409, {"code": "TASK_CLAIMS_ONLY_ON_FINALIZATION"})
        if t["task_kind"] == "NORMAL":
            linked = latest_linked_remedial(c, req.task_id)
            if linked and linked["contract_status"] == "OPEN":
                raise HTTPException(409, {"code": "ORIGINAL_TASK_BLOCKED_BY_REMEDIAL"})
            if linked and linked["contract_status"] == "UNRESOLVED":
                raise HTTPException(409, {"code": "TASK_TERMINATED_UNRESOLVED"})
            if failed_attempts(c, req.task_id, expected, int(t["failure_reset_checkpoint"])) >= MAX_LOCAL_REMEDIATION_FAILURES:
                raise HTTPException(409, {"code": "REMEDIAL_ESCALATION_REQUIRED", "trigger_step_key": expected})
            if any(x is not None for x in (req.remedial_disposition, req.remedial_outcome, req.recovery_strategy)):
                raise HTTPException(409, {"code": "REMEDIAL_FIELDS_FORBIDDEN_ON_NORMAL_TASK"})
        else:
            fails = failed_attempts(c, req.task_id, expected, 0)
            if fails >= MAX_REMEDIAL_STEP_FAILURES and req.remedial_disposition != "EXHAUSTED":
                raise HTTPException(409, {"code": "REMEDIAL_STEP_EXHAUSTED", "step_key": expected})
            if req.remedial_outcome is not None and not req.finalize_task:
                raise HTTPException(409, {"code": "REMEDIAL_OUTCOME_ONLY_ON_FINALIZATION"})

        unverified_before = c.execute("SELECT COUNT(*) FROM task_registry_steps WHERE task_id=? AND verified=0", (req.task_id,)).fetchone()[0]
        if req.finalize_task and unverified_before != 1:
            raise HTTPException(409, {"code": "FINALIZATION_REQUIRES_LAST_STEP", "remaining": unverified_before})
        if req.phase == "POST_EXECUTION" and unverified_before == 1 and not req.finalize_task:
            raise HTTPException(409, {"code": "FINAL_STEP_REQUIRES_FINALIZATION"})

        _require_action_admission(req.action,req.phase)
        # A fresh E3-E5 PRE must never reclassify an immutable logical step
        # as physical. Historical signed logical gates may still complete POST.
        if (req.phase=="PRE_EXECUTION" and req.action is not None
            and req.action.effect_class in ("E3","E4","E5")
            and not step_contract.get("execution_required",False)):
            raise HTTPException(409,{"code":"IMMUTABLE_LOGICAL_STEP_FORBIDS_HIGH_EFFECT"})
        fp = action_fingerprint(req.action); intent_fp = action_intent_fingerprint(req.action)
        gate = None
        if req.phase == "PRE_EXECUTION":
            # An actionable READY gate may already have produced a durable
            # effect. No newer PRE may replace it until signed reconciliation
            # or verified POST consumes the original gate.
            pending = latest_gate(c, req.task_id, expected)
            if (pending and pending["pre_verdict"] == "READY_TO_EXECUTE"
                    and not pending["consumed"]
                    and pending["action_fingerprint"] != action_fingerprint(None)):
                raise HTTPException(409, {
                    "code": "UNRESOLVED_ACTION_GATE_NO_NEW_PRE",
                    "pre_checkpoint_no": int(pending["pre_checkpoint_no"]),
                })
            ctx = EvalContext("PRE_EXECUTION", req.checkpoint_no, None)
        else:
            # A failed POST leaves the PRE gate unconsumed: verification is retried against the SAME gate,
            # never by authorizing (and thus potentially re-executing) the action again.
            gate = latest_gate(c, req.task_id, expected)
            if not gate:
                raise HTTPException(409, {"code": "PRE_EXECUTION_REQUIRED", "step_key": expected, "checkpoint_no": req.checkpoint_no})
            if gate["pre_verdict"] != "READY_TO_EXECUTE":
                raise HTTPException(409, {"code": "PRE_EXECUTION_NOT_READY", "verdict": gate["pre_verdict"]})
            if gate["consumed"]:
                raise HTTPException(409, {"code": "PRE_EXECUTION_ALREADY_CONSUMED"})
            if not ct(gate["action_fingerprint"], fp):
                raise HTTPException(409, {"code": "ACTION_FINGERPRINT_MISMATCH"})
            # One unified trusted admission path for EVERY concrete action.
            # A notarized claim alone never proves an action actually occurred.
            if req.action is not None:
                pin=(pinned_high_effect_gate(c,req.task_id,expected,int(gate["pre_checkpoint_no"]),req.action)
                     if req.action.effect_class in ("E3","E4","E5") else None)
                signer=(pin["public_key_b64"] if pin else EXECUTOR_PUBLIC_KEY_B64)
                valid, receipt_reason = verify_execution_receipt(
                    req.execution_receipt, public_b64=signer,
                    task_id=req.task_id, step_key=expected,
                    gate_checkpoint_no=int(gate["pre_checkpoint_no"]),
                    action_fingerprint=fp, target=req.action.target,
                    gate_created_at=gate["created_at"])
                if not valid:
                    raise HTTPException(409, {"code": receipt_reason})
                if pin and req.execution_receipt["executor_id"]!="trusted-worker-"+pin["adapter_id"]:
                    raise HTTPException(409,{"code":"HIGH_EFFECT_EXECUTOR_ID_MISMATCH"})
            elif req.execution_receipt is not None:
                raise HTTPException(409, {"code": "EXECUTION_RECEIPT_FOR_LOGICAL_STEP_WITHOUT_ACTION"})
            ctx = EvalContext("POST_EXECUTION", int(gate["pre_checkpoint_no"]), iso_epoch(gate["created_at"]))

        step_pass, notes, evidence_rows = verify_claim_set(req.task_id, expected, criteria, req.claims, "step", ctx)
        task_criteria = json.loads(t["acceptance_criteria_json"]); task_pass = True; task_rows: list[tuple[int, Evidence, EvidenceResult]] = []
        if req.finalize_task:
            validate_claim_coverage(task_criteria, req.task_claims, "TASK_ACCEPTANCE_COVERAGE_INCOMPLETE")
            task_pass, task_notes, task_rows = verify_claim_set(req.task_id, "__TASK__", task_criteria, req.task_claims, "task", ctx)
            notes.extend(task_notes)
            if t["task_kind"] == "REMEDIAL":
                if req.remedial_outcome is None or req.recovery_strategy is None:
                    raise HTTPException(409, {"code": "REMEDIAL_FINAL_OUTCOME_REQUIRED"})
                if req.remedial_outcome == "RECOVERED" and req.recovery_strategy == "EXHAUSTED":
                    raise HTTPException(409, {"code": "INVALID_RECOVERY_STRATEGY"})
                if req.remedial_outcome == "UNRESOLVED" and req.recovery_strategy != "EXHAUSTED":
                    raise HTTPException(409, {"code": "INVALID_UNRESOLVED_STRATEGY"})

        verdict = Verdict.VERIFIED_PASS if step_pass else Verdict.UNVERIFIED
        reason = "all acceptance criteria independently verified with signed phase/checkpoint-bound criterion bindings" if step_pass else "one or more acceptance criteria lack fresh criterion-bound notarized evidence"
        action_rows: list[tuple[str, Evidence, EvidenceResult]] = []; hitl_approved = False; high_effect_pin = None
        if req.phase == "PRE_EXECUTION":
            if step_pass:
                action_v, action_reason, action_rows = action_check(req.task_id, expected, req.action, req.checkpoint_no)
                if action_v == Verdict.REQUIRES_HITL and req.action is not None and req.action.effect_class in ("E3","E4","E5"):
                    cap=high_effect_capability(req.action)
                    try:
                        if cap is None or not HITL_PUBLIC_KEY_B64:
                            raise AdmissionDenied("HIGH_EFFECT_ADAPTER_OR_HITL_AUTHORITY_UNAVAILABLE")
                        signed=req.hitl_approval
                        legacy=None if not isinstance(signed,dict) else {
                            "task_id":req.task_id,"step_key":expected,"gate_checkpoint_no":int(t["checkpoint_no"])+1,
                            "action_fingerprint":action_fingerprint(req.action),"adapter_id":cap.adapter_id,
                            "status":"APPROVED","consumed":False,"expires_at":signed.get("expires_at")}
                        admit_high_effect(action=req.action.model_dump(mode="json",exclude_none=True),capability=cap,
                            approval=legacy,signed_approval=signed,hitl_public_key_b64=HITL_PUBLIC_KEY_B64,
                            task_id=req.task_id,step_key=expected,gate_checkpoint_no=int(t["checkpoint_no"])+1)
                    except AdmissionDenied as exc:
                        verdict=Verdict.REQUIRES_HITL;reason=str(exc)
                    else:
                        verdict=Verdict.READY_TO_EXECUTE;reason="signed scoped HITL plus trusted high-effect capability admitted";hitl_approved=True
                        high_effect_pin={"adapter_id":cap.adapter_id,"public_key_b64":cap.public_key_b64,
                                         "action_fingerprint":action_fingerprint(req.action),
                                         "approval_nonce":signed["nonce"]}
                elif action_v == Verdict.REQUIRES_HITL and require_hitl_key(x_evaluation_hitl_key):
                    verdict = Verdict.READY_TO_EXECUTE; reason = "separate HITL authorization verified"; hitl_approved = True
                else:
                    verdict = action_v; reason = action_reason
            verified = False
        else:
            if req.finalize_task and not task_pass:
                verdict = Verdict.UNVERIFIED; reason = "task-global acceptance criteria are not fully verified with signed bindings"
            else:
                verdict = Verdict.VERIFIED_PASS if step_pass else Verdict.UNVERIFIED
                reason = "all acceptance criteria independently verified after bound PRE_EXECUTION" if step_pass else reason
            verified = verdict == Verdict.VERIFIED_PASS

        newcp = int(t["checkpoint_no"]) + 1; now = now_iso(); materialized: list[dict[str, Any]] = []
        for idx, ev, res in evidence_rows:
            materialized.append(materialize_evidence(c, req.task_id, expected, idx, f"criterion:{idx}", ev, res, now))
        for purpose, ev, res in action_rows:
            materialized.append(materialize_evidence(c, req.task_id, expected, -1, f"action:{purpose}", ev, res, now))
        for idx, ev, res in task_rows:
            materialized.append(materialize_evidence(c, req.task_id, "__TASK__", idx, f"task_criterion:{idx}", ev, res, now))
        digest = sha(canon(sorted(m["evidence_fingerprint"] for m in materialized)))
        gate_cp = newcp if req.phase == "PRE_EXECUTION" else int(gate["pre_checkpoint_no"])

        if verified:
            c.execute("UPDATE task_registry_steps SET verified=1,status='VERIFIED',last_verdict=? WHERE task_id=? AND step_key=?", (verdict.value, req.task_id, expected))
        else:
            c.execute("UPDATE task_registry_steps SET last_verdict=? WHERE task_id=? AND step_key=?", (verdict.value, req.task_id, expected))
        remaining = c.execute("SELECT COUNT(*) FROM task_registry_steps WHERE task_id=? AND verified=0", (req.task_id,)).fetchone()[0]
        contract_status = "OPEN"; completed_at = None; remedial_outcome = t["remedial_outcome"]; recovery_strategy = t["recovery_strategy"]
        if req.finalize_task and verified:
            if remaining != 0:
                raise HTTPException(409, {"code": "FINALIZATION_REQUIRES_ALL_STEPS_VERIFIED", "remaining": remaining})
            completed_at = now
            if t["task_kind"] == "REMEDIAL":
                remedial_outcome = req.remedial_outcome; recovery_strategy = req.recovery_strategy
                contract_status = "SATISFIED" if req.remedial_outcome == "RECOVERED" else "UNRESOLVED"
                c.execute("UPDATE task_registry SET remedial_outcome=?,recovery_strategy=? WHERE task_id=?", (remedial_outcome, recovery_strategy, req.task_id))
                if req.remedial_outcome == "RECOVERED":
                    c.execute("UPDATE task_registry SET failure_reset_checkpoint=?,status='IN_PROGRESS' WHERE task_id=?", (int(t["remedial_origin_checkpoint_no"]), t["remedial_for_task_id"]))
                else:
                    c.execute("UPDATE task_registry SET contract_status='UNRESOLVED',status='TASK_TERMINATED_UNRESOLVED',completed_at=? WHERE task_id=?", (now, t["remedial_for_task_id"]))
            else:
                contract_status = "SATISFIED"

        status = "COMPLETED" if contract_status == "SATISFIED" else ("TASK_TERMINATED_UNRESOLVED" if contract_status == "UNRESOLVED" else ("RECOVERY_PENDING" if t["status"] == "RECOVERY_PENDING" and req.phase == "POST_EXECUTION" and not verified else "IN_PROGRESS"))
        out = {"gateway_version": APP_VERSION, "task_id": req.task_id, "step_key": expected, "verdict": verdict.value, "reason": reason, "step_verified": verified, "contract_status": contract_status, "checkpoint_no": newcp, "evidence_notes": notes, "hitl_approved": hitl_approved, "action_fingerprint": fp, "action_intent_fingerprint": intent_fp, "gate_checkpoint_no": gate_cp, "high_effect_pin": high_effect_pin, "evidence_digest": digest, "materialized_evidence": materialized, "completed_at": completed_at, "remedial_outcome": remedial_outcome, "recovery_strategy": recovery_strategy, "idempotent_replay": False}
        c.execute("UPDATE task_registry SET checkpoint_no=?,status=?,contract_status=?,completed_at=? WHERE task_id=?", (newcp, status, contract_status, completed_at, req.task_id))
        c.execute("INSERT INTO task_registry_checkpoints(task_id,checkpoint_no,step_key,event_id,verdict,verified,evidence_digest,created_at) VALUES(?,?,?,?,?,?,?,?)", (req.task_id, newcp, expected, req.event_id, verdict.value, int(verified), digest, now))
        if req.phase == "PRE_EXECUTION":
            c.execute("INSERT INTO execution_gates(task_id,step_key,pre_checkpoint_no,action_fingerprint,pre_verdict,hitl_approved,created_at) VALUES(?,?,?,?,?,?,?)", (req.task_id, expected, newcp, fp, verdict.value, int(hitl_approved), now))
        elif verified:
            c.execute("UPDATE execution_gates SET consumed=1,post_checkpoint_no=? WHERE task_id=? AND step_key=? AND pre_checkpoint_no=?", (newcp, req.task_id, expected, gate_cp))
        return commit_audited(c, req.task_id, req.event_id, "EVALUATION", req.contract_hash, rh, req.model_dump(mode="json"), out)
    except BaseException:
        c.rollback(); raise
    finally:
        c.close()


@app.post("/v1/tasks/{task_id}/pause", dependencies=[Depends(require_key)])
def pause_task(task_id: str, req: SuspensionRequest):
    if not ID_RE.fullmatch(task_id):
        raise HTTPException(422, "invalid identifier")
    body={"task_id":task_id,**req.model_dump(mode="json")}
    rh=sha(canon(body))
    c=conn()
    try:
        c.execute("BEGIN IMMEDIATE");guard_anchor(c)
        repeated=replay(c,req.event_id,rh)
        if repeated is not None:
            c.commit();return repeated
        t=c.execute("SELECT * FROM task_registry WHERE task_id=?",(task_id,)).fetchone()
        if not t:
            raise HTTPException(404,"task not registered")
        _require_registered_protocol(c, task_id, req.protocol_hash)
        if t["contract_status"]!="OPEN" or t["status"]=="PAUSED":
            raise HTTPException(409,{"code":"TASK_NOT_PAUSABLE"})
        if t["contract_hash"]!=req.contract_hash or t["checkpoint_no"]!=req.checkpoint_no:
            raise HTTPException(409,{"code":"PAUSE_STALE_CONTRACT_OR_CHECKPOINT"})
        c.execute("UPDATE task_registry SET status='PAUSED' WHERE task_id=?",(task_id,))
        response={"task_id":task_id,"status":"PAUSED","checkpoint_no":req.checkpoint_no,
                  "contract_status":"OPEN","indefinite":True,"idempotent_replay":False}
        return commit_audited(c,task_id,req.event_id,"TASK_PAUSE",req.contract_hash,rh,body,response)
    except BaseException:
        c.rollback();raise
    finally:c.close()


@app.post("/v1/tasks/{task_id}/resume", dependencies=[Depends(require_key)])
def resume_task(task_id: str, req: SuspensionRequest):
    if not ID_RE.fullmatch(task_id):
        raise HTTPException(422,"invalid identifier")
    # Resume uses the immutable signed TASK_INTAKE hash (checked below), not
    # the current bootstrap hash. No historical validator is reactivated.
    body={"task_id":task_id,**req.model_dump(mode="json")}
    rh=sha(canon(body))
    c=conn()
    try:
        c.execute("BEGIN IMMEDIATE");guard_anchor(c)
        repeated=replay(c,req.event_id,rh)
        if repeated is not None:
            c.commit();return repeated
        t=c.execute("SELECT * FROM task_registry WHERE task_id=?",(task_id,)).fetchone()
        if not t:raise HTTPException(404,"task not registered")
        _require_registered_protocol(c, task_id, req.protocol_hash)
        if t["contract_status"]!="OPEN" or t["status"]!="PAUSED":
            raise HTTPException(409,{"code":"TASK_NOT_PAUSED"})
        if t["contract_hash"]!=req.contract_hash or t["checkpoint_no"]!=req.checkpoint_no:
            raise HTTPException(409,{"code":"RESUME_STALE_CONTRACT_OR_CHECKPOINT"})
        _,_,key=current_step(c,task_id)
        gate=latest_gate(c,task_id,key) if key else None
        unresolved=bool(gate and gate["pre_verdict"]=="READY_TO_EXECUTE" and not gate["consumed"])
        status="RECOVERY_PENDING" if unresolved else "IN_PROGRESS"
        c.execute("UPDATE task_registry SET status=? WHERE task_id=?",(status,task_id))
        response={"task_id":task_id,"status":status,"checkpoint_no":req.checkpoint_no,
                  "contract_status":"OPEN",
                  "next_action":"RECONCILE_EXISTING_EXECUTION" if unresolved else "EVALUATE_NEXT_STEP",
                  "idempotent_replay":False}
        return commit_audited(c,task_id,req.event_id,"TASK_RESUME",req.contract_hash,rh,body,response)
    except BaseException:
        c.rollback();raise
    finally:c.close()


@app.post("/v1/tasks/{task_id}/reconcile", dependencies=[Depends(require_key)])
def reconcile_task(task_id: str, req: ReconcileRequest):
    """No-effect closeout is NOT a POST success and never increments checkpoint."""
    if not ID_RE.fullmatch(task_id):raise HTTPException(422,"invalid task id")
    request={"task_id":task_id,**req.model_dump(mode="json")}
    rh=sha(canon(request))
    c=conn()
    try:
        c.execute("BEGIN IMMEDIATE");guard_anchor(c)
        replayed=replay(c,req.event_id,rh)
        if replayed is not None:
            c.commit();return replayed
        t=c.execute("SELECT * FROM task_registry WHERE task_id=?",(task_id,)).fetchone()
        if not t:raise HTTPException(404,"task not registered")
        _require_registered_protocol(c,task_id,req.protocol_hash)
        if (t["contract_hash"]!=req.contract_hash or t["checkpoint_no"]!=req.checkpoint_no
            or t["contract_status"]!="OPEN" or t["status"]!="RECOVERY_PENDING"):
            raise HTTPException(409,{"code":"NOT_IN_ACTIVE_PENDING_RECOVERY"})
        _rows,_post,current=current_step(c,task_id)
        if current!=req.step_key:
            raise HTTPException(409,{"code":"RECONCILIATION_STEP_MISMATCH"})
        gate=latest_gate(c,task_id,req.step_key)
        if not gate or gate["consumed"] or gate["pre_verdict"]!="READY_TO_EXECUTE":
            raise HTTPException(409,{"code":"NO_UNCONSUMED_EXECUTION_GATE"})
        if not ct(gate["action_fingerprint"],action_fingerprint(req.action)):
            raise HTTPException(409,{"code":"RECONCILIATION_ACTION_MISMATCH"})
        if req.action.effect_class in ("E3","E4","E5"):
            pin=pinned_high_effect_gate(c,task_id,req.step_key,int(gate["pre_checkpoint_no"]),req.action)
            expected_key=pin["public_key_b64"]
            expected_executor="trusted-worker-"+pin["adapter_id"]
        elif req.action.action_type=="write" and req.action.effect_class=="E2":
            expected_key=EXECUTOR_PUBLIC_KEY_B64
            expected_executor=None
        else:
            raise HTTPException(409,{"code":"RECONCILIATION_ACTION_MISMATCH"})
        if not ct(req.executor_public_key_b64,expected_key):
            raise HTTPException(409,{"code":"RECONCILIATION_EXECUTOR_TRUST_MISMATCH"})
        if not verify_no_effect(req.proof,public_b64=expected_key,
                task_id=task_id,step_key=req.step_key,
                gate_checkpoint_no=int(gate["pre_checkpoint_no"]),
                action_fingerprint=gate["action_fingerprint"],
                target=req.action.target,gate_created_at=gate["created_at"]):
            raise HTTPException(409,{"code":"NO_EFFECT_WORKER_PROOF_INVALID"})
        if expected_executor is not None and req.proof["executor_id"]!=expected_executor:
            raise HTTPException(409,{"code":"NO_EFFECT_EXECUTOR_ADAPTER_MISMATCH"})
        c.execute("UPDATE execution_gates SET consumed=1 WHERE gate_id=?",(gate["gate_id"],))
        c.execute("UPDATE task_registry SET status='IN_PROGRESS' WHERE task_id=?",(task_id,))
        out={"gateway_version":APP_VERSION,"task_id":task_id,"step_key":req.step_key,
             "status":"IN_PROGRESS","reconciled_effect":"NOT_EXECUTED",
             "gate_checkpoint_no":int(gate["pre_checkpoint_no"]),
             "action_fingerprint":gate["action_fingerprint"],
             "checkpoint_no":int(t["checkpoint_no"]),
             "next_action":"FRESH_PRE_REQUIRED","idempotent_replay":False}
        return commit_audited(c,task_id,req.event_id,"TASK_RECONCILE",req.contract_hash,
                              rh,request,out)
    except BaseException:
        c.rollback();raise
    finally:c.close()


@app.post("/v1/tasks/{task_id}/abort", dependencies=[Depends(require_key)])
def abort_task(task_id: str, req: AbortRequest, x_evaluation_hitl_key: str | None = Header(default=None)):
    """Audited, HITL-authorized termination of a task that cannot proceed (e.g. unprovable remedial)."""
    if not ID_RE.fullmatch(task_id):
        raise HTTPException(422, "invalid identifier")
    if not require_hitl_key(x_evaluation_hitl_key):
        raise HTTPException(403, "abort requires separate HITL authorization")
    request = {"task_id": task_id, **req.model_dump(mode="json")}
    rh = sha(canon(request))
    c = conn()
    try:
        c.execute("BEGIN IMMEDIATE")
        guard_anchor(c)
        rep = replay(c, req.event_id, rh)
        if rep is not None:
            c.commit(); return rep
        t = c.execute("SELECT * FROM task_registry WHERE task_id=?", (task_id,)).fetchone()
        if not t:
            raise HTTPException(404, "task not registered")
        _require_registered_protocol(c, task_id, req.protocol_hash)
        if t["contract_status"] in TERMINAL_STATUSES:
            raise HTTPException(409, "task terminal")
        if t["contract_hash"] != req.contract_hash:
            raise HTTPException(409, "immutable contract/agent mismatch")
        if t["checkpoint_no"] != req.checkpoint_no:
            raise HTTPException(409, {"code": "STALE_CHECKPOINT", "expected": t["checkpoint_no"]})
        if t["task_kind"] == "NORMAL":
            linked = latest_linked_remedial(c, task_id)
            if linked and linked["contract_status"] == "OPEN":
                raise HTTPException(409, {"code": "ABORT_REMEDIAL_FIRST", "remedial_task_id": linked["task_id"]})
        now = now_iso()
        c.execute("UPDATE task_registry SET status='TASK_ABORTED',contract_status='ABORTED',completed_at=? WHERE task_id=?", (now, task_id))
        out = {"gateway_version": APP_VERSION, "task_id": task_id, "status": "TASK_ABORTED", "contract_status": "ABORTED", "checkpoint_no": int(t["checkpoint_no"]), "completed_at": now, "idempotent_replay": False}
        return commit_audited(c, task_id, req.event_id, "TASK_ABORT", req.contract_hash, rh, request, out)
    except BaseException:
        c.rollback(); raise
    finally:
        c.close()


@app.get("/v1/tasks/{task_id}/state", dependencies=[Depends(require_key)])
def task_state(task_id: str):
    c = conn()
    try:
        c.execute("BEGIN")
        guard_integrity_read(c)
        t = c.execute("SELECT * FROM task_registry WHERE task_id=?", (task_id,)).fetchone()
        if not t:
            raise HTTPException(404, "not found")
        _, _, next_step = current_step(c, task_id)
        latest = c.execute("SELECT checkpoint_no,step_key,event_id,verdict,verified,created_at FROM task_registry_checkpoints WHERE task_id=? ORDER BY checkpoint_no DESC LIMIT 1", (task_id,)).fetchone()
        guidance = task_guidance(c, t, next_step)
        gate = latest_gate(c, task_id, next_step) if next_step else None
        pending_gate = None
        if gate and gate["pre_verdict"] == "READY_TO_EXECUTE" and not gate["consumed"]:
            pending_gate = {"task_id":task_id,"step_key":gate["step_key"],"checkpoint_no":int(gate["pre_checkpoint_no"]),"pre_checkpoint_no": int(gate["pre_checkpoint_no"]), "verdict":gate["pre_verdict"],"action_fingerprint": gate["action_fingerprint"], "hitl_approved": bool(gate["hitl_approved"]),"created_at":gate["created_at"]}
        return {
            "task_id": task_id,
            "state_version": int(t["checkpoint_no"]),
            "status": t["status"],
            "contract_status": t["contract_status"],
            "current_step": next_step,
            "next_required_step": next_step,
            "latest_checkpoint": dict(latest) if latest else None,
            "pending_execution_gate": pending_gate,
            "last_progress_at": latest["created_at"] if latest else t["created_at"],
            "terminal": guidance["terminal"],
            "next_action": guidance["next_action"],
            "blocked_reason": guidance["blocked_reason"],
            "remedial_task_id": guidance["remedial_task_id"],
        }
    finally:
        c.close()


@app.get("/v1/tasks/{task_id}", dependencies=[Depends(require_key)])
def detail(task_id: str):
    c = conn()
    try:
        c.execute("BEGIN")
        guard_integrity_read(c)
        t = c.execute("SELECT * FROM task_registry WHERE task_id=?", (task_id,)).fetchone()
        if not t:
            raise HTTPException(404, "not found")
        steps = [dict(r) for r in c.execute("SELECT * FROM task_registry_steps WHERE task_id=? ORDER BY step_no", (task_id,))]
        cps = [dict(r) for r in c.execute("SELECT * FROM task_registry_checkpoints WHERE task_id=? ORDER BY checkpoint_no", (task_id,))]
        return {"task": dict(t), "steps": steps, "checkpoints": cps}
    finally:
        c.close()


@app.get("/v1/audit/verify", dependencies=[Depends(require_key)])
def audit_verify():
    """Authenticated, always-fresh full verification (chain + HMAC + anchor + materialized state)."""
    if not integrity_ok(force=True):
        raise HTTPException(409, "integrity verification failed")
    c = conn()
    try:
        n, head = db_head(c)
    finally:
        c.close()
    return {"status": "PASS", "version": APP_VERSION, "protocol_version": PROTOCOL_VERSION, "protocol_hash": protocol_hash(), "evidence_policy": "NOTARIZED_ONLY", "hitl_policy": "SEPARATE_KEY_REQUIRED",
            "admission_mode": ADMISSION_MODE, "records": n, "head": head, "chain": "AUTHENTICATED_VALID", "anchor": "VALID", "materialized_state": "VALID"}
