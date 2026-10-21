"""Shared test harness for the Evaluation Gateway test-suite (isolated runtime under tests/_runtime)."""
import base64, hashlib, os, secrets, shutil, sys, time
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "tests" / "_runtime"
shutil.rmtree(RUNTIME, ignore_errors=True)
(RUNTIME / "evidence").mkdir(parents=True)
(RUNTIME / "evidence").chmod(0o755)
WORKER_OUTPUT=RUNTIME/"worker-outputs"
WORKER_OUTPUT.mkdir(mode=0o700)
PRIV = Ed25519PrivateKey.generate()
EXEC_PRIV = Ed25519PrivateKey.generate()
PRIV_PEM = PRIV.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
PUB = base64.b64encode(PRIV.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
API_KEY = secrets.token_urlsafe(48)
HITL_KEY = secrets.token_urlsafe(48)
AUDIT_KEY = secrets.token_urlsafe(48)
ANCHOR = RUNTIME / "anchor" / "audit.anchor"
os.environ.update({
    "EVALUATION_GATEWAY_API_KEY": API_KEY,
    "EVALUATION_GATEWAY_HITL_KEY": HITL_KEY,
    "EVALUATION_GATEWAY_AUDIT_HMAC_KEY": AUDIT_KEY,
    "EVALUATION_GATEWAY_EVIDENCE_PUBLIC_KEY_B64": PUB,
    "EVALUATION_GATEWAY_EXECUTOR_PUBLIC_KEY_B64": base64.b64encode(EXEC_PRIV.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode(),
    "EVALUATION_GATEWAY_EVIDENCE_ROOT": str(RUNTIME / "evidence"),
    "EVALUATION_GATEWAY_DB_PATH": str(RUNTIME / "data" / "gateway.db"),
    "EVALUATION_GATEWAY_ANCHOR_PATH": str(ANCHOR),
    "EVALUATION_GATEWAY_TRUSTED_EVIDENCE_UID": str(os.getuid()),
    "EVALUATION_GATEWAY_INTEGRITY_CACHE_SECONDS": "0",
    "EVALUATION_GATEWAY_EXECUTOR_OUTPUT_ROOT": str(WORKER_OUTPUT),
})
sys.path.insert(0, str(ROOT))
from fastapi.testclient import TestClient  # noqa: E402
import app.main as gw  # noqa: E402

gw.require_config()
gw.init_db()
CLIENT = TestClient(gw.app)
SOFT = TestClient(gw.app, raise_server_exceptions=False)
HEAD = {"X-Evaluation-Key": API_KEY}
HITL = {**HEAD, "X-Evaluation-HITL-Key": HITL_KEY}
CRIT = "child criterion"


def eid(prefix):
    return f"{prefix}-{time.time_ns()}"


# ---- signed bindings -------------------------------------------------------------------------
def matcher(value="CHECK=PASS", kind="contains"):
    return {"kind": kind, "value": value}


def sb(task, step, idx, criterion, phase, cp, value="CHECK=PASS", kind="contains"):
    return {**gw.step_identity(task, step, idx, criterion, phase, cp), "matcher": matcher(value, kind)}


def tb(task, idx, criterion, cp, value="TASK=PASS", kind="contains"):
    return {**gw.task_identity(task, idx, criterion, "POST_EXECUTION", cp), "matcher": matcher(value, kind)}


def pb(task, step, purpose, action, cp, value, kind="contains"):
    return {**gw.proof_identity(task, step, purpose, gw.Action(**action), cp), "matcher": matcher(value, kind)}


def notarized(source_id, stdout="CHECK=PASS", bindings=None, age=0, status="PASS", exit_code=0, bad_sig=False, manifest_version=4, finished_at=None):
    d = RUNTIME / "evidence" / source_id
    d.mkdir(mode=0o700, exist_ok=False)
    state = {"task_id": source_id, "status": status, "exit_code": exit_code, "finished_at": time.time() - age if finished_at is None else finished_at}
    sr = gw.canon(state).encode(); out = stdout.encode()
    (d / "state.json").write_bytes(sr); (d / "stdout.log").write_bytes(out)
    payload = {"manifest_version": manifest_version, "task_id": source_id, "state_sha256": hashlib.sha256(sr).hexdigest(), "stdout_sha256": hashlib.sha256(out).hexdigest(), "finished_at": state["finished_at"], "bindings": bindings or []}
    sig = PRIV.sign(gw.canon(payload).encode())
    if bad_sig:
        sig = b"0" * 64
    (d / "evidence.json").write_text(gw.canon({**payload, "notary_ed25519_signature_b64": base64.b64encode(sig).decode()}))
    for p in d.iterdir():
        p.chmod(0o600)
    d.chmod(0o700)
    return source_id


# ---- request builders --------------------------------------------------------------------------
def evp(ref):
    return {"source_type": "trusted_task", "reference": ref}


def manual():
    return {"source_type": "manual"}


def claim(ref, idx=0, text=CRIT):
    return {"criterion_index": idx, "claim": text, "evidence": [evp(ref)]}


def register(task=None, criteria_child=None, global_criteria=None, physical=False):
    task = task or eid("task"); criteria_child = criteria_child or [CRIT]; global_criteria = global_criteria or ["all steps evidenced"]
    body = {"event_id": eid("reg"), "task_id": task, "protocol_hash": gw.protocol_hash(), "agent": "ChatGPT", "original_instruction": "perform exact work", "acceptance_criteria": global_criteria, "steps": [
        {"step_key": "01", "title": "Parent", "acceptance_criteria": ["parent criterion"], "required": True,"execution_required":False},
        {"step_key": "01.01", "title": "Child", "acceptance_criteria": criteria_child, "required": True,
         "execution_required":physical,**({"preconditions":criteria_child} if physical else {})}]}
    r = CLIENT.post("/v1/tasks/register", headers=HEAD, json=body)
    assert r.status_code == 200, r.text
    return task, r.json()["contract_hash"]


def raw_eval(task, ch, cp, step="01.01", claims=None, phase="PRE_EXECUTION", action=None, finalize=False, event=None, headers=None, task_claims=None, client=None, **extra):
    body = {"event_id": event or eid("eval"), "task_id": task, "contract_hash": ch, "protocol_hash": gw.protocol_hash(), "checkpoint_no": cp, "step_key": step, "agent": "ChatGPT", "phase": phase, "finalize_task": finalize, "claims": claims or [], "task_claims": task_claims or [], "action": action}
    body.update(extra)
    return (client or CLIENT).post("/v1/evaluate", headers=headers or HEAD, json=body)


def step_ref(task, phase, cp, step="01.01", criteria=None, stdout="CHECK=PASS", value="CHECK=PASS", extra_bindings=None, **kw):
    criteria = criteria or [(0, CRIT)]
    bindings = [sb(task, step, i, t, phase, cp, value) for i, t in criteria] + (extra_bindings or [])
    return notarized(eid("knid-task"), stdout=stdout, bindings=bindings, **kw)


def task_ref(task, gate_cp, idx=0, criterion="all steps evidenced", value="TASK=PASS", **kw):
    return notarized(eid("knid-task"), stdout=value, bindings=[tb(task, idx, criterion, gate_cp, value)], **kw)


def task_claim(ref, idx=0, criterion="all steps evidenced"):
    return {"criterion_index": idx, "claim": criterion, "evidence": [evp(ref)]}


def do_pre(task, ch, cp, step="01.01", criteria=None, action=None, headers=None, stdout="CHECK=PASS", value="CHECK=PASS", ref=None, **kw):
    criteria = criteria or [(0, CRIT)]
    ref = ref or step_ref(task, "PRE_EXECUTION", cp, step=step, criteria=criteria, stdout=stdout, value=value, **kw)
    r = raw_eval(task, ch, cp, step=step, claims=[claim(ref, i, t) for i, t in criteria], phase="PRE_EXECUTION", action=action, headers=headers)
    assert r.status_code == 200, r.text
    return r, ref


def do_post(task, ch, pre, step="01.01", criteria=None, action=None, finalize=False, task_claims=None, stdout="CHECK=PASS", value="CHECK=PASS", req_cp=None, gate_cp=None, ref=None, **extra):
    criteria = criteria or [(0, CRIT)]
    j = pre.json()
    req_cp = j["checkpoint_no"] if req_cp is None else req_cp
    gate_cp = j["gate_checkpoint_no"] if gate_cp is None else gate_cp
    ref = ref or step_ref(task, "POST_EXECUTION", gate_cp, step=step, criteria=criteria, stdout=stdout, value=value)
    if finalize and task_claims is None:
        task_claims = [task_claim(task_ref(task, gate_cp))]
    if action is not None and 'execution_receipt' not in extra:
        # Fixture-owned worker key simulates the REAL isolated executor; production
        # worker never signs without physically applying the action after PRE.
        from app.execution_receipts import body, sign
        from secrets import token_urlsafe
        receipt_body=body(task,step,gate_cp,gw.action_fingerprint(gw.Action(**action)),
                          'trusted-worker-test-fixture',action['target'],b'TEST_RUNTIME_OUTPUT',
                          token_urlsafe(24))
        extra['execution_receipt']=sign(receipt_body,EXEC_PRIV)
    r = raw_eval(task, ch, req_cp, step=step, claims=[claim(ref, i, t) for i, t in criteria], phase="POST_EXECUTION", action=action, finalize=finalize, task_claims=task_claims, **extra)
    return r, ref


def intent_fp(action):
    return gw.action_intent_fingerprint(gw.Action(**action))


def e2_action(task, cp, step="01.01", target="sandbox-target", wrong_binding=False, payload=b"TEST_RUNTIME_OUTPUT"):
    if not str(target).startswith("/"):
        target=str(WORKER_OUTPUT/(str(target)+".txt"))
    skeleton = {"action_type": "write", "target": target, "effect_class": "E2", "reversible": True, "real_world_effect": False,
                "payload_sha256":hashlib.sha256(payload).hexdigest(),"payload_bytes":len(payload),"proofs": []}
    bound = {**skeleton, "target": "unrelated-target"} if wrong_binding else skeleton
    values = {"sandbox_pass": "SANDBOX=PASS", "rollback_ready": "ROLLBACK=READY", "reversible": "REVERSIBLE=YES"}
    ref = notarized(eid("knid-task"), stdout="\n".join(values.values()), bindings=[pb(task, step, p, bound, cp, v) for p, v in values.items()])
    action = {**skeleton, "proofs": [{"purpose": p, "evidence": evp(ref)} for p in values]}
    assert intent_fp(action) == intent_fp(skeleton)
    return action


def e3_action(real=False):
    return {"action_type": "external_change", "target": "bounded-target", "effect_class": "E3", "reversible": True, "real_world_effect": real, "proofs": []}


def finish_normal(task, ch):
    pre, _ = do_pre(task, ch, 0)
    post, _ = do_post(task, ch, pre)
    assert post.status_code == 200, post.text
    cp = post.json()["checkpoint_no"]
    ppre, _ = do_pre(task, ch, cp, step="01", criteria=[(0, "parent criterion")], stdout="PARENT=PASS", value="PARENT=PASS")
    ppost, _ = do_post(task, ch, ppre, step="01", criteria=[(0, "parent criterion")], stdout="PARENT=PASS", value="PARENT=PASS", finalize=True)
    return ppost


def induce_three_failures(task, ch):
    cp = 0
    for _ in range(3):
        r = raw_eval(task, ch, cp, claims=[{"criterion_index": 0, "claim": CRIT, "evidence": [manual()]}], phase="PRE_EXECUTION")
        assert r.status_code == 200 and r.json()["verdict"] == "UNVERIFIED"
        cp = r.json()["checkpoint_no"]
    return cp


def remedial_steps():
    keys = ["01", "01.01", "01.02", "01.03", "02", "02.01", "02.02", "03", "03.01", "03.02"]
    return [{"step_key": k, "title": gw.REMEDIAL_CORE_TITLES[k], "acceptance_criteria": [f"{k} evidenced"], "required": True, "execution_required": False} for k in keys]


def register_remedial(original, origin_cp, attempt=1):
    task = eid("remedial")
    body = {"event_id": eid("reg-rem"), "task_id": task, "protocol_hash": gw.protocol_hash(), "task_kind": "REMEDIAL", "remedial_for_task_id": original, "remedial_trigger_step_key": "01.01", "remedial_origin_checkpoint_no": origin_cp, "remedial_attempt": attempt, "agent": "ChatGPT", "original_instruction": "recover blocked task", "acceptance_criteria": ["recover or prove unresolved"], "steps": remedial_steps()}
    return task, CLIENT.post("/v1/tasks/register", headers=HEAD, json=body)


def complete_remedial(rem, rch, outcome="RECOVERED", strategy="ROLLBACK"):
    cp = 0
    order = ["01.01", "01.02", "01.03", "01", "02.01", "02.02", "02", "03.01", "03.02", "03"]
    for i, key in enumerate(order):
        crit = [(0, f"{key} evidenced")]; value = f"{key}=PASS"
        pre, _ = do_pre(rem, rch, cp, step=key, criteria=crit, stdout=value, value=value)
        assert pre.json()["verdict"] == "READY_TO_EXECUTE", pre.text
        last = i == len(order) - 1
        extra = {"remedial_outcome": outcome, "recovery_strategy": strategy} if last else {}
        tc = [task_claim(task_ref(rem, pre.json()["gate_checkpoint_no"], criterion="recover or prove unresolved", value="RECOVERY=PASS"), criterion="recover or prove unresolved")] if last else None
        post, _ = do_post(rem, rch, pre, step=key, criteria=crit, stdout=value, value=value, finalize=last, task_claims=tc, **extra)
        assert post.status_code == 200, post.text
        cp = post.json()["checkpoint_no"]
    return post


def checkpoint_wal():
    c = gw.conn()
    try:
        c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        c.close()


def db_files():
    return [gw.DB_PATH, gw.DB_PATH.with_name(gw.DB_PATH.name + "-wal"), gw.DB_PATH.with_name(gw.DB_PATH.name + "-shm")]
