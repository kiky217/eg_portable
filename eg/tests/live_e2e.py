#!/usr/bin/env python3
"""Real-process HTTP end-to-end / adversarial check (not collected by pytest).

Starts uvicorn against an isolated temp runtime, drives the API over loopback HTTP, restarts the process,
and performs destructive database tests. Usage: python tests/live_e2e.py
"""
import base64, hashlib, json, os, secrets, shutil, socket, sqlite3, subprocess, sys, tempfile, time
from pathlib import Path
import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
TMP = Path(tempfile.mkdtemp(prefix="eg-live-"))
(TMP / "evidence").mkdir(); (TMP / "evidence").chmod(0o755)
PRIV = Ed25519PrivateKey.generate()
EXEC_PRIV = Ed25519PrivateKey.generate()
ENV = {**os.environ, "EVALUATION_GATEWAY_API_KEY": secrets.token_urlsafe(48), "EVALUATION_GATEWAY_HITL_KEY": secrets.token_urlsafe(48), "EVALUATION_GATEWAY_AUDIT_HMAC_KEY": secrets.token_urlsafe(48),
       "EVALUATION_GATEWAY_EVIDENCE_PUBLIC_KEY_B64": base64.b64encode(PRIV.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode(),
       "EVALUATION_GATEWAY_EXECUTOR_PUBLIC_KEY_B64": base64.b64encode(EXEC_PRIV.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode(),
       "EVALUATION_GATEWAY_EVIDENCE_ROOT": str(TMP / "evidence"), "EVALUATION_GATEWAY_DB_PATH": str(TMP / "data" / "gateway.db"), "EVALUATION_GATEWAY_ANCHOR_PATH": str(TMP / "anchor" / "audit.anchor"),
       "EVALUATION_GATEWAY_TRUSTED_EVIDENCE_UID": str(os.getuid())}
def reserve_test_port():
    # Avoid a fixed port colliding with a legitimate service on a shared test host.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


PORT = int(os.environ["EG_LIVE_PORT"]) if "EG_LIVE_PORT" in os.environ else reserve_test_port()
URL = f"http://127.0.0.1:{PORT}"
HEAD = {"X-Evaluation-Key": ENV["EVALUATION_GATEWAY_API_KEY"]}; HITL = {**HEAD, "X-Evaluation-HITL-Key": ENV["EVALUATION_GATEWAY_HITL_KEY"]}
results = []; proc = None


def check(name, cond):
    results.append((name, bool(cond))); print(("PASS " if cond else "FAIL ") + name, flush=True)


def start(env=None, expect_up=True):
    global proc
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(PORT), "--no-access-log"], cwd=ROOT, env=env or ENV, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for _ in range(100):
        if proc.poll() is not None:
            return False
        try:
            # A different local service may also answer /health; require the
            # authenticated EG protocol endpoint and our own live subprocess.
            response = httpx.get(URL + "/v1/protocol", headers=HEAD, timeout=1)
            if proc.poll() is None and response.status_code == 200 and isinstance(response.json().get("hash"), str):
                return True
        except httpx.HTTPError:
            pass
        time.sleep(0.1)
    return False


def stop():
    global proc
    if proc and proc.poll() is None:
        proc.terminate(); proc.wait(10)
    proc = None


def canon(v): return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def notarize(bindings, stdout="CHECK=PASS"):
    sid = f"knid-{time.time_ns()}"; d = TMP / "evidence" / sid; d.mkdir(mode=0o700)
    state = {"task_id": sid, "status": "PASS", "exit_code": 0, "finished_at": time.time()}; sr = canon(state).encode(); out = stdout.encode()
    (d / "state.json").write_bytes(sr); (d / "stdout.log").write_bytes(out)
    payload = {"manifest_version": 4, "task_id": sid, "state_sha256": hashlib.sha256(sr).hexdigest(), "stdout_sha256": hashlib.sha256(out).hexdigest(), "finished_at": state["finished_at"], "bindings": bindings}
    (d / "evidence.json").write_text(canon({**payload, "notary_ed25519_signature_b64": base64.b64encode(PRIV.sign(canon(payload).encode())).decode()}))
    for p in d.iterdir(): p.chmod(0o600)
    d.chmod(0o700); return sid


def sb(task, step, idx, crit, phase, cp, value="CHECK=PASS"):
    return {"kind": "step_criterion", "eg_task_id": task, "step_key": step, "criterion_index": idx, "criterion": crit, "phase": phase, "checkpoint_no": cp, "matcher": {"kind": "contains", "value": value}}


def tb(task, idx, crit, cp):
    return {"kind": "task_criterion", "eg_task_id": task, "criterion_index": idx, "criterion": crit, "phase": "POST_EXECUTION", "checkpoint_no": cp, "matcher": {"kind": "contains", "value": "TASK=PASS"}}


def cl(ref, idx, text): return {"criterion_index": idx, "claim": text, "evidence": [{"source_type": "trusted_task", "reference": ref}]}


class C:
    def __init__(self): self.h = httpx.Client(base_url=URL, timeout=20)

    def reg(self, task, crit="Hasil tes — lulus (é)"):
        body = {"event_id": f"r-{time.time_ns()}", "task_id": task, "protocol_hash": self.h.get("/v1/protocol", headers=HEAD).json()["hash"], "agent": "ChatGPT", "original_instruction": "x", "acceptance_criteria": ["all steps evidenced"], "steps": [{"step_key": "01", "title": "P", "acceptance_criteria": ["parent criterion"],"execution_required":False}, {"step_key": "01.01", "title": "C", "acceptance_criteria": [crit],"execution_required":False}]}
        r = self.h.post("/v1/tasks/register", headers=HEAD, json=body); return r.json()["contract_hash"] if r.status_code == 200 else None

    def ev(self, task, ch, cp, step, claims, phase, headers=HEAD, finalize=False, task_claims=None, action=None):
        ph = self.h.get("/v1/protocol", headers=HEAD).json()["hash"]
        return self.h.post("/v1/evaluate", headers=headers, json={"event_id": f"e-{time.time_ns()}", "task_id": task, "contract_hash": ch, "protocol_hash": ph, "checkpoint_no": cp, "step_key": step, "agent": "ChatGPT", "phase": phase, "finalize_task": finalize, "claims": claims, "task_claims": task_claims or [], "action": action})


def main():
    check("service starts and /health is minimal", start() and httpx.get(URL + "/health").json() == {"status": "PASS"})
    c = C(); crit = "Hasil tes — lulus (é)"
    check("unauthenticated /v1/protocol -> 401", httpx.get(URL + "/v1/protocol").status_code == 401)
    check("non-ASCII key header -> 401 (not 500)", httpx.get(URL + "/v1/protocol", headers={"X-Evaluation-Key": "é".encode("latin-1")}).status_code == 401)
    check("oversized body -> 413", httpx.post(URL + "/v1/tasks/register", headers=HEAD, content=b"x" * 1_000_100).status_code == 413)
    task = f"t-{time.time_ns()}"; ch = c.reg(task); check("register task with non-ASCII criterion", ch)
    r = c.ev(task, ch, 0, "01.01", [{**cl("x", 0, crit), "max_age_seconds": 999999}], "PRE_EXECUTION"); check("client max_age_seconds rejected (422)", r.status_code == 422)
    pre_ref = notarize([sb(task, "01.01", 0, crit, "PRE_EXECUTION", 0)]); pre = c.ev(task, ch, 0, "01.01", [cl(pre_ref, 0, crit)], "PRE_EXECUTION")
    check("PRE READY with phase/checkpoint-bound evidence", pre.json().get("verdict") == "READY_TO_EXECUTE" and pre.json()["gate_checkpoint_no"] == 1)
    replay = c.ev(task, ch, 1, "01.01", [cl(pre_ref, 0, crit)], "POST_EXECUTION"); check("PRE evidence replayed as POST -> UNVERIFIED", replay.json().get("verdict") == "UNVERIFIED")
    bad_ref = notarize([sb(task, "01.01", 0, crit, "POST_EXECUTION", 1)], stdout="NOTHING"); bad = c.ev(task, ch, 2, "01.01", [cl(bad_ref, 0, crit)], "POST_EXECUTION")
    check("POST with refuting signed matcher -> UNVERIFIED", bad.json().get("verdict") == "UNVERIFIED")
    st = c.h.get(f"/v1/tasks/{task}/state", headers=HEAD).json(); check("state exposes pending gate to retry", st["pending_execution_gate"]["pre_checkpoint_no"] == 1)
    ok_ref = notarize([sb(task, "01.01", 0, crit, "POST_EXECUTION", 1)]); ok = c.ev(task, ch, 3, "01.01", [cl(ok_ref, 0, crit)], "POST_EXECUTION")
    check("POST retried on SAME gate -> VERIFIED_PASS", ok.json().get("verdict") == "VERIFIED_PASS" and ok.json()["gate_checkpoint_no"] == 1)
    p2ref = notarize([sb(task, "01", 0, "parent criterion", "PRE_EXECUTION", 4)]); p2 = c.ev(task, ch, 4, "01", [cl(p2ref, 0, "parent criterion")], "PRE_EXECUTION")
    f_ref = notarize([sb(task, "01", 0, "parent criterion", "POST_EXECUTION", 5)]); t_ref = notarize([tb(task, 0, "all steps evidenced", 5)], stdout="TASK=PASS")
    fin = c.ev(task, ch, 5, "01", [cl(f_ref, 0, "parent criterion")], "POST_EXECUTION", finalize=True, task_claims=[cl(t_ref, 0, "all steps evidenced")])
    check("task finalizes SATISFIED", p2.json().get("verdict") == "READY_TO_EXECUTE" and fin.json().get("contract_status") == "SATISFIED")
    check("terminal state -> STOP", c.h.get(f"/v1/tasks/{task}/state", headers=HEAD).json()["next_action"] == "STOP")
    # HITL + abort
    t2 = f"t-{time.time_ns()}"; ch2 = c.reg(t2)
    governed_action = {"action_type": "external_change", "target": "x", "effect_class": "governed_operation", "reversible": True, "real_world_effect": False, "proofs": []}
    r_ref = notarize([sb(t2, "01.01", 0, crit, "PRE_EXECUTION", 0)]); p = c.ev(t2, ch2, 0, "01.01", [cl(r_ref, 0, crit)], "PRE_EXECUTION", action=governed_action)
    check("unprovisioned governed_operation -> capability fail-closed 409", p.status_code == 409 and p.json().get("detail", {}).get("code") == "UNSUPPORTED_ACTION_CAPABILITY_FAIL_CLOSED")
    ab = {"event_id": f"a-{time.time_ns()}", "contract_hash": ch2, "protocol_hash": c.h.get("/v1/protocol", headers=HEAD).json()["hash"], "checkpoint_no": 0, "reason": "e2e abort"}
    check("abort without HITL key -> 403", c.h.post(f"/v1/tasks/{t2}/abort", headers=HEAD, json=ab).status_code == 403)
    check("abort with HITL key -> ABORTED", c.h.post(f"/v1/tasks/{t2}/abort", headers=HITL, json=ab).json().get("contract_status") == "ABORTED")
    a = c.h.get("/v1/audit/verify", headers=HEAD).json(); anchor = json.loads((TMP / "anchor" / "audit.anchor").read_text())
    check("audit verify PASS and anchor equals ledger head", a["status"] == "PASS" and anchor["seq"] == a["records"] and anchor["head"] == a["head"])
    t0 = time.time(); codes = [httpx.get(URL + "/health").status_code for _ in range(300)]; el = time.time() - t0
    check(f"300 unauthenticated /health calls all 200 ({el:.2f}s)", set(codes) == {200})
    stop(); check("restart preserves verified state", start() and httpx.get(URL + "/v1/tasks/%s/state" % task, headers=HEAD).json()["contract_status"] == "SATISFIED")
    # destructive tests
    stop(); db = Path(ENV["EVALUATION_GATEWAY_DB_PATH"]); snapshot = TMP / "snap.db"
    s = sqlite3.connect(db); s.execute("PRAGMA wal_checkpoint(TRUNCATE)"); s.close(); shutil.copy2(db, snapshot)
    assert start(); t3 = f"t-{time.time_ns()}"; check("new task after snapshot", C().reg(t3)); stop()
    s = sqlite3.connect(db); s.execute("PRAGMA wal_checkpoint(TRUNCATE)"); s.close()
    good = TMP / "good.db"; shutil.copy2(db, good)
    s = sqlite3.connect(db); s.execute("UPDATE audit SET response_json='{\"x\":1}' WHERE seq=(SELECT MAX(seq) FROM audit)"); s.commit(); s.close()
    check("audit row tamper -> refuses to start", not start()); stop()
    for f in (db, db.with_name(db.name + "-wal"), db.with_name(db.name + "-shm")):
        if f.exists(): f.unlink()
    shutil.copy2(snapshot, db)
    check("whole-DB rollback -> refuses to start", not start()); stop()
    rp = subprocess.run([sys.executable, str(ROOT / "tools" / "reanchor.py"), "--confirm"], env=ENV, cwd=ROOT, capture_output=True, text=True)
    check("reanchor after deliberate restore", rp.returncode == 0 and start()); stop()
    weak = {**ENV, "EVALUATION_GATEWAY_API_KEY": "<generate-at-least-32-random-bytes>"}
    check("placeholder secret -> refuses to start", not start(weak)); stop()
    bad_root = {**ENV}; (TMP / "evidence").chmod(0o777)
    check("group/other-writable evidence root -> refuses to start", not start(bad_root)); stop(); (TMP / "evidence").chmod(0o755)
    passed = sum(1 for _, ok in results if ok); print(f"\nLIVE E2E: {passed}/{len(results)} PASS"); return 0 if passed == len(results) else 1


if __name__ == "__main__":
    try:
        rc = main()
    finally:
        stop(); shutil.rmtree(TMP, ignore_errors=True)
    sys.exit(rc)
