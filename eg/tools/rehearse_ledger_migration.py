#!/usr/bin/env python3
"""Read-only migration rehearsal of an EG ledger with the ONE current core.

This creates an isolated SQLite backup and audit-anchor copy, starts a
disposable new-core process against that COPY and checks historical and
in-flight task continuity. It never connects a second writer to the live DB,
never claims production executor isolation and never changes source ledger.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request
from no_redirect_http import urlopen


def env_from_file(path: Path) -> dict[str, str]:
    result = {}
    for line in path.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        name, sep, value = line.partition("=")
        if sep:
            result[name.strip()] = value.strip().strip('"').strip("'")
    return result


def scalar(conn: sqlite3.Connection, statement: str, args: tuple = ()):
    return conn.execute(statement, args).fetchone()


def source_state(db: Path, task: str, historical: str):
    conn = sqlite3.connect("file:" + str(db) + "?mode=ro", uri=True)
    try:
        count = scalar(conn, "SELECT COUNT(*),MAX(seq) FROM audit")
        old = scalar(conn,
                     "SELECT contract_status,checkpoint_no FROM task_registry WHERE task_id=?",
                     (historical,))
        cur = scalar(conn,
                     "SELECT contract_status,checkpoint_no FROM task_registry WHERE task_id=?",
                     (task,))
        gate = scalar(conn,
                      "SELECT step_key,pre_checkpoint_no,consumed FROM execution_gates "
                      "WHERE task_id=? AND consumed=0 ORDER BY pre_checkpoint_no DESC LIMIT 1",
                      (task,))
        return {"audit": tuple(count), "historical": tuple(old) if old else None,
                "current": tuple(cur) if cur else None,
                "gate": tuple(gate) if gate else None}
    finally:
        conn.close()


def request(port: int, path: str, api_key: str, body=None):
    headers = {"X-Evaluation-Key": api_key}
    data = None
    method = "GET"
    if body is not None:
        method = "POST"
        data = json.dumps(body, separators=(",", ":")).encode()
        headers["Content-Type"] = "application/json"
    with urlopen(Request(f"http://127.0.0.1:{port}{path}", data=data,
                         method=method, headers=headers), timeout=3) as response:
        return json.loads(response.read())


def choose_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ("db", "anchor", "evidence", "runtime-env-file",
                 "historical-task", "open-task"):
        ap.add_argument("--" + name, required=True)
    ap.add_argument("--uid", type=int, default=os.getuid())
    ap.add_argument("--gid", type=int, default=os.getgid())
    ap.add_argument("--report", type=Path)
    args = ap.parse_args()
    paths = {name: Path(getattr(args, name.replace("-", "_"))).resolve()
             for name in ("db", "anchor", "evidence", "runtime-env-file")}
    for name in ("db", "anchor", "runtime-env-file"):
        if not paths[name].is_file():
            raise RuntimeError("INPUT_NOT_FOUND_" + name.upper())
    if not paths["evidence"].is_dir():
        raise RuntimeError("EVIDENCE_ROOT_NOT_FOUND")
    if args.uid == 0:
        raise RuntimeError("STAGED_EG_MUST_USE_NONROOT_UID")
    if os.geteuid() != 0 and args.uid != os.geteuid():
        raise RuntimeError("NONROOT_CANNOT_SWITCH_UID")
    source = source_state(paths["db"], args.open_task, args.historical_task)
    if not (source["historical"] and source["historical"][0] == "SATISFIED"):
        raise RuntimeError("HISTORICAL_TASK_NOT_SATISFIED")
    if not (source["current"] and source["current"][0] == "OPEN"):
        raise RuntimeError("CURRENT_TASK_NOT_OPEN")
    if not (source["gate"] and source["gate"][2] == 0):
        raise RuntimeError("EXPECTED_PENDING_GATE_NOT_FOUND")

    before_anchor = paths["anchor"].read_bytes()
    env_secrets = env_from_file(paths["runtime-env-file"])
    if not env_secrets.get("EVALUATION_GATEWAY_API_KEY"):
        raise RuntimeError("API_KEY_MISSING")
    stage = Path(tempfile.mkdtemp(prefix="eg-migration-rehearsal-"))
    process = None
    try:
        stage.chmod(0o711)
        for name in ("data", "anchor"):
            p = stage / name
            p.mkdir(mode=0o700)
            os.chown(p, args.uid, args.gid)
        copied_db = stage / "data/gateway.db"
        reader = sqlite3.connect("file:" + str(paths["db"]) + "?mode=ro", uri=True)
        writer = sqlite3.connect(copied_db)
        try:
            reader.backup(writer)
        finally:
            reader.close()
            writer.close()
        os.chown(copied_db, args.uid, args.gid)
        copied_db.chmod(0o600)
        copied_anchor = stage / "anchor/audit.anchor"
        shutil.copyfile(paths["anchor"], copied_anchor)
        os.chown(copied_anchor, args.uid, args.gid)
        copied_anchor.chmod(0o600)
        if source != source_state(paths["db"], args.open_task, args.historical_task):
            raise RuntimeError("SOURCE_CHANGED_DURING_SNAPSHOT")
        if paths["anchor"].read_bytes() != before_anchor:
            raise RuntimeError("SOURCE_ANCHOR_CHANGED_DURING_SNAPSHOT")

        port = choose_port()
        env = dict(os.environ)
        env.update(env_secrets)
        env.update({
            "EVALUATION_GATEWAY_DB_PATH": str(copied_db),
            "EVALUATION_GATEWAY_ANCHOR_PATH": str(copied_anchor),
            "EVALUATION_GATEWAY_EVIDENCE_ROOT": str(paths["evidence"]),
            "EVALUATION_GATEWAY_ADMISSION_MODE": "disabled",
            "EVALUATION_GATEWAY_EXECUTOR_PUBLIC_KEY_B64": "",
            "EVALUATION_GATEWAY_TRUSTED_EVIDENCE_UID": str(args.uid),
            "EVALUATION_GATEWAY_INTEGRITY_CACHE_SECONDS": "0",
        })
        root = Path(__file__).resolve().parents[1]
        def demote():
            if os.geteuid() == 0:
                os.setgroups([])
                os.setgid(args.gid)
                os.setuid(args.uid)
        logpath = stage / "server.log"
        with logpath.open("wb") as logfile:
            process = subprocess.Popen([
                sys.executable, "-m", "uvicorn", "app.main:app", "--app-dir",
                str(root), "--host", "127.0.0.1", "--port", str(port),
                "--no-access-log"], cwd=str(root), env=env, preexec_fn=demote,
                stdout=logfile, stderr=subprocess.STDOUT)
        audit = None
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError("STAGE_EXITED_BEFORE_AUDIT")
            try:
                audit = request(port, "/v1/audit/verify",
                                env["EVALUATION_GATEWAY_API_KEY"])
                if audit.get("status") == "PASS":
                    break
            except (URLError, TimeoutError, ConnectionError):
                time.sleep(0.1)
        if not audit or audit.get("status") != "PASS":
            raise RuntimeError("STAGE_AUDIT_NOT_PASS")
        old = request(port, "/v1/tasks/" + args.historical_task + "/state",
                      env["EVALUATION_GATEWAY_API_KEY"])
        cur = request(port, "/v1/tasks/" + args.open_task + "/state",
                      env["EVALUATION_GATEWAY_API_KEY"])
        if not (old["contract_status"] == "SATISFIED" and old["terminal"]
                and old["latest_checkpoint"]["checkpoint_no"] == source["historical"][1]):
            raise RuntimeError("HISTORICAL_LEDGER_NOT_EQUIVALENT")
        gate = cur.get("pending_execution_gate")
        if not (cur["contract_status"] == "OPEN"
                and cur["latest_checkpoint"]["checkpoint_no"] == source["current"][1]
                and gate and gate["pre_checkpoint_no"] == source["gate"][1]):
            raise RuntimeError("INFLIGHT_GATE_NOT_PRESERVED")

        conn = sqlite3.connect("file:" + str(copied_db) + "?mode=ro", uri=True)
        try:
            action = None
            for row in conn.execute(
                "SELECT request_json FROM audit WHERE task_id=? AND event_type='EVALUATION' "
                "ORDER BY seq DESC", (args.open_task,)):
                value = json.loads(row[0])
                if (value.get("step_key") == source["gate"][0]
                        and value.get("phase") == "PRE_EXECUTION"):
                    action = value
                    break
        finally:
            conn.close()
        if not action or not action.get("action"):
            raise RuntimeError("ORIGINAL_PRE_ACTION_UNAVAILABLE")
        probe = dict(action, event_id="rehearsal-" + uuid.uuid4().hex,
                     checkpoint_no=source["current"][1],
                     phase="POST_EXECUTION", execution_receipt=None)
        try:
            request(port, "/v1/evaluate", env["EVALUATION_GATEWAY_API_KEY"], probe)
            raise RuntimeError("UNAUTHORIZED_ACTION_WAS_ACCEPTED")
        except HTTPError as exc:
            reason = json.loads(exc.read())
            if not (exc.code == 409 and reason.get("detail", {}).get("code")
                    == "TRUSTED_EXECUTOR_UNAVAILABLE_FAIL_CLOSED"):
                raise RuntimeError("WRONG_FAIL_CLOSED_VERDICT") from exc

        after = source_state(paths["db"], args.open_task, args.historical_task)
        if after != source or paths["anchor"].read_bytes() != before_anchor:
            raise RuntimeError("LIVE_STATE_CHANGED_DURING_REHEARSAL")
        staged = source_state(copied_db, args.open_task, args.historical_task)
        if staged != source or copied_anchor.read_bytes() != before_anchor:
            raise RuntimeError("STAGED_LEDGER_CHANGED_OR_DIVERGED")
        if int(audit.get("records", -1)) != source["audit"][0]:
            raise RuntimeError("AUDIT_RECORD_COUNT_MISMATCH")
        result = {
            "status": "PASS",
            "migration_compatible": True,
            "task_id": args.open_task,
            "historical_task": args.historical_task,
            "historical_checkpoint": source["historical"][1],
            "current_checkpoint": source["current"][1],
            "pending_gate": source["gate"][0],
            "audit_records": source["audit"][0],
            "audit_head": audit["head"],
            "audit": "PASS",
            "stage_admission": "disabled",
            "unauthorized_concrete_action": "DENIED_409",
            "single_writer_live_state": True,
            "source_unchanged": True,
            "production_signer_isolation_verified": False,
            "cutover_performed": False,
        }
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            if args.report.exists():
                raise RuntimeError("REPORT_ALREADY_EXISTS_NO_OVERWRITE")
            with args.report.open("x") as stream:
                json.dump(result, stream, indent=2, sort_keys=True)
                stream.write("\n")
        print(json.dumps(result, sort_keys=True))
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        shutil.rmtree(stage, ignore_errors=True)


if __name__ == "__main__":
    main()
