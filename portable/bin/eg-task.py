#!/usr/bin/env python3
"""Portable EG task admission. All jobs through THIS managed entrypoint require EG proof.

Scope: this executable and consumers explicitly calling it. Does NOT intercept
Colab root shell, direct notebook Python, or unrelated processes.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.request import Request, urlopen

WORKSPACE = Path("/content/workspace")
PYTHON = WORKSPACE / "eg/.venv/bin/python"
ENDPOINT = "http://127.0.0.1:18765"
ENVFILE = WORKSPACE / "eg/secrets/runtime.env"
POLICY_VERSION = "portable-eg-mandatory-v1"

# HARDCODED POLICY: these flags cannot be overridden from environment/config.
EG_REQUIRED = True
REQUIRE_SIGNED_PRE = True
REQUIRE_VERIFIED_POST = True
REQUIRE_TERMINAL_ACCEPTANCE = True
REQUIRE_AUTHENTICATED_AUDIT = True
DENY_UNREGISTERED = True
DENY_UNLISTED = True
NO_AUTOMATIC_RETRY_UNKNOWN_EFFECT = True
EFFECTS_E3_TO_E5_DENIED = True

# Explicitly allowlisted jobs. Do NOT accept paths, shell strings or arbitrary scripts.
JOBS = {
    "hostname": ("bin/eg-gated-run.py", "E0"),
    "uptime": ("bin/eg-gated-run.py", "E0"),
    "workspace-list": ("bin/eg-gated-run.py", "E0"),
    "e2-smoke": ("bin/eg-e2-managed.py", "E2"),
}
TASK_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class Denied(RuntimeError):
    pass


def require_policy():
    expected = (EG_REQUIRED, REQUIRE_SIGNED_PRE, REQUIRE_VERIFIED_POST,
                REQUIRE_TERMINAL_ACCEPTANCE, REQUIRE_AUTHENTICATED_AUDIT,
                DENY_UNREGISTERED, DENY_UNLISTED,
                NO_AUTOMATIC_RETRY_UNKNOWN_EFFECT, EFFECTS_E3_TO_E5_DENIED)
    if not all(expected):
        raise Denied("mandatory portable EG policy disabled")
    if not (WORKSPACE / "AGENTS.md").is_file():
        raise Denied("canonical workspace policy missing")
    if not PYTHON.is_file():
        raise Denied("canonical EG Python runtime missing")
    if not ENVFILE.is_file():
        raise Denied("EG credentials unavailable")


def api_token():
    for line in ENVFILE.read_text().splitlines():
        if line.startswith("EVALUATION_GATEWAY_API_KEY="):
            value = line.split("=", 1)[1].strip()
            if len(value) >= 32:
                return value
    raise Denied("EG authentication unavailable")


def eg_get(path):
    request = Request(ENDPOINT + path, headers={"X-Evaluation-Key": api_token()})
    with urlopen(request, timeout=15) as response:
        return json.loads(response.read())


def require_audit():
    audit = eg_get("/v1/audit/verify")
    if audit.get("status") != "PASS":
        raise Denied("EG authenticated audit not PASS")
    if audit.get("chain") != "AUTHENTICATED_VALID":
        raise Denied("EG audit chain not authenticated")
    if audit.get("anchor") != "VALID":
        raise Denied("EG audit anchor not valid")
    return audit


def check_terminal(task_id, job, effect):
    if not isinstance(task_id, str) or not TASK_RE.fullmatch(task_id):
        raise Denied("job result lacks valid EG task identity")
    state = eg_get("/v1/tasks/" + task_id + "/state")
    if (state.get("task_id") != task_id
            or state.get("contract_status") != "SATISFIED"
            or state.get("terminal") is not True
            or state.get("next_action") != "STOP"
            or state.get("pending_execution_gate") is not None
            or state.get("latest_checkpoint", {}).get("verdict") != "VERIFIED_PASS"
            or state.get("latest_checkpoint", {}).get("verified") != 1):
        raise Denied("EG task not terminal VERIFIED_PASS")
    detail = eg_get("/v1/tasks/" + task_id)
    contract = detail.get("task", {})
    expected_instruction = ("E0 approved probe " + job if effect == "E0"
        else "One sandbox-limited, reversible E2 file creation")
    if (contract.get("task_id") != task_id
            or contract.get("agent") != "ColabEGTaskRunner"
            or contract.get("task_kind") != "NORMAL"
            or contract.get("original_instruction") != expected_instruction
            or contract.get("contract_status") != "SATISFIED"):
        raise Denied("EG registered task does not match authorized job")
    steps = detail.get("steps", [])
    checkpoints = detail.get("checkpoints", [])
    if not steps or not checkpoints or any(
        step.get("required") != 1 or step.get("verified") != 1
        or step.get("last_verdict") != "VERIFIED_PASS" for step in steps
    ):
        raise Denied("EG acceptance criteria incomplete")
    for step in steps:
        events = [cp for cp in checkpoints if cp.get("step_key") == step["step_key"]]
        if (not any(cp.get("verdict") == "READY_TO_EXECUTE" for cp in events)
                or not any(cp.get("verdict") == "VERIFIED_PASS"
                           and cp.get("verified") == 1 for cp in events)):
            raise Denied("EG PRE/POST missing for a required step")
    if checkpoints[-1].get("checkpoint_no") != state["latest_checkpoint"]["checkpoint_no"]:
        raise Denied("EG checkpoint identity mismatch")
    return state


def execute(job):
    require_policy()
    if job not in JOBS:
        raise Denied("job not in hardcoded EG allowlist")
    relative_script, effect = JOBS[job]
    if effect not in ("E0", "E2"):
        raise Denied("effect class not authorized by portable EG executor")
    require_audit()  # Fail closed BEFORE any execution.
    script = WORKSPACE / relative_script
    if not script.is_file() or script.is_symlink():
        raise Denied("registered executor unavailable or linked")
    argv = [str(PYTHON), str(script)]
    if effect == "E0":
        argv.append(job)
    # No shell=True; never retry an uncertain E2 outcome.
    clean_env = os.environ.copy()
    for key in ("PYTHONPATH", "PYTHONSTARTUP", "PYTHONINSPECT", "LD_PRELOAD"):
        clean_env.pop(key, None)
    clean_env["HOME"] = str(WORKSPACE / "config/rea-home")
    result = subprocess.run(argv, cwd=WORKSPACE, env=clean_env,
                            text=True, capture_output=True, timeout=120)
    if result.returncode != 0:
        raise Denied("executor returned nonzero; reconcile any E2 effect before retry")
    try:
        answer = json.loads(result.stdout.strip())
    except (ValueError, TypeError) as exc:
        raise Denied("executor did not return valid EG receipt") from exc
    if not isinstance(answer, dict) or answer.get("status") != "EG_VERIFIED":
        raise Denied("executor did not provide VERIFIED EG receipt")
    if effect == "E2" and answer.get("effect") != "E2_FILE_WRITE":
        raise Denied("E2 effect receipt mismatch")
    state = check_terminal(answer.get("task_id"), job, effect)
    require_audit()  # Post-execution independent gateway confirmation.
    receipt = {"policy": POLICY_VERSION, "effect_class": effect,
               "job": job, "task_id": state["task_id"],
               "checkpoint": state["latest_checkpoint"]["checkpoint_no"],
               "status": "VERIFIED", "eg_contract": "SATISFIED"}
    print(json.dumps(receipt, sort_keys=True))
    return 0


def main():
    if len(sys.argv) != 2:
        raise Denied("exactly one registered task name required")
    return execute(sys.argv[1])


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        # No API secrets or credential data are printed; fail closed.
        print("EG_HARD_POLICY_DENIED " + type(exc).__name__, file=sys.stderr)
        sys.exit(77)
