#!/usr/bin/env python3
"""Read-only local agent preflight. Never authorizes execution or reveals secrets."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from no_redirect_http import urlopen
from capability_catalog import parse_catalog, lookup, CatalogError

BUILTIN = {"E0": {"read"}, "E2": {"write"}}
ENV_MODE = "EVALUATION_GATEWAY_ADMISSION_MODE"
ENV_ROOT = "EVALUATION_GATEWAY_EXECUTOR_OUTPUT_ROOT"
ENV_KEY = "EVALUATION_GATEWAY_EXECUTOR_PUBLIC_KEY_B64"


def diagnose(effect: str, action: str, env: dict[str, str], catalog=()) -> dict:
    """Static diagnostics ONLY; a successful result is not proof of a live worker."""
    mode = env.get(ENV_MODE, "enabled")
    key_present = bool(env.get(ENV_KEY, "").strip())
    output_root_present = bool(env.get(ENV_ROOT, "").strip())
    candidates = lookup(catalog, effect, action)
    reasons = []
    if mode not in {"enabled", "disabled"}:
        reasons.append("INVALID_ADMISSION_MODE")
    if mode == "disabled":
        reasons.append("ADMISSION_DISABLED_ALL_CONCRETE_ACTIONS_DENIED")
    if not key_present:
        reasons.append("EXECUTOR_PUBLIC_KEY_NOT_CONFIGURED")
    if effect not in BUILTIN or action not in BUILTIN.get(effect, set()):
        reasons.append("EXTERNAL_CAPABILITY_UNVERIFIED" if candidates else "CAPABILITY_NOT_DISCOVERED")
    if effect == "E2" and action == "write" and not output_root_present:
        reasons.append("EXECUTOR_OUTPUT_ROOT_NOT_CONFIGURED")
    # Even with every local setting present, runtime authentication, separate
    # signer identity and exact PRE must be checked against live EG.
    reasons.append("LIVE_EXECUTOR_IDENTITY_CAPABILITY_AND_PRE_NOT_VERIFIED")
    return {
        "preflight": "NOT_ADMITTED" if len(reasons) > 1 else "REQUIRES_LIVE_VERIFICATION",
        "admission_mode": mode,
        "effect": effect,
        "action": action,
        "builtin_dispatcher_action_supported": action in BUILTIN.get(effect, set()),
        "executor_public_key_configured": key_present,
        "executor_output_root_configured": output_root_present,
        "reasons": reasons,
        "discovered_candidates": list(candidates),
        "mutated": False,
        "live_verified": False,
    }


def diagnose_live(effect: str, action: str, *, url: str, api_key: str) -> dict:
    """Authenticated read-only runtime discovery; NEVER substitutes PRE."""
    loc = urlsplit(url)
    if (loc.username or loc.password or loc.query or loc.fragment or
        not (loc.scheme == "https" or
             (loc.scheme == "http" and loc.hostname in ("127.0.0.1", "localhost")))):
        raise ValueError("UNTRUSTED_EG_DISCOVERY_URL")
    if not api_key:
        raise ValueError("EG_DISCOVERY_API_KEY_REQUIRED")
    endpoint = url.rstrip("/") + "/v1/agent/capabilities"
    with urlopen(Request(endpoint, headers={"X-Evaluation-Key": api_key}), timeout=5) as response:
        payload = json.load(response)
    if not isinstance(payload, dict) or not isinstance(payload.get("capabilities"), list):
        raise ValueError("INVALID_EG_DISCOVERY_RESPONSE")
    matches = [row for row in payload["capabilities"] if isinstance(row,dict)
               and row.get("effect_class") == effect and row.get("action_type") == action]
    valid_catalog = payload.get("catalog_valid") is True
    mode = payload.get("admission_mode")
    trusted_statuses = {"CONFIGURED_NEEDS_LIVE_PRE", "EXTERNAL_LIVE_PRE_ATTESTATION_REQUIRED"}
    available = valid_catalog and mode == "enabled" and any(
        isinstance(row.get("status"),str) and row["status"] in trusted_statuses
        for row in matches)
    reason = ("INVALID_LIVE_CAPABILITY_CATALOG" if not valid_catalog else
              "ADMISSION_DISABLED" if mode != "enabled" else
              "CAPABILITY_NOT_DISCOVERED" if not matches else
              "OPERATOR_BINDING_REQUIRED" if any(
                  row.get("status") == "EXTERNAL_OPERATOR_BINDING_REQUIRED" for row in matches)
              else "MATCHED_CAPABILITY_NOT_TRUSTED")
    return {"effect":effect, "action":action,
            "preflight":"REQUIRES_LIVE_PRE" if available else "NOT_ADMITTED",
            "reasons":[] if available else [reason],
            "candidates":matches, "registered_count":len(matches),
            "admission_mode":payload.get("admission_mode"),
            "catalog_valid":payload.get("catalog_valid") is True,
            "live_discovery":True,"live_verified":False,"mutated":False,
            "note":"Discovery is not a live signed PRE or execution authorization."}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--effect", required=True, choices=["E0", "E1", "E2", "E3", "E4", "E5"])
    parser.add_argument("--action", required=True, help="Typed action name, e.g. read, write, service_control")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable diagnostics")
    parser.add_argument("--catalog", type=Path, help="Optional untrusted local JSON capability catalog")
    parser.add_argument("--url", help="Live EG URL (HTTPS or local loopback HTTP only)")
    args = parser.parse_args(argv)
    try:
        catalog = parse_catalog(args.catalog.read_text(encoding="utf-8")) if args.catalog else ()
    except (OSError, CatalogError) as exc:
        parser.error(f"catalog rejected: {exc}")
    try:
        report = (diagnose_live(args.effect, args.action, url=args.url,
                                api_key=os.getenv("EVALUATION_GATEWAY_API_KEY", ""))
                  if args.url else diagnose(args.effect, args.action, dict(os.environ), catalog))
    except (OSError, ValueError) as exc:
        parser.error(f"live capability discovery failed: {type(exc).__name__}")
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print(f"EG agent preflight: {report['preflight']} (not live authorization)")
        print(f"admission={report['admission_mode']} effect={args.effect} action={args.action}")
        print("Reasons: " + ", ".join(report.get("reasons", ["LIVE_PRE_REQUIRED"])))
    return 0 if report["preflight"] in ("REQUIRES_LIVE_VERIFICATION","REQUIRES_LIVE_PRE") else 2


if __name__ == "__main__":
    raise SystemExit(main())
