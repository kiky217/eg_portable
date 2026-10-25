#!/usr/bin/env python3
"""Run an operator-pinned E3 process worker with a separate OS identity.

The operator supplies a private, immutable config and protected keys; the agent
cannot select executables, arguments, UIDs, or sign its own approvals.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tools.trusted_process_effect import TrustedProcessEffect
from tools.trusted_process_catalog import TrustedProcessCatalog, validate_profiles, ProcessDenied
from tools.trusted_generic_rpc import serve


class ConfigurationDenied(ValueError):
    pass


def _private_file(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o077 or info.st_nlink != 1):
            raise ConfigurationDenied("PRIVATE_WORKER_FILE_REQUIRED")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            return stream.read(65537)
    finally:
        os.close(fd)


def load_config(path: Path) -> dict:
    if os.geteuid() == 0:
        raise ConfigurationDenied("WORKER_MUST_RUN_UNPRIVILEGED")
    value = json.loads(_private_file(path))
    fields = {"adapter_id", "capability_sha256", "socket_path", "journal_dir",
              "private_key_path", "eg_url", "eg_api_key_path", "hitl_public_key_b64",
              "controller_uid", "executable", "fixed_args", "target"}
    catalog_fields = (fields - {"executable", "fixed_args", "target"}) | {"profiles"}
    if (not isinstance(value, dict) or set(value) not in (fields, fields | {"controller_group_gid"},
                                                        catalog_fields, catalog_fields | {"controller_group_gid"})
            or type(value.get("controller_uid")) is not int
            or value["controller_uid"] in (0, os.geteuid())
            or ("fixed_args" in value and (
                not isinstance(value["fixed_args"], list)
                or len(value["fixed_args"]) > 24
                or any(not isinstance(item, str) or len(item) > 1024 for item in value["fixed_args"])))):
        raise ConfigurationDenied("INVALID_OPERATOR_WORKER_CONFIGURATION")
    if (not isinstance(value["eg_url"], str) or not value["eg_url"].startswith("https://")
        ) and not value["eg_url"].startswith(("http://127.0.0.1:", "http://localhost:")):
        raise ConfigurationDenied("UNTRUSTED_EG_ENDPOINT")
    cap_hash = value["capability_sha256"]
    if not isinstance(cap_hash, str) or len(cap_hash) != 64 or any(c not in "0123456789abcdef" for c in cap_hash):
        raise ConfigurationDenied("INVALID_CAPABILITY_DIGEST")
    key = load_pem_private_key(_private_file(Path(value["private_key_path"])), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ConfigurationDenied("WORKER_KEY_NOT_ED25519")
    token = _private_file(Path(value["eg_api_key_path"])).decode("ascii").strip()
    if not token or len(token) > 512:
        raise ConfigurationDenied("INVALID_WORKER_GATEWAY_CREDENTIAL")
    if "profiles" in value:
        try:
            value["profiles"] = validate_profiles(value["profiles"])
        except ProcessDenied as exc:
            raise ConfigurationDenied("INVALID_OPERATOR_PROFILE_CATALOG") from exc
    value["private_key"] = key
    value["eg_api_key"] = token
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path, help="operator-owned 0600 worker configuration")
    args = parser.parse_args(argv)
    config = load_config(args.config)
    common = dict(journal_dir=config["journal_dir"],
        private_key=config["private_key"], adapter_id=config["adapter_id"],
        hitl_key_b64=config["hitl_public_key_b64"])
    if "profiles" in config:
        worker = TrustedProcessCatalog(**common, profiles=config["profiles"])
    else:
        worker = TrustedProcessEffect(**common,
            executable=config["executable"], fixed_args=tuple(config["fixed_args"]),
            target=config["target"])
    serve(socket_path=config["socket_path"], adapter=worker,
          capability_sha256=config["capability_sha256"],
          eg_url=config["eg_url"], eg_key=config["eg_api_key"],
          hitl_public_key_b64=config["hitl_public_key_b64"],
          controller_uid=config["controller_uid"],
          controller_group_gid=config.get("controller_group_gid"))


if __name__ == "__main__":
    main()
