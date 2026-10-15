#!/usr/bin/env python3
"""Generate the three distinct gateway secrets (API key, HITL key, audit HMAC key).

Usage:
  generate_secrets.py [OUTPUT_ENV_FILE]

With an output path the lines are written with mode 0600 (existing files are never overwritten);
otherwise they are printed to stdout. Values are 48 random bytes, URL-safe base64, which satisfy
the gateway's length/charset/entropy validation.
"""
import os
import secrets
import sys

NAMES = ("EVALUATION_GATEWAY_API_KEY", "EVALUATION_GATEWAY_HITL_KEY", "EVALUATION_GATEWAY_AUDIT_HMAC_KEY")
text = "".join(f"{n}={secrets.token_urlsafe(48)}\n" for n in NAMES)
if len(sys.argv) > 1:
    fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    print(f"written: {sys.argv[1]}")
else:
    sys.stdout.write(text)
