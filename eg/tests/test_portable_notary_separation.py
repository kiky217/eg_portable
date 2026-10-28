"""Issue #21: generated portable init/start never mint or expose notary private keys."""
import ast
import base64
import os
from pathlib import Path
import subprocess
import sys

from tools import build_portable_bundle as builder


def generated_script(variable):
    source=ast.parse(Path(builder.__file__).read_text())
    for node in ast.walk(source):
        if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id==variable for t in node.targets):
            if isinstance(node.value,ast.Constant) and isinstance(node.value.value,str):
                return node.value.value
    raise AssertionError(f"generated script {variable} not found")


def test_init_rejects_missing_independent_notary_key(tmp_path):
    text=generated_script("installer")
    assert "EG_NOTARY_PUBLIC_KEY_B64" in text
    assert "Ed25519PrivateKey.generate" not in text
    assert "notary-private.pem" in text
    assert "EVALUATION_GATEWAY_EVIDENCE_PUBLIC_KEY_B64" in text


def test_generated_init_uses_external_notary_root_and_no_private_key(tmp_path):
    script=tmp_path/"init.sh"
    script.write_text(generated_script("installer"))
    script.chmod(0o755)
    runner=tmp_path/"python.sh"
    runner.write_text(f"#!/bin/sh\nexec '{sys.executable}' \"$@\"\n")
    runner.chmod(0o755)
    state=tmp_path/"state"
    first=base64.b64encode(b"a"*32).decode()
    second=base64.b64encode(b"b"*32).decode()
    env={**os.environ,"EG_STATE_DIR":str(state),"EG_EXECUTOR_PUBLIC_KEY_B64":first,"EG_NOTARY_PUBLIC_KEY_B64":second}
    result=subprocess.run([str(script)],env=env,text=True,capture_output=True)
    assert result.returncode==0,(result.stdout,result.stderr)
    assert not (state/"notary-private.pem").exists()
    runtime=(state/"runtime.env").read_text()
    assert "EVALUATION_GATEWAY_EVIDENCE_PUBLIC_KEY_B64="+second in runtime
    assert first in runtime
    assert "PRIVATE_KEY" not in runtime


def test_start_script_refuses_private_notary_key_in_state():
    script=generated_script("envrunner")
    assert 'notary-private.pem' in script
    assert 'exit 77' in script
