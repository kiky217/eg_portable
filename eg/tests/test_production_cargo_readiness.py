from tools.production_cargo_readiness import inspect_readiness
from pathlib import Path
import json
def test_missing_owner_hitl_refuses_ready(tmp_path):
 root=tmp_path/"workspace";root.mkdir();(root/"Cargo.toml").write_text("[package]")
 home=tmp_path/"worker";home.mkdir(mode=0o700)
 cap=tmp_path/"cap.json";cap.write_text(json.dumps({"ci_only":True}))
 result=inspect_readiness(worker_home=home,workspace=root,capability=cap,owner_hitl_public_key="")
 assert result["status"]=="FAIL_CLOSED"
 assert "INDEPENDENT_OWNER_HITL_NOT_PROVISIONED" in result["issues"]
def test_missing_source_refuses_ready(tmp_path):
 home=tmp_path/"worker";home.mkdir(mode=0o700)
 cap=tmp_path/"cap.json";cap.write_text("{}")
 r=inspect_readiness(worker_home=home,workspace=tmp_path/"missing",capability=cap,owner_hitl_public_key="")
 assert "WORKSPACE_ABSENT" in r["issues"]
