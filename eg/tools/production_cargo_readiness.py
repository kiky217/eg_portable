"""Readiness is checked without revealing secrets and without enabling production."""
import json,os,stat
from pathlib import Path
from tools.high_effect_admission import AdapterCapability
def inspect_readiness(*,worker_home,workspace,capability,owner_hitl_public_key):
 home=Path(worker_home)
 root=Path(workspace)
 issues=[]
 if not root.is_dir() or not (root/"Cargo.toml").is_file():
  issues.append("WORKSPACE_ABSENT")
 if not home.is_dir() or home.is_symlink() or stat.S_IMODE(home.stat().st_mode)&0o077:
  issues.append("WORKER_HOME_NOT_PRIVATE")
 try:
  cap=AdapterCapability(**json.loads(Path(capability).read_text()))
  cap.validate(allow_production=True)
  if cap.ci_only or cap.effect_class!="E3":issues.append("CAPABILITY_INVALID")
 except (ValueError,TypeError,KeyError,OSError):
  issues.append("CAPABILITY_UNVERIFIED")
 if not owner_hitl_public_key:
  issues.append("INDEPENDENT_OWNER_HITL_NOT_PROVISIONED")
 return {"status":"READY_FOR_CANONICAL_PRE" if not issues else "FAIL_CLOSED",
         "issues":issues,"worker_uid":home.stat().st_uid if home.exists() else None}
