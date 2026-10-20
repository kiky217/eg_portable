"""Strict GitHub promotion candidate. Validates repository/branch/commit and requires EG approval.
No network push without separately provisioned noninteractive GitHub credentials."""
import hashlib,json,re,subprocess,os,stat
from pathlib import Path
from tools.high_effect_admission import action_fingerprint
from tools.signed_hitl_approval import verify_approval
from tools.durable_hitl_ledger import ApprovalLedger
from app.execution_receipts import sign,body
HEX40=re.compile(r"^[0-9a-f]{40}$")
class GitPromotionDenied(RuntimeError):pass
class GitPromotionWorker:
 def __init__(self,*,root,adapter_id,hitl_public_key,fetch_state,fetch_detail):
  self.root=Path(root).resolve(strict=True)
  self.adapter_id=adapter_id;self.key=hitl_public_key
  self.state=fetch_state;self.detail=fetch_detail
  if self.root.is_symlink() or not adapter_id.startswith("trusted-adapter-"):
   raise GitPromotionDenied("INVALID_ROOT_OR_ID")
 def validate(self,*,task_id,step_key,action,approval,payload):
  if (not isinstance(action,dict) or action.get("action_type")!="github_promote"
      or action.get("effect_class")!="E4" or action.get("real_world_effect") is not True
      or action.get("reversible") is not False
      or action.get("target")!=str(self.root/".git"/"refs"/"heads"/"main")):
   raise GitPromotionDenied("GITHUB_EFFECT_SCOPE_DENIED")
  if not isinstance(payload,dict) or set(payload)!={"repo","branch","commit_sha","expected_remote_sha"}:
   raise GitPromotionDenied("INVALID_PROMOTION_PAYLOAD")
  if (payload["repo"]!="kiky217/knid-solana" or payload["branch"]!="main"
      or not isinstance(payload["commit_sha"],str)
      or not HEX40.fullmatch(payload["commit_sha"])
      or not isinstance(payload["expected_remote_sha"],str)
      or not HEX40.fullmatch(payload["expected_remote_sha"])):
   raise GitPromotionDenied("REPO_BRANCH_OR_SHA_DENIED")
  content=json.dumps(payload,sort_keys=True,separators=(",",":")).encode()
  if action.get("payload_bytes")!=len(content) or action.get("payload_sha256")!=hashlib.sha256(content).hexdigest():
   raise GitPromotionDenied("PROMOTION_PAYLOAD_NOT_PINNED")
  if not (self.root/".git").is_dir():raise GitPromotionDenied("GIT_REPOSITORY_NOT_INITIALIZED")
  state=self.state(task_id);detail=self.detail(task_id)
  gate=state.get("pending_execution_gate")
  fp=action_fingerprint(action)
  if (state.get("current_step")!=step_key or not gate
      or gate.get("verdict")!="READY_TO_EXECUTE"
      or not gate.get("hitl_approved") or gate.get("action_fingerprint")!=fp
      or detail.get("task",{}).get("contract_status")!="OPEN"):
   raise GitPromotionDenied("CANONICAL_EG_PRE_REQUIRED")
  cp=gate.get("pre_checkpoint_no")
  verify_approval(approval,self.key,task_id=task_id,step_key=step_key,
                  gate_checkpoint_no=cp,action_fingerprint=fp,adapter_id=self.adapter_id)
  return cp,fp
 def push(self,*,task_id,step_key,action,approval,payload,ledger_dir,private):
  cp,fp=self.validate(task_id=task_id,step_key=step_key,action=action,approval=approval,payload=payload)
  # GitHub credentials must be provisioned to a distinct non-root worker.
  if os.geteuid()==0:raise GitPromotionDenied("ROOT_EXECUTOR_FORBIDDEN")
  helper=os.getenv("GITHUB_PROMOTION_ASKPASS")
  if not helper or not os.path.isabs(helper) or os.path.islink(helper):
   raise GitPromotionDenied("SEPARATE_GITHUB_CREDENTIAL_NOT_PROVISIONED")
  st=os.stat(helper)
  if st.st_uid!=os.geteuid() or st.st_mode&0o077 or not st.st_mode&stat.S_IXUSR:
   raise GitPromotionDenied("GITHUB_CREDENTIAL_HELPER_UNTRUSTED")
  env={"HOME":"/nonexistent","PATH":"/usr/bin:/bin","GIT_CONFIG_NOSYSTEM":"1",
       "GIT_TERMINAL_PROMPT":"0","GIT_ASKPASS":helper}
  fixed_remote="https://github.com/kiky217/knid-solana.git"
  def git(*args):
   r=subprocess.run(["/usr/bin/git","-c","credential.helper=",*args],
                    cwd=self.root,env=env,text=True,capture_output=True,
                    timeout=90,stdin=subprocess.DEVNULL)
   if r.returncode!=0:raise GitPromotionDenied("GIT_OPERATION_FAILED_NO_RETRY")
   return r.stdout.strip()
  local=git("rev-parse","HEAD")
  if local!=payload["commit_sha"]:raise GitPromotionDenied("LOCAL_COMMIT_HASH_MISMATCH")
  if git("rev-parse","--abbrev-ref","HEAD")!="main":raise GitPromotionDenied("WRONG_GIT_BRANCH")
  remote=git("ls-remote",fixed_remote,"refs/heads/main")
  observed=(remote.split()[0] if remote else "0"*40)
  if observed!=payload["expected_remote_sha"]:
   raise GitPromotionDenied("REMOTE_BASELINE_CHANGED")
  ledger=ApprovalLedger(ledger_dir)
  scope=dict(task_id=task_id,step_key=step_key,gate_checkpoint_no=cp,
             action_fingerprint=fp,adapter_id=self.adapter_id)
  ledger.consume(approval,self.key,**scope)
  # Exactly one non-force promotion; failures remain UNKNOWN without automatic replay.
  git("push","--porcelain",fixed_remote,payload["commit_sha"]+":refs/heads/main")
  readback=git("ls-remote",fixed_remote,"refs/heads/main")
  if not readback or readback.split()[0]!=payload["commit_sha"]:
   raise GitPromotionDenied("REMOTE_READBACK_UNVERIFIED_NO_RETRY")
  evidence=("github-main-commit="+payload["commit_sha"]).encode()
  receipt=sign(body(task_id,step_key,cp,fp,"trusted-worker-"+self.adapter_id,
                    action["target"],evidence,approval["nonce"]),private)
  ledger.record_executed_effect(action["target"],task_id=task_id,
                  gate_checkpoint_no=cp,action_fingerprint=fp,
                  adapter_id=self.adapter_id,digest=hashlib.sha256(evidence).hexdigest())
  return ledger.seal_receipt(approval["nonce"],receipt,**scope)
