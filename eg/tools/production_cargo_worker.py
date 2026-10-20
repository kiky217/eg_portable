"""Isolated allowlisted Cargo worker candidate. Requires live canonical EG PRE and signed HITL.
Do not expose socket or signing key to the orchestrator. No GitHub credentials."""
import hashlib,json,os,secrets,subprocess,time,base64
from pathlib import Path
from datetime import datetime
from app.execution_receipts import body,sign,verify as verify_receipt
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from tools.high_effect_admission import action_fingerprint
from tools.durable_hitl_ledger import ApprovalLedger
from tools.signed_hitl_approval import verify_approval
class WorkerDenied(RuntimeError):pass
ALLOW={
 "cargo_check":("cargo","check","--workspace","--locked","--offline"),
 "cargo_test":("cargo","test","--workspace","--locked","--offline"),
 "cargo_fmt_check":("cargo","fmt","--all","--","--check"),
}
class CargoWorker:
 def __init__(self,*,root,journal,private,adapter_id,hitl_public_key,fetch_state,fetch_detail):
  self.root=Path(root).resolve(strict=True)
  self.journal=Path(journal).resolve(strict=True)
  if self.root.is_symlink() or self.journal.is_symlink():raise WorkerDenied("SYMLINK_ROOT")
  if os.stat(self.journal).st_mode & 0o077:raise WorkerDenied("JOURNAL_NOT_PRIVATE")
  self.ledger=ApprovalLedger(self.journal)
  self.private=private;self.adapter_id=adapter_id;self.hitl_key=hitl_public_key
  self.state=fetch_state;self.detail=fetch_detail
  if not adapter_id.startswith("trusted-adapter-"):raise WorkerDenied("INVALID_ADAPTER_ID")
 def validate(self,*,task_id,step_key,action,approval):
  if (not isinstance(action,dict) or action.get("action_type") not in ALLOW
      or action.get("effect_class")!="E3" or action.get("real_world_effect") is not True
      or action.get("target")!=str(self.root/"Cargo.toml")):
   raise WorkerDenied("ACTION_SCOPE_DENIED")
  if (self.root/"Cargo.toml").is_symlink() or not (self.root/"Cargo.toml").is_file():raise WorkerDenied("CARGO_MANIFEST_MISSING")
  if not isinstance(task_id,str) or not task_id.startswith("task-knid-solana-"):
   raise WorkerDenied("TASK_SCOPE_DENIED")
  if not isinstance(step_key,str):raise WorkerDenied("STEP_SCOPE_DENIED")
  state=self.state(task_id);detail=self.detail(task_id)
  gate=state.get("pending_execution_gate")
  fp=action_fingerprint(action)
  if (state.get("current_step")!=step_key or not gate
      or gate.get("verdict")!="READY_TO_EXECUTE"
      or gate.get("action_fingerprint")!=fp
      or not gate.get("hitl_approved")
      or detail.get("task",{}).get("contract_status")!="OPEN"):
   raise WorkerDenied("LIVE_EG_PRE_REQUIRED")
  cp=gate.get("pre_checkpoint_no")
  if type(cp) is not int:raise WorkerDenied("PRE_CHECKPOINT_INVALID")
  verify_approval(approval,self.hitl_key,task_id=task_id,step_key=step_key,
                  gate_checkpoint_no=cp,action_fingerprint=fp,adapter_id=self.adapter_id)
  canonical=json.dumps({"operation":action["action_type"],"manifest":str(self.root/"Cargo.toml")},
                       sort_keys=True,separators=(",",":")).encode()
  if (action.get("payload_sha256")!=hashlib.sha256(canonical).hexdigest()
      or action.get("payload_bytes")!=len(canonical)):
   raise WorkerDenied("PAYLOAD_COMMAND_SCOPE_MISMATCH")
  created=gate.get("created_at")
  try:elapsed=time.time()-datetime.fromisoformat(created).timestamp()
  except (TypeError,ValueError,OverflowError) as e:raise WorkerDenied("INVALID_PRE_TIME") from e
  if not 0<=elapsed<=300:raise WorkerDenied("PRE_EXPIRED")
  return cp,fp,approval["nonce"]
 def execute(self,*,task_id,step_key,action,approval):
  cp,fp,nonce=self.validate(task_id=task_id,step_key=step_key,action=action,approval=approval)
  journal=self.journal/(hashlib.sha256((task_id+step_key+str(cp)+fp).encode()).hexdigest()+".json")
  receipt_file=self.journal/(journal.stem+".receipt.json")
  if journal.exists():
   if receipt_file.is_file() and not receipt_file.is_symlink():
    saved=json.loads(receipt_file.read_text())
    if (saved.get("task_id")==task_id and saved.get("step_key")==step_key
        and saved.get("gate_checkpoint_no")==cp and saved.get("action_fingerprint")==fp
        and saved.get("target")==action["target"] and saved.get("nonce")==nonce):
     gate=self.state(task_id).get("pending_execution_gate")
     if not gate:raise WorkerDenied("REPLAY_GATE_NOT_CURRENT")
     key_b64=base64.b64encode(self.private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
     valid,_=verify_receipt(saved,public_b64=key_b64,task_id=task_id,step_key=step_key,
                            gate_checkpoint_no=cp,action_fingerprint=fp,
                            target=action["target"],gate_created_at=gate.get("created_at"))
     if not valid:raise WorkerDenied("REPLAY_RECEIPT_SIGNATURE_INVALID")
     return saved
   raise WorkerDenied("UNKNOWN_EFFECT_NO_RETRY")
  rustup=os.environ.get("CARGO_ADAPTER_RUSTUP_HOME")
  cargo=os.environ.get("CARGO_ADAPTER_CARGO_HOME")
  target_dir=os.environ.get("CARGO_ADAPTER_TARGET_DIR")
  if (not rustup or not cargo or not Path(rustup).is_dir() or not Path(cargo).is_dir()
      or not target_dir or not Path(target_dir).is_dir() or Path(target_dir).is_symlink()
      or Path(target_dir).stat().st_uid!=os.geteuid()):
   raise WorkerDenied("ISOLATED_TOOLCHAIN_OR_TARGET_NOT_PROVISIONED")
  scope=dict(task_id=task_id,step_key=step_key,gate_checkpoint_no=cp,
             action_fingerprint=fp,adapter_id=self.adapter_id)
  self.ledger.consume(approval,self.hitl_key,**scope)
  # Claim before actual execution; an uncertain effect is never repeated.
  fd=os.open(journal,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
  intent=json.dumps({"task_id":task_id,"step_key":step_key,"cp":cp,"fp":fp,"status":"INTENT_DURABLE"})
  with os.fdopen(fd,"w") as stream:stream.write(intent);stream.flush();os.fsync(stream.fileno())
  env={"HOME":"/nonexistent","PATH":str(Path(cargo)/"bin")+":/usr/bin:/bin",
       "RUSTUP_HOME":rustup,"CARGO_HOME":cargo,"RUSTUP_TOOLCHAIN":"stable",
       "CARGO_NET_OFFLINE":"true","CARGO_TERM_COLOR":"never","CARGO_TARGET_DIR":target_dir}
  try:
   result=subprocess.run(ALLOW[action["action_type"]],cwd=self.root,env=env,
                         capture_output=True,timeout=180,text=False,stdin=subprocess.DEVNULL)
  except BaseException:raise WorkerDenied("UNKNOWN_EFFECT_NO_RETRY")
  if result.returncode!=0:raise WorkerDenied("EXECUTION_FAILED_NO_RETRY")
  evidence=(b"exit=0\n"+result.stdout+result.stderr)[:2_000_000]
  if not evidence:raise WorkerDenied("OUTPUT_MISSING")
  receipt=sign(body(task_id,step_key,cp,fp,
                    "trusted-worker-"+self.adapter_id,action["target"],evidence,nonce),self.private)
  fd=os.open(receipt_file,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,"w") as f:
   json.dump(receipt,f,sort_keys=True,separators=(",",":"));f.flush();os.fsync(f.fileno())
  dirfd=os.open(self.journal,os.O_DIRECTORY|os.O_RDONLY|os.O_NOFOLLOW)
  try:os.fsync(dirfd)
  finally:os.close(dirfd)
  return self.ledger.seal_receipt(nonce,receipt,**scope)
