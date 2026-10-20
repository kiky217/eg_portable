"""GitHub promotion never defaults to root or unscoped shell."""
import base64,hashlib,json,subprocess,time
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from tools.production_github_worker import GitPromotionWorker,GitPromotionDenied
from tools.high_effect_admission import action_fingerprint
from tools.signed_hitl_approval import canonical
def public(k):return base64.b64encode(k.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
def make(tmp_path):
 root=tmp_path/"source";root.mkdir()
 subprocess.run(["/usr/bin/git","init",str(root)],capture_output=True,check=True)
 owner=Ed25519PrivateKey.generate();task="task-knid-solana-test";step="06.02"
 payload={"repo":"kiky217/knid-solana","branch":"main","commit_sha":"a"*40,"expected_remote_sha":"0"*40}
 data=canonical(payload)
 action={"action_type":"github_promote","effect_class":"E4","real_world_effect":True,
         "reversible":False,"target":str(root/".git/refs/heads/main"),
         "payload_sha256":hashlib.sha256(data).hexdigest(),"payload_bytes":len(data)}
 fp=action_fingerprint(action);now=time.time()
 b={"version":1,"task_id":task,"step_key":step,"gate_checkpoint_no":42,
    "action_fingerprint":fp,"adapter_id":"trusted-adapter-github-promotion",
    "decision":"APPROVED","issued_at":now-1,"expires_at":now+100,"nonce":"sandbox-gh-promotion-00001"}
 approval={**b,"signature_b64":base64.b64encode(owner.sign(canonical(b))).decode()}
 worker=GitPromotionWorker(root=root,adapter_id=b["adapter_id"],hitl_public_key=public(owner),
    fetch_state=lambda t:{"current_step":step,"pending_execution_gate":{
        "verdict":"READY_TO_EXECUTE","hitl_approved":True,"pre_checkpoint_no":42,"action_fingerprint":fp}},
    fetch_detail=lambda t:{"task":{"contract_status":"OPEN"}})
 return worker,task,step,action,approval,payload
def test_wrong_repo_denied(tmp_path):
 w,task,step,action,ap,p=make(tmp_path);p["repo"]="someone/other"
 with pytest.raises(GitPromotionDenied,match="REPO_BRANCH"):w.validate(task_id=task,step_key=step,action=action,approval=ap,payload=p)
def test_tampered_sha_denied(tmp_path):
 w,task,step,action,ap,p=make(tmp_path);p["commit_sha"]="b"*40
 with pytest.raises(GitPromotionDenied,match="PAYLOAD_NOT_PINNED"):w.validate(task_id=task,step_key=step,action=action,approval=ap,payload=p)
def test_root_cannot_push_even_with_synthetic_approval(tmp_path):
 import os
 if os.geteuid()!=0:pytest.skip("root-only refusal test")
 w,task,step,action,ap,p=make(tmp_path)
 with pytest.raises(GitPromotionDenied,match="ROOT_EXECUTOR_FORBIDDEN"):
  w.push(task_id=task,step_key=step,action=action,approval=ap,payload=p,ledger_dir=tmp_path,private=None)
