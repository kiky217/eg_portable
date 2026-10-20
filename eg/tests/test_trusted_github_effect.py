import base64,hashlib,json,time
from datetime import datetime,timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from tools.high_effect_admission import action_fingerprint
from tools.signed_hitl_approval import canonical
from tools.trusted_github_effect import TrustedGitHubEffect,GitHubWorkerDenied

def pub(k):
    return base64.b64encode(k.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()

def test_trusted_github_write_bound_pre_and_no_replay(tmp_path):
    worker,human=Ed25519PrivateKey.generate(),Ed25519PrivateKey.generate()
    policy={"repository":"example/project","branch_prefix":"agent/","path_prefix":"src","actions":["create_file"]}
    op={"repository":"example/project","operation":"create_file","branch":"agent/test",
        "path":"src/a.py","expected_blob_sha":""}
    content=b"print('ok')"
    args={"operation":op,"commit_message":"governed create",
          "content_sha256":hashlib.sha256(content).hexdigest()}
    payload=json.dumps(args,sort_keys=True,separators=(",",":")).encode()
    action={"action_type":"github_contents_write","target":"/github/example/project/src/a.py",
            "effect_class":"E4","real_world_effect":True,"reversible":False,
            "payload_bytes":len(payload),"payload_sha256":hashlib.sha256(payload).hexdigest()}
    fp=action_fingerprint(action);nonce="approved_test_nonce_123456"
    now=time.time(); cp=7
    envelope={"version":1,"task_id":"task-demo","step_key":"01.01",
              "gate_checkpoint_no":cp,"action_fingerprint":fp,
              "adapter_id":"trusted-adapter-github-demo","decision":"APPROVED",
              "issued_at":int(now)-1,"expires_at":int(now)+100,"nonce":nonce}
    approval={**envelope,"signature_b64":base64.b64encode(human.sign(canonical(envelope))).decode()}
    gate={"task_id":"task-demo","step_key":"01.01","verdict":"READY_TO_EXECUTE",
          "hitl_approved":True,"action_fingerprint":fp,"checkpoint_no":cp,
          "high_effect_pin":{"adapter_id":"trusted-adapter-github-demo",
                             "public_key_b64":pub(worker),"approval_nonce":nonce}}
    calls=[]
    def write(*a,**kw):
        calls.append("write")
        return {"commit_sha":"a"*40,"blob_sha":"b"*40}
    def readback(*a,**kw):
        calls.append("readback")
        return {"status":"CONTENT_VERIFIED_NOT_EXECUTION_PROOF",
                "blob_sha256":hashlib.sha256(content).hexdigest()}
    journal=tmp_path/"journal";journal.mkdir(mode=0o700)
    w=TrustedGitHubEffect(journal_dir=journal,private_key=worker,
         adapter_id="trusted-adapter-github-demo",hitl_public_key_b64=pub(human),
         policy=policy,github_token="fixture",write=write,readback=readback)
    kwargs=dict(task_id="task-demo",step_key="01.01",action=action,approval=approval,
                gate=gate,gate_created_at=datetime.now(timezone.utc).isoformat(),
                operation=op,content=content,commit_message="governed create")
    result=w.execute(**kwargs)
    assert result["status"]=="EXECUTED_POST_NOT_VERIFIED"
    assert result["receipt"]["executor_id"]=="trusted-worker-trusted-adapter-github-demo"
    assert calls==["write","readback"]
    try:w.execute(**kwargs)
    except GitHubWorkerDenied as exc:assert "NO_REPLAY" in str(exc)
    else:raise AssertionError("duplicate effect was allowed")
    assert calls==["write","readback"]

def test_mismatched_pre_denies_without_journal_claim(tmp_path):
    worker,human=Ed25519PrivateKey.generate(),Ed25519PrivateKey.generate()
    journal=tmp_path/"journal";journal.mkdir(mode=0o700)
    w=TrustedGitHubEffect(journal_dir=journal,private_key=worker,
          adapter_id="trusted-adapter-test",hitl_public_key_b64=pub(human),
          policy={"repository":"a/b","branch_prefix":"agent/","path_prefix":"src","actions":["create_file"]},
          github_token="fixture")
    try:w.execute(task_id="demo",step_key="01",action={},approval={},gate={},
                  gate_created_at="",operation={"operation":"create_file",
                  "repository":"a/b","branch":"agent/x","path":"src/a","expected_blob_sha":""},
                  content=b"x",commit_message="x")
    except GitHubWorkerDenied:pass
    else:raise AssertionError("missing PRE allowed")
