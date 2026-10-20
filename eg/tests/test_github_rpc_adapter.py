"""Canonical E4 Github typed RPC integrates worker and EG original PRE."""
import base64,hashlib,time
from datetime import datetime,timezone
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from tools.github_rpc_adapter import GitHubRpcAdapter,wire_bytes,GithubRpcWireDenied
from tools.trusted_github_effect import TrustedGitHubEffect,GitHubWorkerDenied
from tools.high_effect_admission import action_fingerprint
from tools.signed_hitl_approval import canonical
from tools import trusted_generic_rpc as rpc
from app.execution_receipts import verify as verify_receipt
from test_nested_json_schema import SCHEMA as INPUT_SCHEMA
from tools.nested_json_schema import validate_schema_v2

def pub(k):
    return base64.b64encode(k.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()

def test_github_rpc_wire_original_pre_to_signed_effect_no_replay(tmp_path,monkeypatch):
    executor,human=Ed25519PrivateKey.generate(),Ed25519PrivateKey.generate()
    policy={"repository":"example/project","branch_prefix":"agent/",
            "path_prefix":"src","actions":["create_file","update_file"]}
    operation={"repository":"example/project","operation":"create_file",
              "branch":"agent/acceptance","path":"src/test.json","expected_blob_sha":""}
    content=b'{"hello":"world"}'
    wire=wire_bytes(operation=operation,content=content,commit_message="EG governed test")
    calls=[]
    def write(*args,**kwargs):
        calls.append("write")
        return {"commit_sha":"a"*40,"blob_sha":"b"*40}
    def readback(*args,**kwargs):
        calls.append("readback")
        return {"status":"CONTENT_VERIFIED_NOT_EXECUTION_PROOF",
                "commit_sha":"a"*40,"blob_sha256":hashlib.sha256(content).hexdigest()}
    journal=tmp_path/"journal";journal.mkdir(mode=0o700)
    output_schema={"schema_version":2,"schema_id":"github/receipt-v1",
        "document":{"type":"object","additional_properties":False,
        "required":["commit_sha","blob_sha","content_sha256"],
        "properties":{name:{"type":"string","minimum":40 if name!="content_sha256" else 64,
                             "maximum":40 if name!="content_sha256" else 64}
                      for name in ("commit_sha","blob_sha","content_sha256")}}}
    underlying=TrustedGitHubEffect(journal_dir=journal,private_key=executor,
            adapter_id="trusted-adapter-github-e4-acceptance",
            hitl_public_key_b64=pub(human),policy=policy,github_token="fixture",
            readback=readback,write=write,
            input_schema=INPUT_SCHEMA,input_schema_sha256=validate_schema_v2(INPUT_SCHEMA),
            output_schema=output_schema,output_schema_sha256=validate_schema_v2(output_schema))
    adapter=GitHubRpcAdapter(underlying)
    task,step,cp="task-github-e4-test","01.01",8
    action={"action_type":"github_contents_write","effect_class":"E4",
            "target":"/github/example/project/src/test.json",
            "real_world_effect":True,"reversible":False,
            "payload_sha256":hashlib.sha256(wire).hexdigest(),
            "payload_bytes":len(wire)}
    fp=action_fingerprint(action)
    nonce="independent_hitl_nonce_e4_1234"
    now=int(time.time())
    approved={"version":1,"task_id":task,"step_key":step,"gate_checkpoint_no":cp,
              "action_fingerprint":fp,"adapter_id":adapter.adapter_id,
              "decision":"APPROVED","issued_at":now-1,"expires_at":now+120,"nonce":nonce}
    approval={**approved,"signature_b64":base64.b64encode(human.sign(canonical(approved))).decode()}
    gate={"task_id":task,"step_key":step,"checkpoint_no":cp,"verdict":"READY_TO_EXECUTE",
          "action_fingerprint":fp,"hitl_approved":True,
          "high_effect_pin":{"adapter_id":adapter.adapter_id,"public_key_b64":pub(executor),
                 "action_fingerprint":fp,"approval_nonce":nonce}}
    created=datetime.now(timezone.utc).isoformat()
    state={"status":"IN_PROGRESS","current_step":step,
           "pending_execution_gate":gate,
           "latest_checkpoint":{"checkpoint_no":cp,"verdict":"READY_TO_EXECUTE"}}
    detail={"task":{"contract_status":"OPEN"},
            "checkpoints":[{"checkpoint_no":cp,"created_at":created,"verdict":"READY_TO_EXECUTE"}]}
    monkeypatch.setattr(rpc,"_get",lambda url,key,task,suffix:state if suffix=="/state" else detail)
    request={"task_id":task,"step_key":step,"action":action,"approval":approval,
             "data_b64":base64.b64encode(wire).decode(),"operation":"execute"}
    result=rpc.dispatch_once(request,adapter=adapter,eg_url="http://127.0.0.1:9999",
                             eg_key="fixture",hitl_public_key_b64=pub(human))
    ok,reason=verify_receipt(result["receipt"],public_b64=pub(executor),
         task_id=task,step_key=step,gate_checkpoint_no=cp,
         action_fingerprint=fp,target=action["target"],gate_created_at=created)
    assert ok,reason
    assert calls==["write","readback"]
    with pytest.raises(GitHubWorkerDenied,match="NO_REPLAY"):
        rpc.dispatch_once(request,adapter=adapter,eg_url="http://127.0.0.1:9999",
                          eg_key="fixture",hitl_public_key_b64=pub(human))
    assert calls==["write","readback"]
    recovery={**request,"operation":"recover_receipt","data_b64":""}
    result2=rpc.dispatch_once(recovery,adapter=adapter,eg_url="http://127.0.0.1:9999",
                             eg_key="fixture",hitl_public_key_b64=pub(human))
    assert result2["receipt"]==result["receipt"]
    assert calls==["write","readback"]

def test_noncanonical_or_duplicate_github_payload_denied(tmp_path):
    worker=TrustedGitHubEffect(journal_dir=tmp_path,private_key=Ed25519PrivateKey.generate(),
           adapter_id="trusted-adapter-github-e4-invalid",
           hitl_public_key_b64=pub(Ed25519PrivateKey.generate()),
           policy={"repository":"example/project","branch_prefix":"agent/",
                   "path_prefix":"src","actions":["create_file"]},github_token="fixture")
    adapter=GitHubRpcAdapter(worker)
    for invalid in [b'{"version":1,"version":1}',
                    b'{"version":1,"operation":{},"content_b64":"","commit_message":"x"}',
                    b'{"version":1,"operation":{},"content_b64":"eA==","commit_message":""}',
                    b'{"version":1,"operation":{},"content_b64":"eA==","commit_message":42}',
                    b'{"version":1,"operation":{},"content_b64":"eA==","commit_message":"line\\nnewline"}',
                    b'{"version":1,"operation":{},"content_b64":"%%%","commit_message":"x"}']:
        with pytest.raises(GithubRpcWireDenied):
            adapter.execute(task_id="task",step_key="01.01",action={},
                 approval={},gate={},gate_created_at="",stdin=invalid)
