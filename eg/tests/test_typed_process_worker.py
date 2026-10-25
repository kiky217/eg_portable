"""Schema-pinned signed worker only attests bounded typed physical output."""
import base64,hashlib,time
from datetime import datetime,timezone
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from tools.trusted_process_effect import TrustedProcessEffect,ProcessDenied
from tools.durable_hitl_ledger import ApprovalLedger
from tools.typed_payload_contract import canonical
from tools.signed_hitl_approval import canonical as hitl_canonical
from tools.high_effect_admission import action_fingerprint

SCHEMA={"schema_version":1,"schema_id":"generic/message-v1",
        "required":["message"],"additional_properties":False,
        "properties":{"message":{"type":"string","minimum":1,"maximum":80}}}

def pub(k):
    return base64.b64encode(k.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()

def setup(tmp_path):
    priv,human=Ed25519PrivateKey.generate(),Ed25519PrivateKey.generate()
    root=tmp_path/"ledger";root.mkdir(mode=0o700)
    w=object.__new__(TrustedProcessEffect)
    w.ledger=ApprovalLedger(root);w.private=priv;w.adapter_id="trusted-adapter-typed"
    w.effect_class="E3";w.action_type="bounded_process_run"
    w.hitl_key_b64=pub(human);w.executable="/operator/pinned"
    w.fixed_args=();w.target="/tasks/typed/test"
    w.timeout=3;w.max_stdout=2048
    w.input_schema=SCHEMA;w.output_schema=SCHEMA
    w.input_schema_sha256=hashlib.sha256(canonical(SCHEMA)).hexdigest()
    w.output_schema_sha256=w.input_schema_sha256
    content=canonical({"message":"bounded"})
    action={"action_type":"bounded_process_run","effect_class":"E3",
         "target":w.target,"real_world_effect":True,"reversible":False,
         "payload_sha256":hashlib.sha256(content).hexdigest(),
         "payload_bytes":len(content)}
    fp=action_fingerprint(action);now=int(time.time());nonce="typed_approval_nonce_123"
    doc={"version":1,"task_id":"task-typed","step_key":"01.01","gate_checkpoint_no":3,
         "action_fingerprint":fp,"adapter_id":w.adapter_id,"decision":"APPROVED",
         "issued_at":now-1,"expires_at":now+120,"nonce":nonce}
    approval={**doc,"signature_b64":base64.b64encode(human.sign(hitl_canonical(doc))).decode()}
    gate={"task_id":"task-typed","step_key":"01.01","verdict":"READY_TO_EXECUTE",
        "checkpoint_no":3,"hitl_approved":True,"action_fingerprint":fp,
        "high_effect_pin":{"adapter_id":w.adapter_id,"public_key_b64":pub(priv),
                "action_fingerprint":fp,"approval_nonce":nonce}}
    args=dict(task_id="task-typed",step_key="01.01",action=action,approval=approval,
              gate=gate,gate_created_at=datetime.now(timezone.utc).isoformat(),stdin=content)
    return w,args

def test_typed_output_is_signed_only_when_valid(tmp_path,monkeypatch):
    worker,args=setup(tmp_path)
    class Result:returncode=0;stdout=args["stdin"];stderr=b""
    calls=[]
    def run(*a,**kw):calls.append("executed");return Result()
    monkeypatch.setattr("tools.trusted_process_effect._bounded_process",run)
    proof=worker.execute(**args)
    assert proof["status"]=="EXECUTED_POST_NOT_VERIFIED"
    assert proof["receipt"]["output_sha256"]==hashlib.sha256(Result.stdout).hexdigest()
    with pytest.raises(ProcessDenied,match="NO_REPLAY"):worker.execute(**args)
    assert calls==["executed"]

def test_invalid_output_never_receives_valid_receipt(tmp_path,monkeypatch):
    worker,args=setup(tmp_path)
    class Result:returncode=0;stdout=b'{"unexpected":true}';stderr=b""
    calls=[]
    def run(*a,**kw):calls.append("executed");return Result()
    monkeypatch.setattr("tools.trusted_process_effect._bounded_process",run)
    with pytest.raises(ProcessDenied,match="OUTPUT_SCHEMA_DENIED_UNKNOWN_NO_REPLAY"):
        worker.execute(**args)
    with pytest.raises(ProcessDenied,match="NO_REPLAY"):worker.execute(**args)
    assert calls==["executed"]

def test_bad_input_denied_before_consuming_approval(tmp_path,monkeypatch):
    worker,args=setup(tmp_path)
    args["stdin"]=b'{"wrong":1}'
    args["action"]={**args["action"],"payload_sha256":hashlib.sha256(args["stdin"]).hexdigest(),
                    "payload_bytes":len(args["stdin"])}
    from tools.high_effect_admission import action_fingerprint
    # Even with tampered payload hash, original PRE signer must not authorize effect.
    with pytest.raises(ProcessDenied):
        worker.execute(**args)



def test_process_worker_rejects_replaceable_executable_ancestors(tmp_path):
    binary=tmp_path/'pinned'
    binary.write_text('#!/bin/sh\necho PASS\n')
    binary.chmod(0o700)
    journal=tmp_path/'effects';journal.mkdir(mode=0o700)
    signer,approval=Ed25519PrivateKey.generate(),Ed25519PrivateKey.generate()
    args=dict(journal_dir=journal,private_key=signer,
        adapter_id='trusted-adapter-test-executable',hitl_key_b64=pub(approval),
        fixed_args=(),target='/tasks/verify/cmd',
        effect_class='E3',action_type='bounded_process_run')
    # A root-owned binary under /tmp is still replaceable through /tmp.
    with pytest.raises(ProcessDenied,match='UNSAFE_EXECUTABLE_PATH'):
        TrustedProcessEffect(executable=str(binary),**args)
    # A package-manager-owned immutable system path remains admissible.
    safe=TrustedProcessEffect(executable='/usr/bin/cat',**args)
    assert safe.executable=='/usr/bin/cat'

def test_no_effect_retirement_is_signed_and_prevents_late_execution(tmp_path,monkeypatch):
    from app.no_effect_receipts import verify_no_effect
    worker,args=setup(tmp_path)
    scope=dict(task_id=args["task_id"],step_key=args["step_key"],
               gate_checkpoint_no=args["gate"]["checkpoint_no"],
               action_fingerprint=action_fingerprint(args["action"]),
               adapter_id=worker.adapter_id)
    proof=worker.reconcile_no_effect(task_id=args["task_id"],step_key=args["step_key"],
        action=args["action"],approval=args["approval"],gate=args["gate"])
    assert verify_no_effect(proof,public_b64=pub(worker.private),
        target=args["action"]["target"],gate_created_at=args["gate_created_at"],
        **{k:v for k,v in scope.items() if k!="adapter_id"})
    assert worker.ledger.claim_status(args["approval"]["nonce"],**scope) is None
    # The original nonce is durably retired, even across future execute retries.
    class Result:returncode=0;stdout=args["stdin"];stderr=b""
    calls=[]
    monkeypatch.setattr("tools.trusted_process_effect._bounded_process",
        lambda *a,**kw: calls.append("executed") or Result())
    with pytest.raises(Exception,match="RETIRED_NO_EFFECT"):
        worker.execute(**args)
    assert calls==[]
