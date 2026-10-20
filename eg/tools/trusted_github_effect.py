"""Independently provisioned E4 GitHub effect logic, for an isolated RPC worker.

This module cannot self-provision trust. The caller must supply an independently
protected signing key, operator policy, private journal and verified live EG PRE.
"""
from __future__ import annotations
import hashlib,json,time,base64
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from datetime import datetime
from tools.github_effect_scope import validate_operation
from tools.github_bounded_transport import contents_put
from tools.github_commit_readback import verify_commit_content
from tools.durable_hitl_ledger import ApprovalLedger
from tools.high_effect_admission import action_fingerprint
from tools.signed_hitl_approval import verify_approval
from app.execution_receipts import body,sign
from tools.typed_payload_contract import validate_document,TypedPayloadDenied

class GitHubWorkerDenied(RuntimeError):pass

class TrustedGitHubEffect:
    def __init__(self,*,journal_dir,private_key,adapter_id,hitl_public_key_b64,
                 policy,github_token,readback=verify_commit_content,write=contents_put,
                 input_schema=None,input_schema_sha256=None,
                 output_schema=None,output_schema_sha256=None):
        if not isinstance(adapter_id,str) or not adapter_id.startswith("trusted-adapter-"):
            raise GitHubWorkerDenied("INVALID_ADAPTER_ID")
        if ((input_schema is None)!=(input_schema_sha256 is None)
            or (output_schema is None)!=(output_schema_sha256 is None)):
            raise GitHubWorkerDenied("UNPINNED_OPERATOR_SCHEMA")
        self.input_schema=input_schema
        self.input_schema_sha256=input_schema_sha256
        self.output_schema=output_schema
        self.output_schema_sha256=output_schema_sha256
        self.ledger=ApprovalLedger(journal_dir)
        self.private=private_key
        self.adapter_id=adapter_id
        self.hitl_key=hitl_public_key_b64
        self.policy=policy
        self.token=github_token
        self.readback=readback
        self.write=write

    def execute(self,*,task_id,step_key,action,approval,gate,gate_created_at,
                operation,content,commit_message,wire_bytes=None):
        if (not isinstance(commit_message,str) or not 1<=len(commit_message)<=180
            or "\r" in commit_message or "\n" in commit_message):
            raise GitHubWorkerDenied("INVALID_GITHUB_COMMIT_MESSAGE_NO_EFFECT")
        if not isinstance(approval,dict):
            raise GitHubWorkerDenied("SIGNED_HITL_APPROVAL_REQUIRED_NO_EFFECT")
        op=validate_operation(operation,self.policy)
        if (not isinstance(content,bytes) or not content or len(content)>512*1024
            or not isinstance(action,dict) or action.get("effect_class")!="E4"
            or action.get("action_type")!="github_contents_write"
            or action.get("real_world_effect") is not True
            or action.get("reversible") is not False
            or action.get("target")!="/github/"+op["repository"]+"/"+op["path"]):
            raise GitHubWorkerDenied("GITHUB_ACTION_SCOPE_DENIED")
        canonical=json.dumps({"operation":op,"commit_message":commit_message,
                              "content_sha256":hashlib.sha256(content).hexdigest()},
                              sort_keys=True,separators=(",",":")).encode()
        effective_wire=canonical if wire_bytes is None else wire_bytes
        if (not isinstance(effective_wire,bytes) or not effective_wire or len(effective_wire)>524288
            or action.get("payload_sha256")!=hashlib.sha256(effective_wire).hexdigest()
            or action.get("payload_bytes")!=len(effective_wire)):
            raise GitHubWorkerDenied("GITHUB_EFFECT_PAYLOAD_NOT_BOUND")
        if self.input_schema is not None:
            try:
                validate_document(self.input_schema,effective_wire,
                    expected_schema_sha256=self.input_schema_sha256,max_bytes=524288)
            except (TypedPayloadDenied,ValueError) as exc:
                raise GitHubWorkerDenied("INPUT_SCHEMA_DENIED_NO_EFFECT") from exc
        fp=action_fingerprint(action)
        if (not isinstance(gate,dict) or gate.get("task_id")!=task_id
            or gate.get("step_key")!=step_key or gate.get("verdict")!="READY_TO_EXECUTE"
            or not gate.get("hitl_approved") or gate.get("action_fingerprint")!=fp
            or not isinstance(gate.get("high_effect_pin"),dict)
            or gate["high_effect_pin"].get("adapter_id")!=self.adapter_id
            or gate["high_effect_pin"].get("public_key_b64")!=base64.b64encode(
                self.private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
            or gate["high_effect_pin"].get("approval_nonce")!=approval.get("nonce")):
            raise GitHubWorkerDenied("ORIGINAL_CANONICAL_PRE_REQUIRED")
        cp=gate.get("checkpoint_no")
        if type(cp) is not int or cp<=0:
            raise GitHubWorkerDenied("INVALID_PRE_CHECKPOINT")
        try:
            epoch=datetime.fromisoformat(gate_created_at).timestamp()
        except (ValueError,TypeError,OverflowError) as exc:
            raise GitHubWorkerDenied("INVALID_GATE_TIME") from exc
        now=time.time()
        if not epoch-30<=now<=epoch+300:
            raise GitHubWorkerDenied("PRE_EXPIRED")
        verify_approval(approval,self.hitl_key,task_id=task_id,step_key=step_key,
                        gate_checkpoint_no=cp,action_fingerprint=fp,
                        adapter_id=self.adapter_id,now=now)
        nonce=approval["nonce"]
        scope=dict(task_id=task_id,step_key=step_key,gate_checkpoint_no=cp,
                   action_fingerprint=fp,adapter_id=self.adapter_id)
        if self.ledger.claim_status(nonce,**scope) is not None:
            # Cannot link any observed matching commit to our claimed write after
            # an ambiguous API response. No replay and no retrospective receipt.
            raise GitHubWorkerDenied("CLAIMED_EFFECT_UNKNOWN_NO_REPLAY")
        self.ledger.consume(approval,self.hitl_key,now=now,**scope)
        ack=self.write(op,self.policy,content,token=self.token,commit_message=commit_message)
        proof=self.readback(op,self.policy,commit_sha=ack["commit_sha"],
                            expected_bytes=content,token=self.token)
        if (proof.get("status")!="CONTENT_VERIFIED_NOT_EXECUTION_PROOF"
            or proof.get("commit_sha")!=ack["commit_sha"]
            or proof.get("blob_sha256")!=hashlib.sha256(content).hexdigest()):
            raise GitHubWorkerDenied("IMMUTABLE_READBACK_CONTENT_OR_COMMIT_MISMATCH")
        output=json.dumps({"commit_sha":ack["commit_sha"],"blob_sha":ack["blob_sha"],
                           "content_sha256":proof["blob_sha256"]},
                           sort_keys=True,separators=(",",":")).encode()
        if self.output_schema is not None:
            try:
                validate_document(self.output_schema,output,
                    expected_schema_sha256=self.output_schema_sha256,max_bytes=524288)
            except (TypedPayloadDenied,ValueError) as exc:
                # Remote effect may already have committed. Never sign an invalid
                # result or replay the original once-only HITL grant.
                raise GitHubWorkerDenied("OUTPUT_SCHEMA_DENIED_UNKNOWN_NO_REPLAY") from exc
        receipt=sign(body(task_id,step_key,cp,fp,"trusted-worker-"+self.adapter_id,
                          action["target"],output,nonce,
                          completed_ns=max(time.time_ns(),int(epoch*1e9))),self.private)
        self.ledger.record_executed_effect(action["target"],task_id=task_id,
               gate_checkpoint_no=cp,action_fingerprint=fp,adapter_id=self.adapter_id,
               digest=hashlib.sha256(output).hexdigest())
        return {"status":"EXECUTED_POST_NOT_VERIFIED","receipt":self.ledger.seal_receipt(
            nonce,receipt,**scope),"commit_sha":ack["commit_sha"]}
