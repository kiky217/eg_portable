#!/usr/bin/env python3
"""Trusted, bounded E2 file writer for Evaluation Gateway.

Signer private key and output dir belong to a separate worker identity. The
caller cannot request signatures or arbitrary commands, only an EG-preapproved
exclusive file creation. Durable intent prevents duplicate effects on retry.
"""
from __future__ import annotations
import base64
import re
import hashlib
import json
import os
import secrets
import socketserver
import socket
import struct
import stat
import sys
import time
import threading
from datetime import datetime
from pathlib import Path
from tools.private_unix_socket import private_socket_lease
from urllib.request import Request
from tools.no_redirect_http import urlopen
from urllib.error import HTTPError
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PublicFormat
from app.execution_receipts import body, sign, verify
from app.executor_policy import parse_suffixes
from app.no_effect_receipts import sign_no_effect

MAX_PAYLOAD = 1024 * 1024
MAX_CONTENT = 512 * 1024
# Task lifetime can be unbounded; authorization to START NEW effects cannot.
MAX_NEW_WRITE_LEASE_SECONDS = 300
class WorkerDenied(RuntimeError): pass

def gate_allows_new_effect(created_at: str, now_ns: int | None = None) -> bool:
    timestamp_ns=int(datetime.fromisoformat(created_at).timestamp()*1_000_000_000)
    elapsed_ns=(time.time_ns() if now_ns is None else now_ns)-timestamp_ns
    return 0 <= elapsed_ns <= MAX_NEW_WRITE_LEASE_SECONDS*1_000_000_000

def canon(data):
    return json.dumps(data,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def fingerprint(action):
    return hashlib.sha256(canon(action)).hexdigest()
def store_replace(path,payload):
    """Atomic, worker-owned replacement; never expose a partial target."""
    temporary=path.parent/('.'+path.name+'.'+secrets.token_hex(12)+'.tmp')
    try:
        store_exclusive(temporary,payload)
        os.replace(temporary,path)
        fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        if temporary.exists():temporary.unlink()

def store_exclusive(path,payload):
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(payload);f.flush();os.fsync(f.fileno())
    dfd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(dfd)
    finally:os.close(dfd)
def api(url,key,task):
    headers={'X-Evaluation-Key':key}
    def request(suffix):
        with urlopen(Request(url+'/v1/tasks/'+task+suffix,headers=headers),timeout=10) as r:
            return json.loads(r.read())
    return request('/state'),request('')

class TrustedWriter:
    def __init__(self,output_root,journal_root,private_key,eg_url,api_key,executor_id,allowed_suffixes=None):
        self.allowed_suffixes = parse_suffixes(allowed_suffixes)
        self.root=Path(output_root).resolve(strict=True)
        self.journal=Path(journal_root).resolve(strict=True)
        for d in (self.root,self.journal):
            mode=stat.S_IMODE(d.stat().st_mode)
            if mode&0o077 or d.is_symlink():raise WorkerDenied('WORKER_DIRECTORY_NOT_ISOLATED')
        self.private=load_pem_private_key(Path(private_key).read_bytes(),password=None)
        self.lock=threading.RLock()
        self.url=eg_url.rstrip('/')
        self.key=api_key
        if not executor_id.startswith('trusted-worker-'):raise WorkerDenied('INVALID_WORKER_ID')
        self.executor_id=executor_id

    def bounded_target(self, raw_target):
        """Only worker-owned private pre-provisioned directories; no symlink hop."""
        target=Path(raw_target)
        try:
            relative=target.relative_to(self.root)
            if (not target.is_absolute() or not relative.parts or
                ".." in relative.parts or "." in relative.parts or
                target.suffix not in self.allowed_suffixes):
                raise ValueError("bad target")
            parent=self.root
            for component in relative.parts[:-1]:
                parent=parent/component
                info=parent.lstat()
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid()
                    or stat.S_IMODE(info.st_mode)&0o077):
                    raise ValueError("unsafe private directory")
            if target.is_symlink() or target.resolve(strict=False).parent!=parent:
                raise ValueError("symlink or target escape")
        except (ValueError, OSError) as exc:
            raise WorkerDenied("TARGET_OUTSIDE_WORKER_BOUNDS") from exc
        return target

    def reconcile(self, request):
        """Only the isolated worker may assert no intent AND no effect."""
        with self.lock:
            if not isinstance(request,dict) or set(request)!={"operation","task_id","step_key","action"}:
                raise WorkerDenied("INVALID_RECONCILIATION_REQUEST")
            if request["operation"]!="reconcile_no_effect":
                raise WorkerDenied("UNSUPPORTED_RECONCILIATION")
            task=request["task_id"]; step=request["step_key"]; action=request["action"]
            if not isinstance(task,str) or not isinstance(step,str) or not isinstance(action,dict):
                raise WorkerDenied("INVALID_RECONCILIATION_FIELDS")
            if len(task)>127 or len(step)>18 or action.get("action_type") not in ("write","replace") or action.get("effect_class")!="E2":
                raise WorkerDenied("NO_EFFECT_PROOF_REQUIRES_BOUNDED_WRITE")
            try:
                target=self.bounded_target(action.get("target",""))
            except WorkerDenied as exc:
                raise WorkerDenied("RECONCILIATION_TARGET_OUTSIDE_BOUNDS") from exc
            state,detail=api(self.url,self.key,task)
            gate=state.get("pending_execution_gate")
            if (state.get("status")!="RECOVERY_PENDING"
                or state.get("current_step")!=step or not gate or
                gate["action_fingerprint"]!=fingerprint(action) or
                detail["task"]["contract_status"]!="OPEN"):
                raise WorkerDenied("NO_PENDING_RECOVERY_GATE")
            intent=self.journal/(task.replace("/","_")+"-"+step+".json")
            retired=self.journal/(task.replace("/","_")+"-"+step+"-"+str(gate["pre_checkpoint_no"])+".no-effect.json")
            replace=action["action_type"]=="replace"
            if intent.is_symlink() or retired.is_symlink() or target.is_symlink():
                raise WorkerDenied("NO_EFFECT_UNPROVEN_OR_TARGET_PRESENT")
            if replace:
                if (not re.fullmatch(r"[0-9a-f]{64}",action.get("previous_sha256",""))
                    or not target.is_file() or
                    hashlib.sha256(target.read_bytes()).hexdigest()!=action["previous_sha256"]):
                    raise WorkerDenied("NO_EFFECT_UNPROVEN_OR_PREIMAGE_CHANGED")
            elif target.exists():
                raise WorkerDenied("NO_EFFECT_UNPROVEN_OR_TARGET_PRESENT")
            if intent.exists():
                if retired.exists() or not intent.is_file():
                    raise WorkerDenied("AMBIGUOUS_WORKER_RECOVERY_JOURNAL")
                initial=json.loads(intent.read_text())
                if replace and (initial.get('previous_sha256')!=action['previous_sha256'] or
                    hashlib.sha256(base64.b64decode(initial.get('previous_content_b64',''))).hexdigest()!=action['previous_sha256']):
                    raise WorkerDenied("UNTRUSTED_REPLACEMENT_PREIMAGE_JOURNAL")
                if (initial.get("stage")!="INTENT_DURABLE" or
                    initial.get("task_id")!=task or initial.get("step_key")!=step or
                    initial.get("gate")!=gate["pre_checkpoint_no"] or
                    initial.get("target")!=str(target) or
                    initial.get("action_fingerprint")!=gate["action_fingerprint"]):
                    raise WorkerDenied("INTENT_NOT_SAFE_TO_RETIRE")
                # This exclusive worker lock is the only writer admission.
                # No target was ever created; preserve the original durable
                # intent as a gate-specific retired record rather than delete it.
                os.replace(intent,retired)
                dfd=os.open(self.journal,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try:os.fsync(dfd)
                finally:os.close(dfd)
            elif retired.exists():
                if not retired.is_file():
                    raise WorkerDenied("RETIRED_INTENT_NOT_REGULAR")
                initial=json.loads(retired.read_text())
                if replace and initial.get('previous_sha256')!=action['previous_sha256']:
                    raise WorkerDenied("RETIRED_PREIMAGE_MISMATCH")
                if (initial.get("stage")!="INTENT_DURABLE" or
                    initial.get("gate")!=gate["pre_checkpoint_no"] or
                    initial.get("task_id")!=task or initial.get("step_key")!=step or
                    initial.get("target")!=str(target) or
                    initial.get("action_fingerprint")!=gate["action_fingerprint"]):
                    raise WorkerDenied("RETIRED_INTENT_MISMATCH")
            return sign_no_effect(
                self.private,task_id=task,step_key=step,
                gate_checkpoint_no=gate["pre_checkpoint_no"],
                action_fingerprint=gate["action_fingerprint"],
                target=str(target),executor_id=self.executor_id)

    def execute(self,request):
        # Serialize both intent lookup and exclusive WRITE across worker RPC threads.
        with self.lock:
            return self._execute_locked(request)

    def _execute_locked(self,request):
        if not isinstance(request,dict) or set(request)!={'task_id','step_key','action','data_b64'}:
            raise WorkerDenied('INVALID_WORKER_REQUEST')
        task=request['task_id'];step=request['step_key'];action=request['action']
        if not (isinstance(task,str) and isinstance(step,str) and isinstance(action,dict)
                and isinstance(request['data_b64'],str)):
            raise WorkerDenied('INVALID_WORKER_FIELDS')
        if not (len(task)<=127 and len(step)<=18):raise WorkerDenied('INVALID_IDENTIFIERS')
        if len(request['data_b64'])>4*MAX_CONTENT//3+8:raise WorkerDenied('PAYLOAD_OVERSIZE')
        data=base64.b64decode(request['data_b64'],validate=True)
        is_replace=action.get("action_type")=="replace"
        is_write=(action.get('action_type') in ('write','replace') and action.get('effect_class')=='E2'
                  and action.get('reversible') is True and action.get('real_world_effect') is False)
        is_read=(action.get('action_type')=='read' and action.get('effect_class')=='E0'
                 and action.get('reversible') is False and action.get('real_world_effect') is False)
        if not (is_write or is_read):raise WorkerDenied('UNSUPPORTED_ACTION_CAPABILITY_FAIL_CLOSED')
        if is_write and not (0<len(data)<=MAX_CONTENT):
            raise WorkerDenied('INVALID_DATA_LENGTH')
        if is_write and (action.get('payload_sha256') is not None
                         or action.get('payload_bytes') is not None):
            if (action.get('payload_sha256')!=hashlib.sha256(data).hexdigest()
                    or type(action.get('payload_bytes')) is not int
                    or action['payload_bytes']!=len(data)):
                raise WorkerDenied('PAYLOAD_NOT_AUTHORIZED_BY_PRE')
        if is_replace and not re.fullmatch(r"[0-9a-f]{64}",action.get("previous_sha256","")):
            raise WorkerDenied("EXPECTED_PREVIOUS_DIGEST_REQUIRED")
        if is_read and data:raise WorkerDenied('READ_MUST_HAVE_EMPTY_INPUT')
        target=self.bounded_target(action.get('target',''))
        if is_write and target.suffix == '.json':
            try:
                json.loads(data)
            except (ValueError, UnicodeDecodeError) as exc:
                raise WorkerDenied('INVALID_JSON_OUTPUT') from exc
        state,detail=api(self.url,self.key,task)
        gate=state.get('pending_execution_gate')
        if state.get('current_step')!=step or not gate:
            raise WorkerDenied('EG_PRE_NOT_READY')
        if detail['task']['contract_status']!='OPEN':
            raise WorkerDenied('EG_TASK_NOT_OPEN')
        if gate['action_fingerprint']!=fingerprint(action):
            raise WorkerDenied('EG_ACTION_FINGERPRINT_MISMATCH')
        if state.get('status') == 'PAUSED':
            raise WorkerDenied('TASK_PAUSED_NO_EXECUTION')
        gate_record=next((x for x in detail['checkpoints']
                         if x['checkpoint_no']==gate['pre_checkpoint_no']),None)
        if not gate_record or gate_record['verdict']!='READY_TO_EXECUTE':
            raise WorkerDenied('EG_ORIGINAL_GATE_NOT_READY')
        # Receipt recovery MUST precede latest-checkpoint readiness. A failed
        # POST changes latest_checkpoint to UNVERIFIED without consuming the
        # original PRE gate. A sealed journal is read-only evidence, not
        # authority for a second physical write.
        if is_write:
            intent=self.journal/(task.replace('/','_')+'-'+step+'.json')
            if intent.is_symlink():
                raise WorkerDenied('UNSAFE_WORKER_JOURNAL')
            if intent.is_file():
                initial=json.loads(intent.read_text())
                expected_digest=hashlib.sha256(data).hexdigest()
                if (initial.get('task_id')!=task or initial.get('step_key')!=step
                    or (is_replace and initial.get('previous_sha256')!=action['previous_sha256'])
                    or initial.get('gate')!=gate['pre_checkpoint_no']
                    or initial.get('target')!=str(target)
                    or initial.get('data_sha256')!=expected_digest
                    or initial.get('action_fingerprint')!=gate['action_fingerprint']):
                    raise WorkerDenied('INTENT_REPLAY_OR_MISMATCH')
                if initial.get('stage')=='RECEIPT_SEALED':
                    if not target.is_file() or target.is_symlink() or target.read_bytes()!=data:
                        raise WorkerDenied('RECEIPT_EFFECT_MISMATCH')
                    receipt=initial.get('receipt')
                    public_b64=base64.b64encode(self.private.public_key().public_bytes(
                        Encoding.Raw,PublicFormat.Raw)).decode('ascii')
                    valid,reason=verify(receipt,public_b64=public_b64,
                        task_id=task,step_key=step,
                        gate_checkpoint_no=gate['pre_checkpoint_no'],
                        action_fingerprint=gate['action_fingerprint'],
                        target=str(target),gate_created_at=gate_record['created_at'])
                    if not valid or receipt['output_sha256']!=expected_digest or receipt['output_bytes']!=len(data):
                        raise WorkerDenied('SEALED_RECEIPT_VERIFICATION_FAILED:'+reason)
                    return receipt
        # For any NEW effect we still require the current latest checkpoint
        # to be this READY PRE. A failed POST never reopens authorization.
        if (not state.get('latest_checkpoint')
            or state['latest_checkpoint'].get('verdict')!='READY_TO_EXECUTE'
            or gate['pre_checkpoint_no']!=state['latest_checkpoint']['checkpoint_no']):
            raise WorkerDenied('EG_PRE_NOT_READY')
        if is_read:
            if not gate_record or not gate_allows_new_effect(gate_record['created_at']):
                raise WorkerDenied('EXECUTION_LEASE_EXPIRED')
            if target.is_symlink() or not target.is_file():
                raise WorkerDenied('READ_TARGET_NOT_REGULAR_FILE')
            info=target.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_size>MAX_CONTENT:
                raise WorkerDenied('READ_TOO_LARGE_OR_UNSAFE')
            observed=target.read_bytes()
            if not observed:raise WorkerDenied('READ_EMPTY_UNSUPPORTED')
            return sign(body(task,step,gate['pre_checkpoint_no'],
                   gate['action_fingerprint'],self.executor_id,str(target),
                   observed,secrets.token_urlsafe(24)),self.private)
        intent=self.journal/(task.replace('/','_')+'-'+step+'.json')
        if state.get('status') == 'PAUSED':
            raise WorkerDenied('TASK_PAUSED_NO_EXECUTION')
        if state.get('status') == 'RECOVERY_PENDING' and not intent.exists():
            raise WorkerDenied('UNKNOWN_EFFECT_NO_NEW_EXECUTION_ON_RESUME')
        digest=hashlib.sha256(data).hexdigest()
        if intent.exists():
            initial=json.loads(intent.read_text())
            if (initial.get('task_id')!=task or initial.get('step_key')!=step
                or (is_replace and initial.get('previous_sha256')!=action['previous_sha256'])
                or initial.get('gate')!=gate['pre_checkpoint_no']
                or initial.get('target')!=str(target)
                or initial.get('data_sha256')!=digest
                or initial.get('action_fingerprint')!=gate['action_fingerprint']):
                raise WorkerDenied('INTENT_REPLAY_OR_MISMATCH')
            if initial.get('stage')=='RECEIPT_SEALED':
                if not target.is_file() or target.read_bytes()!=data:
                    raise WorkerDenied('RECEIPT_EFFECT_MISMATCH')
                return initial['receipt']
            if initial.get('stage')!='INTENT_DURABLE':
                raise WorkerDenied('UNKNOWN_JOURNAL_STATE')
            # A crash after exclusive WRITE but before receipt sealing: the worker
            # can recover from its own fsynced intent and independently read back.
            if not target.exists():
                raise WorkerDenied('NO_EFFECT_AFTER_CRASH_REQUIRES_FRESH_AUTHORIZATION')
            stat_result=target.stat()
            gate_ns=int(datetime.fromisoformat(
                 next(g['created_at'] for g in detail['checkpoints']
                      if g['checkpoint_no']==gate['pre_checkpoint_no'])
                ).timestamp()*1_000_000_000)
            if (stat_result.st_uid!=os.geteuid() or not stat.S_ISREG(stat_result.st_mode)
                or stat_result.st_mtime_ns < gate_ns
                or target.read_bytes()!=data):
                raise WorkerDenied('RECOVERY_EFFECT_NOT_INDEPENDENTLY_PROVEN')
            # No second WRITE. Only sign the reconciled output.
        else:
            # A paused task can resume in months, but no *new* WRITE may start
            # under an aged PRE authorization. Reconciliation remains allowed.
            gate_entry=next((g for g in detail['checkpoints']
                             if g['checkpoint_no']==gate['pre_checkpoint_no']),None)
            if not gate_entry or not gate_allows_new_effect(gate_entry['created_at']):
                raise WorkerDenied('EXECUTION_LEASE_EXPIRED_REAUTHORIZE_SAFELY')
            # No existing output may be converted to a retroactive receipt.
            if not is_replace and target.exists():raise WorkerDenied('PREEXISTING_EFFECT_RETROACTIVE_DENIED')
            if is_replace:
                if (not target.is_file() or target.is_symlink() or
                    target.stat().st_uid!=os.getuid() or target.stat().st_size>MAX_CONTENT):
                    raise WorkerDenied('REPLACE_TARGET_NOT_WORKER_OWNED')
                previous=target.read_bytes()
                if (not previous or hashlib.sha256(previous).hexdigest()!=action['previous_sha256']
                    or previous==data):
                    raise WorkerDenied('REPLACE_PREIMAGE_MISMATCH')
            if action.get('payload_sha256') is None or action.get('payload_bytes') is None:
                raise WorkerDenied('EXECUTION_PAYLOAD_NOT_BOUND_TO_PRE')
            initial={'stage':'INTENT_DURABLE','task_id':task,'step_key':step,
                     'gate':gate['pre_checkpoint_no'],'target':str(target),
                     'action_fingerprint':gate['action_fingerprint'],
                     'data_sha256':digest}
            if is_replace:
                initial['previous_sha256']=action['previous_sha256']
                initial['previous_content_b64']=base64.b64encode(previous).decode()
            store_exclusive(intent,canon(initial))
            # Only privileged worker performs physical WRITE, after PRE.
            (store_replace if is_replace else store_exclusive)(target,data)
        observed=target.read_bytes()
        if observed!=data:raise WorkerDenied('INDEPENDENT_READBACK_MISMATCH')
        receipt=sign(body(task,step,gate['pre_checkpoint_no'],
                          gate['action_fingerprint'],self.executor_id,str(target),
                          observed,secrets.token_urlsafe(24)),self.private)
        final={**initial,'stage':'RECEIPT_SEALED','receipt':receipt}
        tmp=intent.with_suffix('.sealed')
        store_exclusive(tmp,canon(final))
        os.replace(tmp,intent)
        dfd=os.open(self.journal,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(dfd)
        finally:os.close(dfd)
        return receipt

def serve(config):
    if os.geteuid()==0:
        raise WorkerDenied('TRUSTED_WORKER_MUST_NOT_RUN_AS_ROOT')
    worker=TrustedWriter(config['output_root'],config['journal_root'],
                         config['private_key'],config['eg_url'],
                         config['eg_api_key'],config['executor_id'],
                         config.get('allowed_suffixes'))
    sock=Path(config['socket_path'])
    controller_uid=config.get('controller_uid')
    controller_gid=config.get('controller_group_gid')
    if controller_uid is not None or controller_gid is not None:
        if (type(controller_uid) is not int or controller_uid<=0 or
            controller_uid==os.geteuid() or type(controller_gid) is not int or
            controller_gid<=0 or controller_gid==os.getegid()):
            raise WorkerDenied('INVALID_INDEPENDENT_CONTROLLER_IDENTITY')
        parent=sock.parent.lstat()
        mode=stat.S_IMODE(parent.st_mode)
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=os.geteuid()
            or parent.st_gid!=controller_gid or not parent.st_mode & stat.S_ISGID
            or not mode & stat.S_IXGRP or mode & 0o067):
            raise WorkerDenied('WORKER_SOCKET_GROUP_NOT_PRIVATE')
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            try:
                if controller_uid is not None:
                    credentials=self.request.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,
                        struct.calcsize('3i'))
                    if struct.unpack('3i',credentials)[1]!=controller_uid:
                        raise WorkerDenied('UNAUTHORIZED_CONTROLLER_UID')
                line=self.rfile.readline(MAX_PAYLOAD+1)
                if not line.endswith(b'\n') or len(line)>MAX_PAYLOAD:
                    raise WorkerDenied('INVALID_RPC_SIZE')
                request=json.loads(line)
                if isinstance(request,dict) and request.get('operation')=='reconcile_no_effect':
                    answer={'status':'PASS','reconciliation':worker.reconcile(request)}
                else:
                    receipt=worker.execute(request)
                    answer={'status':'PASS','receipt':receipt}
            except Exception as e:
                answer={'status':'DENIED','reason':type(e).__name__+':'+str(e)}
            self.wfile.write(canon(answer)+b'\n')
    class Server(socketserver.ThreadingUnixStreamServer):
        daemon_threads=True
    with private_socket_lease(sock), Server(str(sock),Handler) as server:
        os.chmod(sock,0o660 if controller_uid is not None else 0o600)
        server.serve_forever(poll_interval=.2)

if __name__=='__main__':
    if len(sys.argv)!=2:raise SystemExit('Expected protected worker configuration path')
    cfg=Path(sys.argv[1])
    if stat.S_IMODE(cfg.stat().st_mode)&0o077:raise SystemExit('Unsafe worker config permissions')
    serve(json.loads(cfg.read_text()))
