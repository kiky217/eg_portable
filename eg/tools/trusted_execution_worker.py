#!/usr/bin/env python3
"""Trusted, bounded E2 file writer for Evaluation Gateway.

Signer private key and output dir belong to a separate worker identity. The
caller cannot request signatures or arbitrary commands, only an EG-preapproved
exclusive file creation. Durable intent prevents duplicate effects on retry.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
import secrets
import socketserver
import stat
import sys
import time
import threading
from datetime import datetime
from pathlib import Path
from urllib.request import Request,urlopen
from urllib.error import HTTPError
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from app.execution_receipts import body, sign

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
    def __init__(self,output_root,journal_root,private_key,eg_url,api_key,executor_id):
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
        is_write=(action.get('action_type')=='write' and action.get('effect_class')=='E2'
                  and action.get('reversible') is True and action.get('real_world_effect') is False)
        is_read=(action.get('action_type')=='read' and action.get('effect_class')=='E0'
                 and action.get('reversible') is False and action.get('real_world_effect') is False)
        if not (is_write or is_read):raise WorkerDenied('UNSUPPORTED_ACTION_CAPABILITY_FAIL_CLOSED')
        if is_write and not (0<len(data)<=MAX_CONTENT):
            raise WorkerDenied('INVALID_DATA_LENGTH')
        if is_read and data:raise WorkerDenied('READ_MUST_HAVE_EMPTY_INPUT')
        target=Path(action.get('target',''))
        resolved=target.resolve(strict=False)
        if (target.is_symlink() or resolved.parent != self.root
            or resolved.suffix not in ('.txt', '.json')):
            raise WorkerDenied('TARGET_OUTSIDE_WORKER_BOUNDS')
        if is_write and resolved.suffix == '.json':
            try:
                json.loads(data)
            except (ValueError, UnicodeDecodeError) as exc:
                raise WorkerDenied('INVALID_JSON_OUTPUT') from exc
        state,detail=api(self.url,self.key,task)
        gate=state.get('pending_execution_gate')
        if (state.get('current_step')!=step or not gate
            or state['latest_checkpoint'].get('verdict')!='READY_TO_EXECUTE'
            or gate['pre_checkpoint_no']!=state['latest_checkpoint']['checkpoint_no']):
            raise WorkerDenied('EG_PRE_NOT_READY')
        if detail['task']['contract_status']!='OPEN':
            raise WorkerDenied('EG_TASK_NOT_OPEN')
        if gate['action_fingerprint']!=fingerprint(action):
            raise WorkerDenied('EG_ACTION_FINGERPRINT_MISMATCH')
        if state.get('status') == 'PAUSED':
            raise WorkerDenied('TASK_PAUSED_NO_EXECUTION')
        gate_record=next((x for x in detail['checkpoints']
                         if x['checkpoint_no']==gate['pre_checkpoint_no']),None)
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
            if target.exists():raise WorkerDenied('PREEXISTING_EFFECT_RETROACTIVE_DENIED')
            initial={'stage':'INTENT_DURABLE','task_id':task,'step_key':step,
                     'gate':gate['pre_checkpoint_no'],'target':str(target),
                     'action_fingerprint':gate['action_fingerprint'],
                     'data_sha256':digest}
            store_exclusive(intent,canon(initial))
            # Only privileged worker performs physical WRITE, after PRE.
            store_exclusive(target,data)
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
                         config['eg_api_key'],config['executor_id'])
    sock=Path(config['socket_path'])
    if sock.exists():raise WorkerDenied('SOCKET_ALREADY_EXISTS')
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            try:
                line=self.rfile.readline(MAX_PAYLOAD+1)
                if not line.endswith(b'\n') or len(line)>MAX_PAYLOAD:
                    raise WorkerDenied('INVALID_RPC_SIZE')
                receipt=worker.execute(json.loads(line))
                answer={'status':'PASS','receipt':receipt}
            except Exception as e:
                answer={'status':'DENIED','reason':type(e).__name__+':'+str(e)}
            self.wfile.write(canon(answer)+b'\n')
    class Server(socketserver.ThreadingUnixStreamServer):
        daemon_threads=True
    with Server(str(sock),Handler) as server:
        os.chmod(sock,0o600)
        server.serve_forever(poll_interval=.2)

if __name__=='__main__':
    if len(sys.argv)!=2:raise SystemExit('Expected protected worker configuration path')
    cfg=Path(sys.argv[1])
    if stat.S_IMODE(cfg.stat().st_mode)&0o077:raise SystemExit('Unsafe worker config permissions')
    serve(json.loads(cfg.read_text()))
