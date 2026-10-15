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
from pathlib import Path
from urllib.request import Request,urlopen
from urllib.error import HTTPError
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from app.execution_receipts import body, sign

MAX_PAYLOAD = 1024 * 1024
MAX_CONTENT = 512 * 1024
class WorkerDenied(RuntimeError): pass

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
        self.url=eg_url.rstrip('/')
        self.key=api_key
        if not executor_id.startswith('trusted-worker-'):raise WorkerDenied('INVALID_WORKER_ID')
        self.executor_id=executor_id

    def execute(self,request):
        if not isinstance(request,dict) or set(request)!={'task_id','step_key','action','data_b64'}:
            raise WorkerDenied('INVALID_WORKER_REQUEST')
        task=request['task_id'];step=request['step_key'];action=request['action']
        if not (isinstance(task,str) and isinstance(step,str) and isinstance(action,dict)
                and isinstance(request['data_b64'],str)):
            raise WorkerDenied('INVALID_WORKER_FIELDS')
        if not (len(task)<=127 and len(step)<=18):raise WorkerDenied('INVALID_IDENTIFIERS')
        if len(request['data_b64'])>4*MAX_CONTENT//3+8:raise WorkerDenied('PAYLOAD_OVERSIZE')
        data=base64.b64decode(request['data_b64'],validate=True)
        if not (0<len(data)<=MAX_CONTENT):raise WorkerDenied('INVALID_DATA_LENGTH')
        if action.get('action_type')!='write' or action.get('effect_class')!='E2' or not action.get('reversible') or action.get('real_world_effect'):
            raise WorkerDenied('UNAUTHORIZED_EFFECT_CLASS')
        target=Path(action.get('target',''))
        resolved=target.resolve(strict=False)
        if target.is_symlink() or resolved.parent!=self.root or not resolved.name.endswith('.txt'):
            raise WorkerDenied('TARGET_OUTSIDE_WORKER_BOUNDS')
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
        intent=self.journal/(task.replace('/','_')+'-'+step+'.json')
        if state.get('status') == 'PAUSED':
            raise WorkerDenied('TASK_PAUSED_NO_EXECUTION')
        if state.get('status') == 'RECOVERY_PENDING' and not intent.exists():
            raise WorkerDenied('UNKNOWN_EFFECT_NO_NEW_EXECUTION_ON_RESUME')
        if intent.exists():
            old=json.loads(intent.read_text())
            if old.get('stage')=='RECEIPT_SEALED' and old.get('data_sha256')==hashlib.sha256(data).hexdigest() and target.read_bytes()==data:
                return old['receipt']
            raise WorkerDenied('UNKNOWN_OR_CHANGED_EFFECT_NO_DUPLICATE_WRITE')
        # No existing output may be turned into a retroactive execution receipt.
        if target.exists():raise WorkerDenied('PREEXISTING_EFFECT_RETROACTIVE_DENIED')
        initial={'stage':'INTENT_DURABLE','task_id':task,'step_key':step,
                 'gate':gate['pre_checkpoint_no'],'target':str(target),
                 'data_sha256':hashlib.sha256(data).hexdigest()}
        store_exclusive(intent,canon(initial))
        # Only this privileged worker performs the physical write after EG gate.
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
