"""Operator-preapproved generic E3–E5 typed scope: independent, limited signed HITL grants.

This is an OPTIONAL separate-UID signer, not a way for agents to approve themselves.
No automatic production authority, no arbitrary shell, and no HITL key shared with the agent.
"""
from __future__ import annotations

import base64
import json
import os
import re
import secrets
import socket
import socketserver
import sqlite3
import stat
import struct
import time
from pathlib import Path
from tools.private_unix_socket import private_socket_lease
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from tools.high_effect_admission import action_fingerprint
from tools.operator_process_service import _private_file
from tools.signed_hitl_approval import canonical


class PolicyDenied(RuntimeError):
    pass


def configure(path):
    if os.geteuid() == 0:
        raise PolicyDenied('INDEPENDENT_NONROOT_SIGNER_REQUIRED')
    config = json.loads(_private_file(Path(path)))
    fields = {'key_file', 'ledger_dir', 'socket_path', 'controller_uid',
              'controller_group_gid', 'adapter_id', 'target_prefix',
              'expires_at', 'max_grants', 'max_payload_bytes', 'effect_class', 'action_type'}
    if (not isinstance(config, dict) or set(config) != fields or
        type(config['controller_uid']) is not int or config['controller_uid'] in (0, os.geteuid()) or
        type(config['controller_group_gid']) is not int or config['controller_group_gid'] <= 0 or
        not isinstance(config['adapter_id'], str) or not config['adapter_id'].startswith('trusted-adapter-') or
        not isinstance(config['target_prefix'], str) or not config['target_prefix'].startswith('/tasks/') or
        '..' in config['target_prefix'].split('/') or
        type(config['max_grants']) is not int or not 1 <= config['max_grants'] <= 100 or
        type(config['max_payload_bytes']) is not int or not 1 <= config['max_payload_bytes'] <= 524288 or
        type(config['expires_at']) is not int or
        not time.time() < config['expires_at'] <= time.time() + 86400 or
        config['effect_class'] not in ('E3','E4','E5') or
        not isinstance(config['action_type'],str) or
        not re.fullmatch(r'[a-z][a-z0-9_]{0,63}', config.get('action_type','bounded_process_run'))):
        raise PolicyDenied('INVALID_SCOPED_OPERATOR_POLICY')
    key = load_pem_private_key(_private_file(Path(config['key_file'])), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise PolicyDenied('INVALID_SIGNING_KEY')
    config['key'] = key
    return config


class Grants:
    def __init__(self, config):
        self.p = config
        folder = Path(config['ledger_dir'])
        if (folder.is_symlink() or not folder.is_dir() or folder.stat().st_uid != os.geteuid() or
            stat.S_IMODE(folder.stat().st_mode) & 0o077):
            raise PolicyDenied('PRIVATE_GRANT_LEDGER_REQUIRED')
        self.db = folder / 'scoped-approvals.sqlite3'
        if self.db.exists() and (self.db.is_symlink() or
            self.db.stat().st_uid != os.geteuid() or stat.S_IMODE(self.db.stat().st_mode) & 0o077):
            raise PolicyDenied('UNSAFE_GRANT_LEDGER')
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS grants (scope TEXT PRIMARY KEY, approval TEXT NOT NULL)')
        os.chmod(self.db, 0o600)

    def connect(self):
        db = sqlite3.connect(self.db, timeout=10, isolation_level=None)
        db.execute('PRAGMA busy_timeout=10000')
        db.execute('PRAGMA synchronous=FULL')
        return db

    def issue(self, request):
        fields = {'task_id','step_key','gate_checkpoint_no','action'}
        if not isinstance(request,dict) or set(request)!=fields:
            raise PolicyDenied('INVALID_APPROVAL_REQUEST')
        task,step,gate,action = (request['task_id'],request['step_key'],
                                 request['gate_checkpoint_no'],request['action'])
        p=self.p
        if (not isinstance(task,str) or not 1<=len(task)<=127 or any(x in task for x in '/?#')
            or not isinstance(step,str) or not 1<=len(step)<=127 or type(gate) is not int or gate<=0
            or not isinstance(action,dict) or action.get('action_type')!=p['action_type']
            or action.get('effect_class')!=p['effect_class']
            or action.get('real_world_effect') is not True
            or (action.get('effect_class')=='E5' and action.get('reversible') is not False)
            or (action.get('effect_class')=='E4' and action.get('reversible') is not True)
            or not isinstance(action.get('target'),str)
            or not action['target'].startswith(p['target_prefix'].rstrip('/')+'/')
            or any(x in ('.','..','') for x in action['target'][len(p['target_prefix'].rstrip('/'))+1:].split('/'))
            or type(action.get('payload_bytes')) is not int
            or not 1<=action['payload_bytes']<=p['max_payload_bytes']
            or not isinstance(action.get('payload_sha256'),str)
            or not re.fullmatch('[0-9a-f]{64}',action['payload_sha256'])):
            raise PolicyDenied('ACTION_OUTSIDE_OPERATOR_POLICY')
        now=int(time.time())
        if now>=p['expires_at']:
            raise PolicyDenied('STANDING_OPERATOR_POLICY_EXPIRED')
        scope=canonical({'task':task,'step':step,'gate':gate,'fingerprint':action_fingerprint(action)})
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            prior=db.execute('SELECT approval FROM grants WHERE scope=?',(scope.decode(),)).fetchone()
            if prior:
                result=json.loads(prior[0])
                if now>=result['expires_at']:
                    raise PolicyDenied('PREVIOUS_GRANT_EXPIRED_NO_REISSUE')
                return result
            if db.execute('SELECT COUNT(*) FROM grants').fetchone()[0]>=p['max_grants']:
                raise PolicyDenied('OPERATOR_APPROVAL_QUOTA_EXHAUSTED')
            body={'version':1,'task_id':task,'step_key':step,'gate_checkpoint_no':gate,
                  'action_fingerprint':action_fingerprint(action),'adapter_id':p['adapter_id'],
                  'decision':'APPROVED','issued_at':now-1,
                  'expires_at':min(now+120,p['expires_at']),'nonce':secrets.token_urlsafe(24)}
            result={**body,'signature_b64':base64.b64encode(p['key'].sign(canonical(body))).decode()}
            db.execute('INSERT INTO grants VALUES (?,?)',(scope.decode(),json.dumps(result,sort_keys=True)))
            db.commit()
        return result


def serve(config):
    grants=Grants(config)
    socket_path=Path(config['socket_path'])
    folder=socket_path.parent
    info=folder.stat()
    if (folder.is_symlink() or info.st_uid!=os.geteuid() or
        info.st_gid!=config['controller_group_gid'] or
        stat.S_IMODE(info.st_mode)!=0o2710):
        raise PolicyDenied('INVALID_OPERATOR_SOCKET_DIRECTORY')

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            try:
                self.request.settimeout(4)
                uid=struct.unpack('3i',self.request.getsockopt(socket.SOL_SOCKET,
                        socket.SO_PEERCRED,struct.calcsize('3i')))[1]
                if uid!=config['controller_uid']:
                    raise PolicyDenied('UNAUTHORIZED_AGENT_IDENTITY')
                raw=self.rfile.readline(8193)
                if len(raw)>8192 or not raw.endswith(b'\n'):
                    raise PolicyDenied('OVERSIZED_APPROVAL_REQUEST')
                result={'status':'PASS','approval':grants.issue(json.loads(raw))}
            except Exception as exc:
                result={'status':'DENIED','reason':type(exc).__name__+':'+str(exc)}
            self.wfile.write(canonical(result)+b'\n')

    class Server(socketserver.ThreadingUnixStreamServer):
        daemon_threads=True
    with private_socket_lease(socket_path), Server(str(socket_path),Handler) as server:
        os.chmod(socket_path,0o660)
        server.serve_forever(poll_interval=.2)


if __name__=='__main__':
    import sys
    if len(sys.argv)!=2:
        raise SystemExit('usage: python -m tools.operator_scoped_approval protected-operator-config.json')
    serve(configure(sys.argv[1]))
