"""Regression tests: one or more per audited finding (B1..B8 and the low-severity items)."""
import json, os, shutil, subprocess, sys, threading, time
import pytest
from fastapi.testclient import TestClient
import harness as H
from harness import gw, CLIENT, SOFT, HEAD, HITL, RUNTIME, CRIT, eid, claim, evp, manual, notarized, register, raw_eval, step_ref, task_ref, task_claim, do_pre, do_post, e3_action, induce_three_failures, register_remedial, complete_remedial, sb

ROOT = H.ROOT


# ---------------- B1: evidence bound to phase / checkpoint / gate / time ----------------
def test_b1_pre_evidence_cannot_be_replayed_as_post_evidence():
    task, ch = register(); pre, pre_ref = do_pre(task, ch, 0)
    r = raw_eval(task, ch, pre.json()['checkpoint_no'], claims=[claim(pre_ref)], phase='POST_EXECUTION')
    assert r.status_code == 200 and r.json()['verdict'] == 'UNVERIFIED' and not r.json()['step_verified']
    assert any('binding mismatch' in n['note'] for n in r.json()['evidence_notes'])


def test_b1_post_evidence_bound_to_wrong_gate_checkpoint_rejected():
    task, ch = register(); pre, _ = do_pre(task, ch, 0)
    r, _ = do_post(task, ch, pre, gate_cp=pre.json()['gate_checkpoint_no'] + 5)
    assert r.json()['verdict'] == 'UNVERIFIED' and any('binding mismatch' in n['note'] for n in r.json()['evidence_notes'])


def test_b1_post_evidence_finished_before_gate_is_rejected():
    task, ch = register(); pre, _ = do_pre(task, ch, 0)
    ref = step_ref(task, 'POST_EXECUTION', pre.json()['gate_checkpoint_no'], age=gw.CLOCK_SKEW_SECONDS + 60)
    r, _ = do_post(task, ch, pre, ref=ref)
    assert r.json()['verdict'] == 'UNVERIFIED' and any('predates execution gate' in n['note'] for n in r.json()['evidence_notes'])


def test_b1_fact_check_evidence_cannot_authorize_pre():
    task, ch = register(); ref = step_ref(task, 'FACT_CHECK', 0)
    r = raw_eval(task, ch, 0, claims=[claim(ref)], phase='PRE_EXECUTION'); assert r.json()['verdict'] == 'UNVERIFIED'


def test_b1_pre_evidence_from_previous_checkpoint_cannot_be_reused():
    task2, ch2 = register(); r1, ref = do_pre(task2, ch2, 0)
    r2 = raw_eval(task2, ch2, r1.json()['checkpoint_no'], claims=[claim(ref)], phase='PRE_EXECUTION')
    assert r2.json()['verdict'] == 'UNVERIFIED'


# ---------------- B2: freshness window is server policy ----------------
def test_b2_client_cannot_supply_max_age():
    task, ch = register(); ref = step_ref(task, 'PRE_EXECUTION', 0)
    cl = {**claim(ref), 'max_age_seconds': 604800}; r = raw_eval(task, ch, 0, claims=[cl]); assert r.status_code == 422


def test_b2_server_policy_governs_freshness(monkeypatch):
    task, ch = register(); ref = step_ref(task, 'PRE_EXECUTION', 0, age=1000)
    assert raw_eval(task, ch, 0, claims=[claim(ref)]).json()['verdict'] == 'UNVERIFIED'
    monkeypatch.setattr(gw, 'EVIDENCE_MAX_AGE_SECONDS', 2000)
    task2, ch2 = register(); ref2 = step_ref(task2, 'PRE_EXECUTION', 0, age=1000)
    assert raw_eval(task2, ch2, 0, claims=[claim(ref2)]).json()['verdict'] == 'READY_TO_EXECUTE'


def test_b2_non_finite_timestamp_rejected():
    task, ch = register(); ref = step_ref(task, 'PRE_EXECUTION', 0, finished_at=float('nan'))
    r = raw_eval(task, ch, 0, claims=[claim(ref)]); assert r.json()['verdict'] == 'UNVERIFIED' and any('completion timestamp missing' in n['note'] for n in r.json()['evidence_notes'])


def test_b2_bounded_environment_settings(monkeypatch):
    monkeypatch.setenv('EVALUATION_GATEWAY_EVIDENCE_MAX_AGE_SECONDS', '999999')
    with pytest.raises(RuntimeError): gw.env_int('EVALUATION_GATEWAY_EVIDENCE_MAX_AGE_SECONDS', 300, 1, 86400)
    monkeypatch.setenv('EVALUATION_GATEWAY_EVIDENCE_MAX_AGE_SECONDS', 'abc')
    with pytest.raises(RuntimeError): gw.env_int('EVALUATION_GATEWAY_EVIDENCE_MAX_AGE_SECONDS', 300, 1, 86400)


# ---------------- B3: external anchor ----------------
def test_b3_whole_database_rollback_is_detected_and_recoverable():
    task0, ch0 = register(); H.checkpoint_wal()
    snap = RUNTIME / 'snap'; snap.mkdir(exist_ok=True)
    for f in H.db_files():
        if f.exists(): shutil.copy2(f, snap / f.name)
    task, ch = register(); pre, _ = do_pre(task, ch, 0); post, _ = do_post(task, ch, pre); assert post.json()['step_verified']
    H.checkpoint_wal()
    for f in H.db_files():
        if f.exists(): f.unlink()
    for f in snap.iterdir(): shutil.copy2(f, gw.DB_PATH.parent / f.name)
    r = SOFT.post('/v1/tasks/register', headers=HEAD, json={'event_id': eid('x'), 'task_id': eid('t'), 'protocol_hash': gw.protocol_hash(), 'agent': 'a', 'original_instruction': 'x', 'acceptance_criteria': ['g'], 'steps': [{'step_key': '01', 'title': 'p', 'acceptance_criteria': ['c']}, {'step_key': '01.01', 'title': 'c', 'acceptance_criteria': ['c']}]})
    assert r.status_code == 503
    assert raw_eval(task0, ch0, 0, claims=[claim(step_ref(task0, 'PRE_EXECUTION', 0))]).status_code == 503
    assert CLIENT.get('/health').status_code == 503
    assert CLIENT.get('/v1/audit/verify', headers=HEAD).status_code == 409
    env = {**os.environ}
    p = subprocess.run([sys.executable, str(ROOT / 'tools' / 'reanchor.py'), '--confirm'], capture_output=True, text=True, env=env); assert p.returncode == 0, p.stderr
    assert CLIENT.get('/health').status_code == 200


def test_b3_anchor_authentication_and_presence(monkeypatch):
    original = H.ANCHOR.read_bytes()
    try:
        H.ANCHOR.write_text(json.dumps({'version': 1, 'seq': 0, 'head': gw.ZERO_HASH, 'mac': '0' * 64}))
        assert CLIENT.get('/health').status_code == 503
        H.ANCHOR.unlink()
        assert CLIENT.get('/health').status_code == 503
    finally:
        H.ANCHOR.write_bytes(original)
    assert CLIENT.get('/health').status_code == 200


def test_b3_audit_record_mac_binds_sequence_and_detects_deleted_row():
    task, ch = register(); register(); H.checkpoint_wal()
    copy = RUNTIME / 'gap.db'; shutil.copy2(gw.DB_PATH, copy)
    import sqlite3
    c = sqlite3.connect(copy); c.row_factory = sqlite3.Row; assert gw.verify_audit_chain(c)
    seq = c.execute('SELECT seq FROM audit ORDER BY seq LIMIT 1 OFFSET 3').fetchone()[0]
    c.execute('DELETE FROM audit WHERE seq=?', (seq,)); c.commit(); assert not gw.verify_audit_chain(c); c.close()


def test_b3_anchor_dir_must_differ_from_database_dir(monkeypatch):
    monkeypatch.setattr(gw, 'ANCHOR_PATH', gw.DB_PATH.parent / 'audit.anchor')
    with pytest.raises(RuntimeError, match='different directory'): gw.require_config()
    monkeypatch.setattr(gw, 'ANCHOR_PATH', None)
    with pytest.raises(RuntimeError, match='anchor path missing'): gw.require_config()


# ---------------- B4: non-ASCII safe comparisons ----------------
def test_b4_non_ascii_criteria_are_fully_evaluable():
    crit = 'Hasil tes — lulus (é) “ok” 🚀'; task, ch = register(criteria_child=[crit], global_criteria=['kriteria global — é'])
    pre, _ = do_pre(task, ch, 0, criteria=[(0, crit)]); assert pre.json()['verdict'] == 'READY_TO_EXECUTE', pre.text
    post, _ = do_post(task, ch, pre, criteria=[(0, crit)]); assert post.json()['verdict'] == 'VERIFIED_PASS'
    cp = post.json()['checkpoint_no']
    ppre, _ = do_pre(task, ch, cp, step='01', criteria=[(0, 'parent criterion')], stdout='PARENT=PASS', value='PARENT=PASS')
    tr = task_ref(task, ppre.json()['gate_checkpoint_no'], criterion='kriteria global — é')
    fin, _ = do_post(task, ch, ppre, step='01', criteria=[(0, 'parent criterion')], stdout='PARENT=PASS', value='PARENT=PASS', finalize=True, task_claims=[task_claim(tr, criterion='kriteria global — é')])
    assert fin.status_code == 200 and fin.json()['contract_status'] == 'SATISFIED'


def test_b4_non_ascii_secrets_and_hashes_never_cause_500():
    assert SOFT.get('/v1/protocol', headers={'X-Evaluation-Key': 'é'.encode('latin-1')}).status_code == 401
    assert SOFT.get('/v1/protocol', headers={'X-Evaluation-Key': 'ключ'.encode('utf-8')}).status_code == 401
    body = {'event_id': eid('r'), 'task_id': eid('t'), 'protocol_hash': 'é', 'agent': 'a', 'original_instruction': 'x', 'acceptance_criteria': ['g'], 'steps': [{'step_key': '01', 'title': 'p', 'acceptance_criteria': ['c']}, {'step_key': '01.01', 'title': 'c', 'acceptance_criteria': ['c']}]}
    assert SOFT.post('/v1/tasks/register', headers=HEAD, json=body).status_code == 422
    task, ch = register(); ref = step_ref(task, 'PRE_EXECUTION', 0)
    r = SOFT.post('/v1/evaluate', headers={**HEAD, 'X-Evaluation-HITL-Key': 'é'.encode('latin-1')}, json={'event_id': eid('e'), 'task_id': task, 'contract_hash': ch, 'protocol_hash': gw.protocol_hash(), 'checkpoint_no': 0, 'step_key': '01.01', 'agent': 'ChatGPT', 'phase': 'PRE_EXECUTION', 'claims': [claim(ref)], 'action': e3_action()})
    assert r.status_code == 200 and r.json()['verdict'] == 'REQUIRES_HITL'


def test_b4_ct_helper_handles_arbitrary_unicode():
    assert gw.ct('é', 'é') and not gw.ct('é', 'e') and not gw.ct('🚀', '')


# ---------------- B5: cheap, minimal, bounded /health ----------------
def test_b5_health_failure_reveals_nothing(monkeypatch):
    monkeypatch.setattr(gw, 'HITL_KEY', gw.API_KEY); r = CLIENT.get('/health')
    assert r.status_code == 503 and r.json() == {'detail': 'integrity check failed'} and 'differ' not in r.text


def test_b5_integrity_verification_is_single_flight_and_cached(monkeypatch):
    calls = []; real = gw._full_verification
    monkeypatch.setattr(gw, '_full_verification', lambda: (calls.append(1), real())[1])
    monkeypatch.setattr(gw, 'INTEGRITY_CACHE_SECONDS', 60); gw._integrity_cache.update(ok=False, at=None)
    for _ in range(25): assert CLIENT.get('/health').status_code == 200
    assert len(calls) == 1
    assert CLIENT.get('/v1/audit/verify', headers=HEAD).status_code == 200 and len(calls) == 2  # authenticated verify always forces a fresh run


def test_b5_verification_is_consistent_under_concurrent_writes():
    stop = threading.Event(); errors = []
    def writer():
        c = TestClient(gw.app)
        try:
            for _ in range(12):
                task = eid('cw'); body = {'event_id': eid('reg'), 'task_id': task, 'protocol_hash': gw.protocol_hash(), 'agent': 'ChatGPT', 'original_instruction': 'x', 'acceptance_criteria': ['all steps evidenced'], 'steps': [{'step_key': '01', 'title': 'P', 'acceptance_criteria': ['parent criterion']}, {'step_key': '01.01', 'title': 'C', 'acceptance_criteria': [CRIT]}]}
                r = c.post('/v1/tasks/register', headers=HEAD, json=body); assert r.status_code == 200, r.text
                ch = r.json()['contract_hash']; ref = step_ref(task, 'PRE_EXECUTION', 0)
                r = raw_eval(task, ch, 0, claims=[claim(ref)], client=c); assert r.status_code == 200, r.text
        except Exception as e:  # noqa
            errors.append(repr(e))
        finally:
            stop.set()
    t = threading.Thread(target=writer); t.start(); runs = 0
    while not stop.is_set():
        assert gw._full_verification() is True; runs += 1
    t.join(); assert not errors, errors; assert runs >= 1 and gw._full_verification() is True


# ---------------- B6: failed POST is retried on the same gate ----------------
def test_b6_failed_post_retries_on_same_gate_without_new_pre():
    task, ch = register(); pre, _ = do_pre(task, ch, 0)
    bad, _ = do_post(task, ch, pre, stdout='NOTHING'); assert bad.status_code == 200 and bad.json()['verdict'] == 'UNVERIFIED'
    assert bad.json()['gate_checkpoint_no'] == pre.json()['gate_checkpoint_no']
    st = CLIENT.get(f'/v1/tasks/{task}/state', headers=HEAD).json(); assert st['pending_execution_gate']['pre_checkpoint_no'] == 1
    ok, _ = do_post(task, ch, pre, req_cp=bad.json()['checkpoint_no']); assert ok.status_code == 200 and ok.json()['verdict'] == 'VERIFIED_PASS' and ok.json()['gate_checkpoint_no'] == 1
    c = gw.conn(); g = c.execute('SELECT consumed,post_checkpoint_no FROM execution_gates WHERE task_id=?', (task,)).fetchone(); assert g['consumed'] == 1 and g['post_checkpoint_no'] == ok.json()['checkpoint_no']; assert gw.verify_materialized_state(c); c.close()


def test_b6_hitl_not_required_again_for_post_retry():
    task, ch = register(); action = e3_action(); pre, _ = do_pre(task, ch, 0, action=action, headers=HITL)
    bad, _ = do_post(task, ch, pre, action=action, stdout='NOTHING'); assert bad.json()['verdict'] == 'UNVERIFIED'
    ok, _ = do_post(task, ch, pre, action=action, req_cp=bad.json()['checkpoint_no']); assert ok.json()['verdict'] == 'VERIFIED_PASS'


def test_b6_new_failed_pre_supersedes_ready_gate():
    task, ch = register(); pre, _ = do_pre(task, ch, 0)
    bad = raw_eval(task, ch, 1, claims=[{'criterion_index': 0, 'claim': CRIT, 'evidence': [manual()]}]); assert bad.json()['verdict'] == 'UNVERIFIED'
    r, _ = do_post(task, ch, pre, req_cp=bad.json()['checkpoint_no']); assert r.status_code == 409 and r.json()['detail']['code'] == 'PRE_EXECUTION_NOT_READY'


def test_b6_post_cannot_consume_gate_twice_or_after_verification():
    task, ch = register(); pre, _ = do_pre(task, ch, 0); ok, _ = do_post(task, ch, pre); assert ok.json()['step_verified']
    again = raw_eval(task, ch, ok.json()['checkpoint_no'], claims=[claim(step_ref(task, 'POST_EXECUTION', 1))], phase='POST_EXECUTION'); assert again.status_code == 409


# ---------------- B7: secrets ----------------
@pytest.mark.parametrize('bad', ['<generate-at-least-32-random-bytes>', 'A' * 32, 'x' * 64, 'short', 'changeme-changeme-changeme-changeme12345', 'abcdefabcdefabcdefabcdefabcdefabcdefabcdef', 'has space in it ' * 4, 'ünïcödé-ünïcödé-ünïcödé-ünïcödé-12345678'])
def test_b7_weak_or_placeholder_secrets_rejected(bad):
    with pytest.raises(RuntimeError): gw.validate_secret('k', bad)


def test_b7_generated_secrets_accepted():
    import secrets
    for _ in range(50): gw.validate_secret('k', secrets.token_urlsafe(48))
    out = subprocess.run([sys.executable, str(ROOT / 'tools' / 'generate_secrets.py')], capture_output=True, text=True, check=True).stdout.strip().splitlines()
    assert len(out) == 3 and len({l.split('=', 1)[1] for l in out}) == 3
    for l in out: gw.validate_secret(l.split('=')[0], l.split('=', 1)[1])


def test_b7_env_example_contains_no_usable_placeholder_secrets():
    values = dict(l.split('=', 1) for l in (ROOT / '.env.example').read_text().splitlines() if l and not l.startswith('#') and '=' in l)
    for k in ('EVALUATION_GATEWAY_API_KEY', 'EVALUATION_GATEWAY_HITL_KEY', 'EVALUATION_GATEWAY_AUDIT_HMAC_KEY', 'EVALUATION_GATEWAY_EVIDENCE_PUBLIC_KEY_B64'): assert values[k] == ''


def test_b7_require_config_rejects_weak_configured_keys(monkeypatch):
    monkeypatch.setattr(gw, 'API_KEY', 'A' * 40)
    with pytest.raises(RuntimeError): gw.require_config()
    assert CLIENT.get('/health').status_code == 503


# ---------------- B8: matcher is signed, never client-supplied ----------------
def test_b8_client_supplied_matcher_is_rejected_by_schema():
    task, ch = register(); ref = step_ref(task, 'PRE_EXECUTION', 0)
    cl = {'criterion_index': 0, 'claim': CRIT, 'evidence': [{**evp(ref), 'matcher': {'kind': 'not_contains', 'value': 'zzz-random'}}]}
    assert raw_eval(task, ch, 0, claims=[cl]).status_code == 422


def test_b8_signed_matcher_decides_support():
    task, ch = register(); ref = notarized(eid('knid-task'), stdout='SOMETHING=ELSE', bindings=[sb(task, '01.01', 0, CRIT, 'PRE_EXECUTION', 0, 'CHECK=PASS')])
    r = raw_eval(task, ch, 0, claims=[claim(ref)]); assert r.json()['verdict'] == 'UNVERIFIED' and any('refutes signed matcher' in n['note'] for n in r.json()['evidence_notes'])
    task2, ch2 = register(); ref2 = notarized(eid('knid-task'), stdout='SOMETHING=ELSE', bindings=[sb(task2, '01.01', 0, CRIT, 'PRE_EXECUTION', 0, 'CHECK=FAIL', 'not_contains')])
    assert raw_eval(task2, ch2, 0, claims=[claim(ref2)]).json()['verdict'] == 'READY_TO_EXECUTE'


def test_b8_invalid_or_ambiguous_signed_matcher_rejected():
    task, ch = register(); b = sb(task, '01.01', 0, CRIT, 'PRE_EXECUTION', 0); b['matcher'] = {'kind': 'regex', 'value': '.*'}
    ref = notarized(eid('knid-task'), bindings=[b]); assert any('matcher missing/invalid' in n['note'] for n in raw_eval(task, ch, 0, claims=[claim(ref)]).json()['evidence_notes'])
    task2, ch2 = register(); b1 = sb(task2, '01.01', 0, CRIT, 'PRE_EXECUTION', 0, 'CHECK=PASS'); b2 = sb(task2, '01.01', 0, CRIT, 'PRE_EXECUTION', 0, 'CHECK')
    ref2 = notarized(eid('knid-task'), bindings=[b1, b2]); assert any('ambiguous' in n['note'] for n in raw_eval(task2, ch2, 0, claims=[claim(ref2)]).json()['evidence_notes'])


def _run_notary(tmp, stdout, bindings, status='PASS', exit_code=0):
    sid = eid('knid-task'); d = tmp / sid; d.mkdir(parents=True)
    (d / 'state.json').write_text(json.dumps({'task_id': sid, 'status': status, 'exit_code': exit_code, 'finished_at': time.time()}))
    (d / 'stdout.log').write_text(stdout); key = tmp / 'k.pem'; key.write_bytes(H.PRIV_PEM); bp = tmp / 'b.json'; bp.write_text(json.dumps(bindings))
    return sid, d, subprocess.run([sys.executable, str(ROOT / 'tools' / 'notarize_evidence.py'), str(key), str(d), str(bp)], capture_output=True, text=True)


def test_b8_notary_tool_signs_valid_bindings_and_gateway_accepts(tmp_path):
    task, ch = register(); b = sb(task, '01.01', 0, CRIT, 'PRE_EXECUTION', 0)
    sid, d, p = _run_notary(tmp_path, 'CHECK=PASS\n', [b]); assert p.returncode == 0, p.stderr
    shutil.move(str(d), str(RUNTIME / 'evidence' / sid)); (RUNTIME / 'evidence' / sid).chmod(0o700)
    r = raw_eval(task, ch, 0, claims=[claim(sid)]); assert r.json()['verdict'] == 'READY_TO_EXECUTE', r.text


def test_b8_notary_tool_refuses_to_sign_false_or_malformed_attestations(tmp_path):
    task, _ = register(); good = sb(task, '01.01', 0, CRIT, 'PRE_EXECUTION', 0)
    assert _run_notary(tmp_path, 'nothing here', [good])[2].returncode != 0
    assert _run_notary(tmp_path, 'CHECK=PASS', [good], status='FAIL')[2].returncode != 0
    assert _run_notary(tmp_path, 'CHECK=PASS', [good], exit_code=1)[2].returncode != 0
    legacy = {k: v for k, v in good.items() if k not in ('phase', 'checkpoint_no')}
    assert _run_notary(tmp_path, 'CHECK=PASS', [legacy])[2].returncode != 0
    assert _run_notary(tmp_path, 'CHECK=PASS', [{**good, 'phase': 'POST_EXECUTION', 'kind': 'task_criterion'}])[2].returncode != 0
    assert _run_notary(tmp_path, 'CHECK=PASS', [{**good, 'matcher': {'kind': 'contains', 'value': ' '}}])[2].returncode != 0


# ---------------- low-severity items ----------------
def test_low_evidence_directory_and_root_must_not_be_writable(monkeypatch):
    task, ch = register(); ref = step_ref(task, 'PRE_EXECUTION', 0); d = RUNTIME / 'evidence' / ref; d.chmod(0o770)
    r = raw_eval(task, ch, 0, claims=[claim(ref)]); assert r.json()['verdict'] == 'UNVERIFIED' and any('directory missing or unsafe' in n['note'] for n in r.json()['evidence_notes'])
    d.chmod(0o700); root = RUNTIME / 'evidence'
    try:
        root.chmod(0o775)
        with pytest.raises(RuntimeError, match='evidence root'): gw.require_config()
    finally: root.chmod(0o755)
    gw.require_config()


def test_low_state_guidance_reflects_blockers():
    task, ch = register(); st = CLIENT.get(f'/v1/tasks/{task}/state', headers=HEAD).json(); assert st['next_action'] == 'EXECUTE_OR_EVALUATE' and st['blocked_reason'] is None and st['terminal'] is False
    cp = induce_three_failures(task, ch); st = CLIENT.get(f'/v1/tasks/{task}/state', headers=HEAD).json(); assert st['next_action'] == 'REGISTER_REMEDIAL' and st['blocked_reason'] == 'REMEDIAL_ESCALATION_REQUIRED'
    rem, rr = register_remedial(task, cp); assert rr.status_code == 200
    st = CLIENT.get(f'/v1/tasks/{task}/state', headers=HEAD).json(); assert st['next_action'] == 'COMPLETE_REMEDIAL' and st['remedial_task_id'] == rem and st['blocked_reason'] == 'ORIGINAL_TASK_BLOCKED_BY_REMEDIAL'
    complete_remedial(rem, rr.json()['contract_hash']); st = CLIENT.get(f'/v1/tasks/{task}/state', headers=HEAD).json(); assert st['next_action'] == 'EXECUTE_OR_EVALUATE'
    done, dch = register(); H.finish_normal(done, dch); st = CLIENT.get(f'/v1/tasks/{done}/state', headers=HEAD).json(); assert st['next_action'] == 'STOP' and st['terminal'] is True


def test_low_remedial_step_exhaustion_guidance():
    task, ch = register(); cp = induce_three_failures(task, ch); rem, rr = register_remedial(task, cp); rch = rr.json()['contract_hash']; c = 0
    for _ in range(3):
        r = raw_eval(rem, rch, c, step='01.01', claims=[{'criterion_index': 0, 'claim': '01.01 evidenced', 'evidence': [manual()]}]); c = r.json()['checkpoint_no']
    st = CLIENT.get(f'/v1/tasks/{rem}/state', headers=HEAD).json(); assert st['next_action'] == 'SUBMIT_EXHAUSTED_DISPOSITION' and st['blocked_reason'] == 'REMEDIAL_STEP_EXHAUSTED'


def _abort(task, ch, cp, headers=HITL, event=None, reason='unprovable; stopping'):
    return CLIENT.post(f'/v1/tasks/{task}/abort', headers=headers, json={'event_id': event or eid('abort'), 'contract_hash': ch, 'protocol_hash': gw.protocol_hash(), 'checkpoint_no': cp, 'reason': reason})


def test_low_abort_requires_hitl_and_terminates_task_with_audit():
    task, ch = register(); assert _abort(task, ch, 0, headers=HEAD).status_code == 403
    assert _abort(task, ch, 7, headers=HITL).status_code == 409
    ev_id = eid('abort'); r = _abort(task, ch, 0, event=ev_id); assert r.status_code == 200 and r.json()['contract_status'] == 'ABORTED'
    assert _abort(task, ch, 0, event=ev_id).json()['idempotent_replay'] is True
    assert _abort(task, ch, 0).status_code == 409
    ref = step_ref(task, 'PRE_EXECUTION', 0); assert raw_eval(task, ch, 0, claims=[claim(ref)]).status_code == 409
    st = CLIENT.get(f'/v1/tasks/{task}/state', headers=HEAD).json(); assert st['terminal'] and st['next_action'] == 'STOP' and st['status'] == 'TASK_ABORTED'
    c = gw.conn(); assert gw.verify_materialized_state(c); done_at = c.execute('SELECT completed_at FROM task_registry WHERE task_id=?', (task,)).fetchone()[0]
    c.execute("UPDATE task_registry SET contract_status='OPEN',status='REGISTERED',completed_at=NULL WHERE task_id=?", (task,)); assert not gw.verify_materialized_state(c)
    c.execute("UPDATE task_registry SET contract_status='ABORTED',status='TASK_ABORTED',completed_at=? WHERE task_id=?", (done_at, task)); assert gw.verify_materialized_state(c); c.close()
    assert CLIENT.get('/v1/audit/verify', headers=HEAD).status_code == 200


def test_low_abort_of_blocked_remedial_unlocks_new_attempt_and_original_abort_needs_it_first():
    task, ch = register(); cp = induce_three_failures(task, ch); rem, rr = register_remedial(task, cp); assert rr.status_code == 200
    assert _abort(task, ch, cp).status_code == 409 and _abort(task, ch, cp).json()['detail']['code'] == 'ABORT_REMEDIAL_FIRST'
    assert _abort(rem, rr.json()['contract_hash'], 0).status_code == 200
    rem2, rr2 = register_remedial(task, cp, attempt=2); assert rr2.status_code == 200, rr2.text
    c = gw.conn(); assert gw.verify_materialized_state(c); c.close()


def test_low_database_busy_maps_to_503_with_retry_after(monkeypatch):
    import sqlite3
    task, ch = register(); ref = step_ref(task, 'PRE_EXECUTION', 0)
    blocker = gw.conn(); blocker.execute('BEGIN IMMEDIATE')
    real = gw.conn
    def quick():
        c = sqlite3.connect(gw.DB_PATH, timeout=0.05, isolation_level=None); c.row_factory = sqlite3.Row; return c
    monkeypatch.setattr(gw, 'conn', quick)
    try:
        r = SOFT.post('/v1/evaluate', headers=HEAD, json={'event_id': eid('e'), 'task_id': task, 'contract_hash': ch, 'protocol_hash': gw.protocol_hash(), 'checkpoint_no': 0, 'step_key': '01.01', 'agent': 'ChatGPT', 'phase': 'PRE_EXECUTION', 'claims': [claim(ref)]})
        assert r.status_code == 503 and r.headers.get('retry-after') == '1'
    finally:
        blocker.rollback(); blocker.close(); monkeypatch.setattr(gw, 'conn', real)
    assert raw_eval(task, ch, 0, claims=[claim(ref)]).status_code == 200


def test_low_extra_fields_rejected_everywhere():
    body = {'event_id': eid('r'), 'task_id': eid('t'), 'protocol_hash': gw.protocol_hash(), 'agent': 'a', 'original_instruction': 'x', 'acceptance_criteria': ['g'], 'unexpected': 1, 'steps': [{'step_key': '01', 'title': 'p', 'acceptance_criteria': ['c']}, {'step_key': '01.01', 'title': 'c', 'acceptance_criteria': ['c']}]}
    assert CLIENT.post('/v1/tasks/register', headers=HEAD, json=body).status_code == 422


def test_low_no_connection_leak_on_unexpected_error(monkeypatch):
    monkeypatch.setattr(gw, 'protocol_hash', lambda: (_ for _ in ()).throw(RuntimeError('boom')))
    assert SOFT.get('/health').status_code in (200, 503)


# ---------------- consistency of version / legacy leftovers ----------------
def test_version_is_single_sourced_and_consistent():
    v = (ROOT / 'VERSION').read_text().strip(); assert gw.APP_VERSION == v
    assert f'evaluation-gateway-local:{v}' in (ROOT / 'docker-compose.yml').read_text()
    assert f'EXECUTOR PROTOCOL {gw.PROTOCOL_VERSION}' in (ROOT / 'docs' / 'EXECUTOR_PROTOCOL.md').read_text().upper()
    assert 'COPY VERSION' in (ROOT / 'Dockerfile').read_text()
    assert CLIENT.get('/v1/protocol', headers=HEAD).json()['version'] == gw.PROTOCOL_VERSION


def test_no_legacy_artifacts_or_hardcoded_leftovers():
    skip = {'CHANGELOG.md', 'HARDENING_REPORT.md'}
    stale = ['legacy_mode', 'max_age_seconds', 'MAX_EVIDENCE_STATE_BYTES', 'MAX_EVIDENCE_META_BYTES', 'MAX_EVIDENCE_BYTES', 'criterion_binding', 'manifest v3', 'chown -R gateway:gateway /app', '2.2.0']
    for p in ROOT.rglob('*'):
        if not p.is_file() or '_runtime' in p.parts or '__pycache__' in p.parts or p.name in skip or p.suffix in ('.pyc',) or p.name in ('test_v3_regressions.py', 'live_e2e.py') or p.name == 'MANIFEST.sha256': continue
        text = p.read_text(errors='ignore')
        for s in stale: assert s not in text, f'{s!r} found in {p.relative_to(ROOT)}'
    assert not (ROOT / 'schema_mysql.sql').exists() and not (ROOT / 'baseline').exists()
    assert not list((ROOT / 'docs').glob('LOCAL_*REHARDENING_*'))
    df = (ROOT / 'Dockerfile').read_text(); assert 'chown gateway:gateway /data /evidence /anchor' in df and '/app' not in df.split('chown')[1].split('\n')[0]
    assert 'gateway_anchor:/anchor' in (ROOT / 'docker-compose.yml').read_text()


def test_anchor_write_io_failure_is_fail_closed_and_requires_offline_recovery(monkeypatch):
    """A committed DB mutation must never appear successful if its anchor cannot persist."""
    original_write = gw.write_anchor
    original = H.ANCHOR.read_bytes()
    task = eid('iofail')
    body = {'event_id': eid('reg'), 'task_id': task, 'protocol_hash': gw.protocol_hash(), 'agent': 'a', 'original_instruction': 'x', 'acceptance_criteria': ['g'], 'steps': [{'step_key': '01', 'title': 'p', 'acceptance_criteria': ['c']}, {'step_key': '01.01', 'title': 'c', 'acceptance_criteria': ['c']}]}
    def disk_failure(*args, **kwargs):
        raise OSError('injected audit anchor EIO')
    monkeypatch.setattr(gw, 'write_anchor', disk_failure)
    try:
        first = SOFT.post('/v1/tasks/register', headers=HEAD, json=body)
        assert first.status_code == 503
        assert H.ANCHOR.read_bytes() == original
        assert SOFT.post('/v1/tasks/register', headers=HEAD, json={**body, 'event_id': eid('second'), 'task_id': eid('second-task')}).status_code == 503
        assert CLIENT.get('/health').status_code == 503
        assert CLIENT.get('/v1/audit/verify', headers=HEAD).status_code == 409
    finally:
        monkeypatch.setattr(gw, 'write_anchor', original_write)
        # Recovery is an explicit offline operator action, never automatic runtime mutation.
        c = gw.conn()
        try:
            assert gw.verify_audit_chain(c)
            assert gw.verify_materialized_state(c)
            seq, head = gw.db_head(c)
        finally:
            c.close()
        original_write(seq, head)
    assert CLIENT.get('/health').status_code == 200
