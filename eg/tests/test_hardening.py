"""Core hardening regression suite (ported to signed binding manifest v4)."""
import asyncio, json, shutil, sqlite3, stat
import pytest
import harness as H
from harness import gw, CLIENT, HEAD, HITL, RUNTIME, CRIT, eid, claim, evp, manual, notarized, register, raw_eval, step_ref, task_claim, do_pre, do_post, e2_action, e3_action, finish_normal, induce_three_failures, register_remedial, complete_remedial, sb, tb


def test_01_health_minimal_and_audit_verify_detailed():
    r = CLIENT.get('/health'); assert r.status_code == 200 and r.json() == {'status': 'PASS'}
    a = CLIENT.get('/v1/audit/verify', headers=HEAD).json()
    assert a['status'] == 'PASS' and a['version'] == gw.APP_VERSION and a['chain'] == 'AUTHENTICATED_VALID' and a['anchor'] == 'VALID' and a['materialized_state'] == 'VALID' and a['evidence_policy'] == 'NOTARIZED_ONLY' and a['hitl_policy'] == 'SEPARATE_KEY_REQUIRED'


def test_02_docs_and_openapi_disabled():
    for p in ('/docs', '/redoc', '/openapi.json'):
        assert CLIENT.get(p).status_code == 404


def test_03_protocol_mismatch_registration_blocked():
    body = {'event_id': eid('reg'), 'task_id': eid('task'), 'protocol_hash': '0' * 64, 'agent': 'ChatGPT', 'original_instruction': 'x', 'acceptance_criteria': ['x'], 'steps': [{'step_key': '01', 'title': 'p', 'acceptance_criteria': ['p'],"execution_required":False}, {'step_key': '01.01', 'title': 'c', 'acceptance_criteria': ['c'],"execution_required":False}]}
    assert CLIENT.post('/v1/tasks/register', headers=HEAD, json=body).status_code == 428


def test_04_empty_claims_cannot_pass():
    task, ch = register(); assert raw_eval(task, ch, 0, claims=[]).status_code == 422


def test_05_manual_evidence_never_authoritative():
    task, ch = register(); r = raw_eval(task, ch, 0, claims=[{'criterion_index': 0, 'claim': CRIT, 'evidence': [manual()]}])
    assert r.status_code == 200 and r.json()['verdict'] == 'UNVERIFIED' and not r.json()['step_verified']


def test_06_forged_notary_signature_blocked():
    task, ch = register(); ref = step_ref(task, 'PRE_EXECUTION', 0, bad_sig=True); r = raw_eval(task, ch, 0, claims=[claim(ref)])
    assert r.status_code == 200 and r.json()['verdict'] == 'UNVERIFIED'


def test_07_tampered_stdout_blocked():
    task, ch = register(); ref = step_ref(task, 'PRE_EXECUTION', 0); p = RUNTIME / 'evidence' / ref / 'stdout.log'; p.write_text('CHECK=PASS\nTAMPERED'); p.chmod(0o600)
    r = raw_eval(task, ch, 0, claims=[claim(ref)]); assert r.status_code == 200 and r.json()['verdict'] == 'UNVERIFIED'


def test_08_stale_evidence_blocked():
    task, ch = register(); ref = step_ref(task, 'PRE_EXECUTION', 0, age=gw.EVIDENCE_MAX_AGE_SECONDS + 700)
    r = raw_eval(task, ch, 0, claims=[claim(ref)]); assert r.status_code == 200 and r.json()['verdict'] == 'UNVERIFIED' and any('stale' in n['note'] for n in r.json()['evidence_notes'])


def test_09_oversized_evidence_blocked():
    task, ch = register(); ref = step_ref(task, 'PRE_EXECUTION', 0, stdout='CHECK=PASS\n' + ('X' * (gw.MAX_EVIDENCE_FILE_BYTES + 100)))
    r = raw_eval(task, ch, 0, claims=[claim(ref)]); assert r.status_code == 200 and r.json()['verdict'] == 'UNVERIFIED' and any('too large' in n['note'] for n in r.json()['evidence_notes'])


def test_10_all_acceptance_criteria_must_be_covered():
    task, ch = register(criteria_child=['criterion A', 'criterion B']); ref = step_ref(task, 'PRE_EXECUTION', 0, criteria=[(0, 'criterion A')])
    r = raw_eval(task, ch, 0, claims=[claim(ref, 0, 'criterion A')]); assert r.status_code == 409 and r.json()['detail']['code'] == 'ACCEPTANCE_COVERAGE_INCOMPLETE'


def test_11_wrong_hierarchy_step_blocked():
    task, ch = register(); ref = step_ref(task, 'PRE_EXECUTION', 0, step='01'); r = raw_eval(task, ch, 0, step='01', claims=[claim(ref)])
    assert r.status_code == 409 and r.json()['detail']['code'] == 'STEP_SEQUENCE_VIOLATION'


def test_12_post_without_pre_is_blocked():
    task, ch = register(); ref = step_ref(task, 'POST_EXECUTION', 1); r = raw_eval(task, ch, 0, claims=[claim(ref)], phase='POST_EXECUTION')
    assert r.status_code == 409 and r.json()['detail']['code'] == 'PRE_EXECUTION_REQUIRED'


def test_13_ready_pre_then_bound_post_verifies_step():
    task, ch = register(); pre, _ = do_pre(task, ch, 0); assert pre.json()['verdict'] == 'READY_TO_EXECUTE' and not pre.json()['step_verified'] and pre.json()['gate_checkpoint_no'] == 1
    post, _ = do_post(task, ch, pre); assert post.status_code == 200
    j = post.json(); assert j['verdict'] == 'VERIFIED_PASS' and j['step_verified'] and j['checkpoint_no'] == 2 and j['gate_checkpoint_no'] == 1


def test_14_stale_checkpoint_rejected_after_pre():
    task, ch = register(); pre, _ = do_pre(task, ch, 0); r, _ = do_post(task, ch, pre, req_cp=0)
    assert r.status_code == 409 and r.json()['detail']['code'] == 'STALE_CHECKPOINT'


def test_15_finalize_before_all_steps_blocked_and_post_rolled_back():
    task, ch = register(); pre, _ = do_pre(task, ch, 0); r, _ = do_post(task, ch, pre, finalize=True); assert r.status_code == 409
    d = CLIENT.get(f'/v1/tasks/{task}', headers=HEAD).json(); child = [s for s in d['steps'] if s['step_key'] == '01.01'][0]
    assert child['verified'] == 0 and d['task']['checkpoint_no'] == 1


def test_16_e2_without_proofs_blocked():
    task,ch=register(physical=True)
    action={'action_type':'write','target':str(H.WORKER_OUTPUT/'without-proof.txt'),
            'effect_class':'E2','reversible':True,'real_world_effect':False,
            'payload_sha256':'a'*64,'payload_bytes':1,'proofs':[]}
    r,_=do_pre(task,ch,0,action=action)
    assert r.json()['verdict']=='UNVERIFIED'


def test_17_e2_with_action_bound_notarized_proofs_ready_and_post_passes():
    task, ch = register(physical=True); action = e2_action(task, 0)
    pre, _ = do_pre(task, ch, 0, action=action); assert pre.json()['verdict'] == 'READY_TO_EXECUTE', pre.text
    post, _ = do_post(task, ch, pre, action=action); assert post.status_code == 200 and post.json()['verdict'] == 'VERIFIED_PASS'


def test_18_action_mutation_between_pre_and_post_blocked():
    task, ch = register(physical=True); action = e2_action(task, 0, target='target-a')
    pre, _ = do_pre(task, ch, 0, action=action); assert pre.json()['verdict'] == 'READY_TO_EXECUTE'
    post, _ = do_post(task, ch, pre, action={**action, 'target': 'target-b'}); assert post.status_code == 409 and post.json()['detail']['code'] == 'ACTION_FINGERPRINT_MISMATCH'


def test_19_e3_without_registered_adapter_refused():
    task,ch=register();act=e3_action()
    r=raw_eval(task,ch,0,claims=[claim(step_ref(task,'PRE_EXECUTION',0))],action=act)
    assert r.status_code==409 and r.json()['detail']['code']=='UNSUPPORTED_ACTION_CAPABILITY_FAIL_CLOSED'


def test_20_hitl_not_a_missing_executor_adapter():
    task,ch=register();act=e3_action()
    r=raw_eval(task,ch,0,claims=[claim(step_ref(task,'PRE_EXECUTION',0))],action=act,headers=HITL)
    assert r.status_code==409 and r.json()['detail']['code']=='UNSUPPORTED_ACTION_CAPABILITY_FAIL_CLOSED'


def test_21_hitl_key_must_differ_from_api_key(monkeypatch):
    monkeypatch.setattr(gw, 'HITL_KEY', gw.API_KEY)
    with pytest.raises(RuntimeError, match='must differ'): gw.require_config()
    assert CLIENT.get('/health').status_code == 503


def test_22_real_world_e2_not_supported_by_bounded_worker():
    task,ch=register()
    action={'action_type':'write','target':str(H.WORKER_OUTPUT/'real.txt'),'effect_class':'E2','reversible':True,'real_world_effect':True,
            'payload_sha256':'a'*64,'payload_bytes':1,'proofs':[]}
    r=raw_eval(task,ch,0,claims=[claim(step_ref(task,'PRE_EXECUTION',0))],action=action,headers=HITL)
    assert r.status_code==409 and r.json()['detail']['code']=='UNSUPPORTED_ACTION_CAPABILITY_FAIL_CLOSED'


def test_23_full_task_finalizes_only_with_global_criteria_verified():
    task, ch = register(); ppost = finish_normal(task, ch); assert ppost.status_code == 200 and ppost.json()['contract_status'] == 'SATISFIED'


def test_24_event_id_replay_idempotent_and_mismatch_blocked():
    task, ch = register(); ref = step_ref(task, 'PRE_EXECUTION', 0); event = eid('eval'); claims = [claim(ref)]
    r = raw_eval(task, ch, 0, claims=claims, event=event); assert r.status_code == 200
    rr = raw_eval(task, ch, 0, claims=claims, event=event); assert rr.status_code == 200 and rr.json()['idempotent_replay'] is True
    assert raw_eval(task, ch, 0, claims=[claim(ref, 0, 'different claim')], event=event).status_code == 409


def test_25_audit_hash_chain_detects_simple_tamper():
    c = gw.conn(); row = c.execute('SELECT seq,response_json FROM audit ORDER BY seq DESC LIMIT 1').fetchone(); original = row['response_json']; c.execute('UPDATE audit SET response_json=? WHERE seq=?', ('{"tampered":true}', row['seq'])); c.close()
    assert CLIENT.get('/v1/audit/verify', headers=HEAD).status_code == 409
    c = gw.conn(); c.execute('UPDATE audit SET response_json=? WHERE seq=?', (original, row['seq'])); assert gw.verify_audit_chain(c); c.close()


def test_26_materialized_contract_tamper_detected():
    task, ch = register(); c = gw.conn(); orig = c.execute('SELECT original_instruction FROM task_registry WHERE task_id=?', (task,)).fetchone()[0]
    c.execute('UPDATE task_registry SET original_instruction=? WHERE task_id=?', ('tampered', task)); assert not gw.verify_materialized_state(c)
    c.execute('UPDATE task_registry SET original_instruction=? WHERE task_id=?', (orig, task)); assert gw.verify_materialized_state(c); c.close()


def test_27_request_size_limit():
    payload = b'{' + b'"x":"' + b'A' * (gw.MAX_REQUEST_BYTES + 100) + b'"}'
    assert CLIENT.post('/v1/tasks/register', headers={**HEAD, 'content-type': 'application/json'}, content=payload).status_code == 413


def test_28_three_failures_force_remedial_escalation():
    task, ch = register(); cp = induce_three_failures(task, ch); ref = step_ref(task, 'PRE_EXECUTION', cp); r = raw_eval(task, ch, cp, claims=[claim(ref)])
    assert r.status_code == 409 and r.json()['detail']['code'] == 'REMEDIAL_ESCALATION_REQUIRED'


def test_29_linked_remedial_registration_and_original_freeze():
    task, ch = register(); cp = induce_three_failures(task, ch); rem, rr = register_remedial(task, cp); assert rr.status_code == 200, rr.text
    ref = step_ref(task, 'PRE_EXECUTION', cp); r = raw_eval(task, ch, cp, claims=[claim(ref)]); assert r.status_code == 409 and r.json()['detail']['code'] == 'ORIGINAL_TASK_BLOCKED_BY_REMEDIAL'


def test_30_nested_remedial_forbidden():
    task, ch = register(); cp = induce_three_failures(task, ch); rem, rr = register_remedial(task, cp); assert rr.status_code == 200
    body = {'event_id': eid('nested'), 'task_id': eid('nested-rem'), 'protocol_hash': gw.protocol_hash(), 'task_kind': 'REMEDIAL', 'remedial_for_task_id': rem, 'remedial_trigger_step_key': '01.01', 'remedial_origin_checkpoint_no': 0, 'remedial_attempt': 1, 'agent': 'ChatGPT', 'original_instruction': 'nested forbidden', 'acceptance_criteria': ['x'], 'steps': H.remedial_steps()}
    r = CLIENT.post('/v1/tasks/register', headers=HEAD, json=body); assert r.status_code == 409 and r.json()['detail']['code'] == 'NESTED_REMEDIAL_FORBIDDEN'


def test_31_verified_remedial_recovery_allows_original_resume():
    task, ch = register(); origin_cp = induce_three_failures(task, ch); rem, rr = register_remedial(task, origin_cp); assert rr.status_code == 200
    complete_remedial(rem, rr.json()['contract_hash'])
    pre, _ = do_pre(task, ch, origin_cp); assert pre.status_code == 200 and pre.json()['verdict'] == 'READY_TO_EXECUTE'
    post, _ = do_post(task, ch, pre); assert post.status_code == 200 and post.json()['verdict'] == 'VERIFIED_PASS'


def test_32_streamed_request_without_content_length_is_bounded():
    body1 = b'x' * 600_000; body2 = b'y' * 500_001
    scope = {'type': 'http', 'asgi': {'version': '3.0'}, 'http_version': '1.1', 'method': 'POST', 'scheme': 'http', 'path': '/v1/tasks/register', 'raw_path': b'/v1/tasks/register', 'query_string': b'', 'headers': [(b'content-type', b'application/json'), (b'x-evaluation-key', H.API_KEY.encode())], 'client': ('127.0.0.1', 12345), 'server': ('127.0.0.1', 18765)}
    incoming = [{'type': 'http.request', 'body': body1, 'more_body': True}, {'type': 'http.request', 'body': body2, 'more_body': False}]; sent = []
    async def receive(): return incoming.pop(0)
    async def send(message): sent.append(message)
    asyncio.run(gw.app(scope, receive, send)); starts = [m for m in sent if m.get('type') == 'http.response.start']; assert starts and starts[0]['status'] == 413, sent


def test_33_database_file_mode_is_0600_and_wal():
    gw.init_db(); assert stat.S_IMODE(gw.DB_PATH.stat().st_mode) == 0o600
    c = gw.conn(); assert c.execute('PRAGMA journal_mode').fetchone()[0].lower() == 'wal'; c.close()


def test_34_same_notarized_evidence_can_materialize_multiple_criteria_without_collision():
    task, ch = register(criteria_child=['criterion A', 'criterion B']); crit = [(0, 'criterion A'), (1, 'criterion B')]
    pre, _ = do_pre(task, ch, 0, criteria=crit, stdout='MULTI=PASS', value='MULTI=PASS'); assert pre.json()['verdict'] == 'READY_TO_EXECUTE', pre.text
    post, _ = do_post(task, ch, pre, criteria=crit, stdout='MULTI=PASS', value='MULTI=PASS'); assert post.json()['verdict'] == 'VERIFIED_PASS', post.text
    c = gw.conn(); got = {r[0] for r in c.execute("SELECT criterion_index FROM evidence_records WHERE task_id=? AND step_key='01.01' AND criterion_index>=0", (task,))}; assert got == {0, 1}, got; assert gw.verify_materialized_state(c); c.close()


def test_35_metadata_bounds_and_read_only_state():
    task, ch = register(); state = CLIENT.get(f'/v1/tasks/{task}/state', headers=HEAD); assert state.status_code == 200; before = state.json(); assert before['state_version'] == 0 and before['current_step'] == '01.01'
    ref = step_ref(task, 'PRE_EXECUTION', 0); p = RUNTIME / 'evidence' / ref / 'state.json'; p.write_bytes(b'{' + b'"x":"' + b'A' * (gw.MAX_EVIDENCE_FILE_BYTES + 1) + b'"}'); p.chmod(0o600)
    r = raw_eval(task, ch, 0, claims=[claim(ref)]); assert r.status_code == 200 and r.json()['verdict'] == 'UNVERIFIED' and any('state too large' in n['note'] for n in r.json()['evidence_notes'])
    task2, ch2 = register(); ref2 = step_ref(task2, 'PRE_EXECUTION', 0); p2 = RUNTIME / 'evidence' / ref2 / 'evidence.json'; p2.write_bytes(b'{' + b'"x":"' + b'B' * (gw.MAX_EVIDENCE_FILE_BYTES + 1) + b'"}'); p2.chmod(0o600)
    r2 = raw_eval(task2, ch2, 0, claims=[claim(ref2)]); assert r2.status_code == 200 and r2.json()['verdict'] == 'UNVERIFIED' and any('metadata too large' in n['note'] for n in r2.json()['evidence_notes'])
    after = CLIENT.get(f'/v1/tasks/{task}/state', headers=HEAD); assert after.status_code == 200 and after.json()['state_version'] == 1 and after.json()['latest_checkpoint']['verdict'] == 'UNVERIFIED'


def test_36_unrelated_evidence_cannot_satisfy_criterion_even_when_matcher_passes():
    crit = 'production database was backed up successfully'; task, ch = register(criteria_child=[crit])
    ref = notarized(eid('knid-task'), stdout='BANANA=YELLOW', bindings=[sb(task, '01.01', 0, 'banana is yellow', 'PRE_EXECUTION', 0, 'BANANA=YELLOW')])
    r = raw_eval(task, ch, 0, claims=[claim(ref, 0, crit)]); assert r.status_code == 200 and r.json()['verdict'] == 'UNVERIFIED' and any('binding mismatch' in n['note'] for n in r.json()['evidence_notes'])


def test_37_claim_text_must_exactly_match_registered_criterion():
    task, ch = register(); ref = step_ref(task, 'PRE_EXECUTION', 0); r = raw_eval(task, ch, 0, claims=[claim(ref, 0, 'different claim')]); assert r.status_code == 409 and r.json()['detail']['code'] == 'CLAIM_CRITERION_MISMATCH'


def test_38_global_acceptance_criteria_are_mandatory_for_satisfaction():
    task, ch = register(); pre, _ = do_pre(task, ch, 0); post, _ = do_post(task, ch, pre); cp = post.json()['checkpoint_no']
    ppre, _ = do_pre(task, ch, cp, step='01', criteria=[(0, 'parent criterion')], stdout='PARENT=PASS', value='PARENT=PASS')
    bad, _ = do_post(task, ch, ppre, step='01', criteria=[(0, 'parent criterion')], stdout='PARENT=PASS', value='PARENT=PASS', finalize=True, task_claims=[])
    assert bad.status_code == 409 and bad.json()['detail']['code'] == 'TASK_ACCEPTANCE_COVERAGE_INCOMPLETE'
    d = CLIENT.get(f'/v1/tasks/{task}', headers=HEAD).json(); assert d['task']['contract_status'] == 'OPEN' and [x for x in d['steps'] if x['step_key'] == '01'][0]['verified'] == 0


def test_39_e2_proofs_for_unrelated_action_are_rejected():
    task, ch = register(physical=True); action = e2_action(task, 0, target='prod-db-primary', wrong_binding=True)
    r, _ = do_pre(task, ch, 0, action=action); assert r.json()['verdict'] == 'UNVERIFIED' and 'binding' in r.json()['reason']


def test_40_same_source_evidence_across_steps_and_tasks_has_unique_materialization_and_health_passes():
    t1, c1 = register(criteria_child=['shared']); t2, c2 = register(criteria_child=['shared'])
    bindings = [sb(t1, '01.01', 0, 'shared', 'PRE_EXECUTION', 0, 'SHARED=PASS'), sb(t1, '01.01', 0, 'shared', 'POST_EXECUTION', 1, 'SHARED=PASS'), sb(t1, '01', 0, 'parent criterion', 'PRE_EXECUTION', 2, 'SHARED=PASS'), sb(t2, '01.01', 0, 'shared', 'PRE_EXECUTION', 0, 'SHARED=PASS'), sb(t2, '01.01', 0, 'shared', 'POST_EXECUTION', 1, 'SHARED=PASS')]
    ref = notarized(eid('knid-task'), stdout='SHARED=PASS', bindings=bindings); crit = [(0, 'shared')]
    p1, _ = do_pre(t1, c1, 0, criteria=crit, ref=ref); q1, _ = do_post(t1, c1, p1, criteria=crit, ref=ref); assert q1.json()['step_verified']
    p2, _ = do_pre(t2, c2, 0, criteria=crit, ref=ref); q2, _ = do_post(t2, c2, p2, criteria=crit, ref=ref); assert q2.json()['step_verified']
    pp, _ = do_pre(t1, c1, q1.json()['checkpoint_no'], step='01', criteria=[(0, 'parent criterion')], ref=ref); assert pp.status_code == 200
    c = gw.conn(); fps = [r[0] for r in c.execute('SELECT evidence_fingerprint FROM evidence_records WHERE reference=?', (ref,))]; assert len(fps) == 5 and len(set(fps)) == 5; assert gw.verify_materialized_state(c); c.close(); assert CLIENT.get('/health').status_code == 200


def test_41_task_kind_tamper_detected():
    task, ch = register(); c = gw.conn(); c.execute("UPDATE task_registry SET task_kind='REMEDIAL' WHERE task_id=?", (task,)); assert not gw.verify_materialized_state(c); c.execute("UPDATE task_registry SET task_kind='NORMAL' WHERE task_id=?", (task,)); assert gw.verify_materialized_state(c); c.close()


def test_42_remedial_link_tamper_detected():
    task, ch = register(); cp = induce_three_failures(task, ch); rem, rr = register_remedial(task, cp); assert rr.status_code == 200
    c = gw.conn(); orig = c.execute('SELECT remedial_for_task_id FROM task_registry WHERE task_id=?', (rem,)).fetchone()[0]; c.execute('UPDATE task_registry SET remedial_for_task_id=? WHERE task_id=?', ('tampered', rem)); assert not gw.verify_materialized_state(c)
    c.execute('UPDATE task_registry SET remedial_for_task_id=? WHERE task_id=?', (orig, rem)); assert gw.verify_materialized_state(c); c.close()


def test_43_historical_verified_step_rollback_detected():
    task, ch = register(); pre, _ = do_pre(task, ch, 0); post, _ = do_post(task, ch, pre); assert post.json()['step_verified']
    c = gw.conn(); c.execute("UPDATE task_registry_steps SET verified=0,status='PLANNED' WHERE task_id=? AND step_key='01.01'", (task,)); assert not gw.verify_materialized_state(c)
    c.execute("UPDATE task_registry_steps SET verified=1,status='VERIFIED' WHERE task_id=? AND step_key='01.01'", (task,)); assert gw.verify_materialized_state(c); c.close()


def test_44_checkpoint_verdict_tamper_detected():
    task, ch = register(); pre, _ = do_pre(task, ch, 0); post, _ = do_post(task, ch, pre); assert post.status_code == 200
    c = gw.conn(); cp = c.execute('SELECT checkpoint_id,verdict FROM task_registry_checkpoints WHERE task_id=? ORDER BY checkpoint_no DESC LIMIT 1', (task,)).fetchone()
    c.execute('UPDATE task_registry_checkpoints SET verdict=? WHERE checkpoint_id=?', ('UNVERIFIED', cp['checkpoint_id'])); assert not gw.verify_materialized_state(c)
    c.execute('UPDATE task_registry_checkpoints SET verdict=? WHERE checkpoint_id=?', (cp['verdict'], cp['checkpoint_id'])); assert gw.verify_materialized_state(c); c.close()


def test_45_full_audit_rehash_without_secret_mac_is_detected():
    H.checkpoint_wal(); copy = RUNTIME / 'audit-rewrite.db'; shutil.copy2(gw.DB_PATH, copy); c = sqlite3.connect(copy); c.row_factory = sqlite3.Row
    rows = c.execute('SELECT * FROM audit ORDER BY seq').fetchall(); prev = gw.ZERO_HASH
    for i, r in enumerate(rows):
        response = json.loads(r['response_json'])
        if i == 0: response['attacker'] = 'rewrite'
        payload = {'seq': r['seq'], 'created_at': r['created_at'], 'task_id': r['task_id'], 'event_id': r['event_id'], 'event_type': r['event_type'], 'contract_hash': r['contract_hash'], 'request_hash': r['request_hash'], 'request': json.loads(r['request_json']), 'response': response, 'prev_hash': prev}
        rh = gw.sha(prev + gw.canon(payload)); c.execute('UPDATE audit SET response_json=?,prev_hash=?,record_hash=? WHERE seq=?', (gw.canon(response), prev, rh, r['seq'])); prev = rh
    c.commit(); assert not gw.verify_audit_chain(c); c.close()


def test_46_fact_check_is_functional_and_read_only():
    task, ch = register(); ref = step_ref(task, 'FACT_CHECK', 0); r = raw_eval(task, ch, 0, claims=[claim(ref)], phase='FACT_CHECK')
    assert r.status_code == 200 and r.json()['verdict'] == 'VERIFIED_PASS' and r.json()['checkpoint_no'] == 0 and r.json()['step_verified'] is False
    d = CLIENT.get(f'/v1/tasks/{task}', headers=HEAD).json(); assert d['task']['checkpoint_no'] == 0 and [x for x in d['steps'] if x['step_key'] == '01.01'][0]['verified'] == 0
    c = gw.conn(); assert c.execute("SELECT COUNT(*) FROM audit WHERE event_id=? AND event_type='FACT_CHECK'", (json.loads(r.request.content)['event_id'],)).fetchone()[0] == 1; assert gw.verify_materialized_state(c); c.close()


def test_47_fact_check_rejects_mutating_fields():
    task, ch = register(); ref = step_ref(task, 'FACT_CHECK', 0); r = raw_eval(task, ch, 0, claims=[claim(ref)], phase='FACT_CHECK', action=e3_action()); assert r.status_code == 409 and r.json()['detail']['code'] == 'FACT_CHECK_READ_ONLY'


def test_48_duplicate_action_proof_purpose_rejected_by_schema():
    task, ch = register(); ref = step_ref(task, 'PRE_EXECUTION', 0); proof = notarized(eid('knid-task'), stdout='X', bindings=[{'kind': 'x'}])
    action = {'action_type': 'write', 'target': 'x', 'effect_class': 'E2', 'reversible': True, 'proofs': [{'purpose': 'sandbox_pass', 'evidence': evp(proof)}, {'purpose': 'sandbox_pass', 'evidence': evp(proof)}]}
    assert raw_eval(task, ch, 0, claims=[claim(ref)], action=action).status_code == 422


def test_49_last_step_cannot_be_closed_without_finalization():
    task, ch = register(); pre, _ = do_pre(task, ch, 0); post, _ = do_post(task, ch, pre); cp = post.json()['checkpoint_no']
    ppre, _ = do_pre(task, ch, cp, step='01', criteria=[(0, 'parent criterion')], stdout='PARENT=PASS', value='PARENT=PASS')
    r, _ = do_post(task, ch, ppre, step='01', criteria=[(0, 'parent criterion')], stdout='PARENT=PASS', value='PARENT=PASS'); assert r.status_code == 409 and r.json()['detail']['code'] == 'FINAL_STEP_REQUIRES_FINALIZATION'


def test_50_audit_hmac_key_required_and_separate(monkeypatch):
    monkeypatch.setattr(gw, 'AUDIT_HMAC_KEY', '')
    with pytest.raises(RuntimeError): gw.require_config()
    assert CLIENT.get('/health').status_code == 503
    monkeypatch.setattr(gw, 'AUDIT_HMAC_KEY', gw.API_KEY)
    with pytest.raises(RuntimeError, match='must differ'): gw.require_config()


def test_51_legacy_manifest_is_fail_closed():
    task, ch = register(); ref = notarized(eid('knid-task'), manifest_version=3, bindings=[sb(task, '01.01', 0, CRIT, 'PRE_EXECUTION', 0)])
    r = raw_eval(task, ch, 0, claims=[claim(ref)]); assert r.status_code == 200 and r.json()['verdict'] == 'UNVERIFIED' and any('v4 required' in n['note'] for n in r.json()['evidence_notes'])


def test_52_binding_tamper_breaks_signature():
    task, ch = register(); ref = step_ref(task, 'PRE_EXECUTION', 0); p = RUNTIME / 'evidence' / ref / 'evidence.json'; meta = json.loads(p.read_text()); meta['bindings'][0]['criterion'] = 'tampered'; p.write_text(gw.canon(meta)); p.chmod(0o600)
    r = raw_eval(task, ch, 0, claims=[claim(ref)]); assert r.status_code == 200 and r.json()['verdict'] == 'UNVERIFIED' and any('invalid notary signature' in n['note'] for n in r.json()['evidence_notes'])


def test_53_materialized_evidence_row_tamper_detected():
    task, ch = register(); pre, _ = do_pre(task, ch, 0); c = gw.conn(); row = c.execute('SELECT evidence_id,reference FROM evidence_records WHERE task_id=? LIMIT 1', (task,)).fetchone()
    c.execute('UPDATE evidence_records SET reference=? WHERE evidence_id=?', ('tampered-ref', row['evidence_id'])); assert not gw.verify_materialized_state(c)
    c.execute('UPDATE evidence_records SET reference=? WHERE evidence_id=?', (row['reference'], row['evidence_id'])); assert gw.verify_materialized_state(c); c.close()


def test_54_execution_gate_tamper_detected():
    task, ch = register(); pre, _ = do_pre(task, ch, 0); c = gw.conn(); row = c.execute('SELECT gate_id,action_fingerprint FROM execution_gates WHERE task_id=?', (task,)).fetchone()
    c.execute('UPDATE execution_gates SET action_fingerprint=? WHERE gate_id=?', ('0' * 64, row['gate_id'])); assert not gw.verify_materialized_state(c)
    c.execute('UPDATE execution_gates SET action_fingerprint=? WHERE gate_id=?', (row['action_fingerprint'], row['gate_id'])); assert gw.verify_materialized_state(c); c.close()


def test_55_global_evidence_binding_must_match_task_criterion():
    task, ch = register(); pre, _ = do_pre(task, ch, 0); post, _ = do_post(task, ch, pre); cp = post.json()['checkpoint_no']
    ppre, _ = do_pre(task, ch, cp, step='01', criteria=[(0, 'parent criterion')], stdout='PARENT=PASS', value='PARENT=PASS')
    wrong = notarized(eid('knid-task'), stdout='TASK=PASS', bindings=[tb(task, 0, 'wrong global', ppre.json()['gate_checkpoint_no'])])
    r, _ = do_post(task, ch, ppre, step='01', criteria=[(0, 'parent criterion')], stdout='PARENT=PASS', value='PARENT=PASS', finalize=True, task_claims=[task_claim(wrong)])
    assert r.status_code == 200 and r.json()['verdict'] == 'UNVERIFIED' and r.json()['contract_status'] == 'OPEN'


def test_56_final_health_and_integrity_pass():
    assert CLIENT.get('/health').status_code == 200
    assert CLIENT.get('/v1/audit/verify', headers=HEAD).status_code == 200
