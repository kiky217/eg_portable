"""One-agent EG sequence; independent workers and notary still decide effects.

Input callbacks provide already notarized PRE claims and independently validated
POST evidence. The caller never creates its own cryptographic authority.
"""
from __future__ import annotations


class WorkflowDenied(RuntimeError):
    pass


def _ok(response):
    if response.status_code != 200:
        raise WorkflowDenied('GATEWAY_HTTP_DENIED')
    value = response.json()
    if not isinstance(value, dict):
        raise WorkflowDenied('INVALID_GATEWAY_RESPONSE')
    return value


def run_step(client, headers, *, task_id, step_key, action, payload_b64,
             pre_request, dispatch_once, post_evidence):
    """Submit fresh PRE, execute at most once, then require canonical verified POST.

    post_evidence(pre, receipt) must read back the actual effect and return
    signed evidence claims; EG verifies these against the original task.
    """
    if (not isinstance(pre_request, dict) or
        pre_request.get('task_id') != task_id or
        pre_request.get('step_key') != step_key or
        pre_request.get('phase') != 'PRE_EXECUTION' or
        pre_request.get('action') != action):
        raise WorkflowDenied('ORIGINAL_PRE_PAYLOAD_REQUIRED')
    pre = _ok(client.post('/v1/evaluate', headers=headers, json=pre_request))
    if pre.get('verdict') != 'READY_TO_EXECUTE' or type(pre.get('checkpoint_no')) is not int:
        raise WorkflowDenied('PRE_NOT_VERIFIED_NO_EFFECT')
    packet = {'task_id': task_id, 'step_key': step_key,
              'action': action, 'data_b64': payload_b64}
    # This call is never retried, even if its response is lost or unknown.
    result = dispatch_once(packet)
    if not isinstance(result, dict) or result.get('status') != 'RECEIPT_VERIFIED_POST_REQUIRED':
        raise WorkflowDenied('EXECUTION_NOT_PROVEN_RECONCILE_ORIGINAL_EFFECT')
    receipt = result.get('execution_receipt')
    if not isinstance(receipt, dict):
        raise WorkflowDenied('SIGNED_EXECUTION_RECEIPT_MISSING')
    after = post_evidence(pre, receipt)
    if (not isinstance(after, dict) or not isinstance(after.get('claims'), list)
        or not after['claims']):
        raise WorkflowDenied('INDEPENDENT_POST_EVIDENCE_REQUIRED')
    post = {**pre_request, **after, 'phase': 'POST_EXECUTION',
            'checkpoint_no': pre['checkpoint_no'],
            'action': action, 'execution_receipt': receipt}
    post_result = _ok(client.post('/v1/evaluate', headers=headers, json=post))
    if post_result.get('verdict') != 'VERIFIED_PASS':
        raise WorkflowDenied('POST_NOT_VERIFIED_DO_NOT_REPEAT_EFFECT')
    return post_result


def run_task(client, headers, *, registration, step_provider, dispatch_once, finalize=None):
    """Register once; each step_provider yields a signed-evidence step request.

    The provider may be an ordinary Python process; no second AI agent is
    required. A task-wide final acceptance is submitted independently by the
    caller after all physical steps are verified.
    """
    accepted = _ok(client.post('/v1/tasks/register', headers=headers, json=registration))
    task_id = registration['task_id']
    checkpoint = 0
    for spec in step_provider(accepted):
        pre_request = spec['pre_request'](checkpoint)
        post = run_step(client, headers, task_id=task_id,
            step_key=spec['step_key'], action=spec['action'],
            payload_b64=spec['data_b64'], pre_request=pre_request,
            dispatch_once=dispatch_once,
            post_evidence=spec['post_evidence'])
        checkpoint = post['checkpoint_no']
    if finalize is not None:
        finalize(checkpoint)  # Must supply independently signed task acceptance.
        detail = _ok(client.get('/v1/tasks/'+task_id, headers=headers))
        if detail.get('task', {}).get('contract_status') != 'SATISFIED':
            raise WorkflowDenied('FINAL_TASK_ACCEPTANCE_NOT_VERIFIED')
        return {'task_id': task_id, 'contract_status': 'SATISFIED',
                'physical_steps_verified': True}
    return {'task_id': task_id, 'checkpoint_no': checkpoint,
            'next_action': 'SUBMIT_ORIGINAL_TASK_ACCEPTANCE',
            'physical_steps_verified': True}
