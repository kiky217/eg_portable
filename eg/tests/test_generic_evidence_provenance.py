"""Portable evidence-source alias; names do not replace notary verification."""
import pytest
import harness as H

@pytest.mark.parametrize("source_type",["trusted_task","knid_task"])
def test_canonical_pre_accepts_signed_trusted_task_provenance(source_type):
    task,contract=H.register()
    ref=H.step_ref(task,"PRE_EXECUTION",0)
    assertion={"criterion_index":0,"claim":H.CRIT,
        "evidence":[{"source_type":source_type,"reference":ref}]}
    result=H.raw_eval(task,contract,0,claims=[assertion])
    assert result.status_code==200,result.text
    assert result.json()["verdict"]=="READY_TO_EXECUTE"

def test_manual_evidence_remains_untrusted():
    task,contract=H.register()
    result=H.raw_eval(task,contract,0,claims=[{
        "criterion_index":0,"claim":H.CRIT,
        "evidence":[{"source_type":"manual"}]}])
    assert result.status_code==200
    assert result.json()["verdict"]=="UNVERIFIED"
