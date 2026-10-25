"""Provider-neutral evidence labels never replace independent notary verification."""
import pytest
import harness as H

@pytest.mark.parametrize("source_type",["trusted_task","external_task","pipeline_task"])
def test_canonical_pre_accepts_notarized_generic_source_labels(source_type):
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

def test_unnotarized_generic_label_does_not_grant_trust():
    task, contract = H.register()
    response = H.raw_eval(task, contract, 0, claims=[{
        "criterion_index": 0, "claim": H.CRIT,
        "evidence": [{"source_type": "external_task", "reference": "missing-source-0001"}],
    }])
    assert response.status_code == 200
    assert response.json()["verdict"] == "UNVERIFIED"


@pytest.mark.parametrize("label", ["untrusted", "worker/task", "", "a" * 80 + "_task"])
def test_malformed_evidence_labels_fail_schema(label):
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        H.gw.Evidence(source_type=label, reference="unused")
