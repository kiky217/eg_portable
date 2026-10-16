"""Issue #14: external provenance AND successful real isolated restore are mandatory."""
import base64
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from tools.check_live_cutover_readiness import inspect_completed_cutover
from tools.cutover_attestation import _digest,_canonical,rehearse_restore
from test_post_cutover_readiness import fixture

def make_attestation(tmp_path, report, data):
    key=Ed25519PrivateKey.generate()
    manifest={
        "version":1,
        "report_sha256":_digest(report),
        "archive_sha256":_digest(data["legacy_source_archive"]),
        "restore_files":rehearse_restore(data["legacy_source_archive"]),
        "checkpoint":data["checkpoint"],
        "audit_head":data["audit_head"],
        "verification_scope":"INDEPENDENT_CUTOVER_AND_RESTORE",
    }
    signed={**manifest,"signature_b64":base64.b64encode(key.sign(_canonical(manifest))).decode()}
    path=tmp_path/"independent-attestation.json"
    path.write_text(json.dumps(signed))
    pub=base64.b64encode(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
    return path,pub

def test_distinct_attestor_real_restore_and_authenticated_provenance(tmp_path):
    report,db,audit,state,data=fixture(tmp_path)
    attestation,pub=make_attestation(tmp_path,report,data)
    result=inspect_completed_cutover(report,audit,state,db,attestation,pub)
    assert result["verified"] is False  # no separate EG step receipt or capability
    assert result["operational_cutover_attested"] is True
    assert result["eg_step_verified"] is False
    assert result["file_consistency_checked"] is True
    assert result["independent_provenance_verified"] is True
    assert result["restore_rehearsal_verified"] is True
    assert result["reason"]=="EG_CUTOVER_STEP_NOT_VERIFIED"
    assert rehearse_restore(data["legacy_source_archive"])

def test_fake_provenance_and_wrong_root_remain_fail_closed(tmp_path):
    report,db,audit,state,data=fixture(tmp_path)
    attest,pub=make_attestation(tmp_path,report,data)
    wrong=Ed25519PrivateKey.generate()
    other=base64.b64encode(wrong.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
    bad=inspect_completed_cutover(report,audit,state,db,attest,other)
    assert bad["verified"] is False
    assert bad["file_consistency_checked"] is True
    tampered=json.loads(attest.read_text())
    tampered["restore_files"]=[{"path":"fake","sha256":"0"*64,"size":1}]
    attest.write_text(json.dumps(tampered))
    result=inspect_completed_cutover(report,audit,state,db,attest,pub)
    assert result["verified"] is False

def test_changed_archive_with_updated_self_report_still_fails_independent_attestation(tmp_path):
    report,db,audit,state,data=fixture(tmp_path)
    attest,pub=make_attestation(tmp_path,report,data)
    import io,tarfile,hashlib
    archive=data["legacy_source_archive"]
    with tarfile.open(archive,"w:gz") as tar:
        content=b"changed rollback payload"
        entry=tarfile.TarInfo("runtime/main.py")
        entry.size=len(content)
        tar.addfile(entry,io.BytesIO(content))
    data["legacy_source_archive_sha256"]=_digest(archive)
    report.write_text(json.dumps(data))
    result=inspect_completed_cutover(report,audit,state,db,attest,pub)
    assert result["file_consistency_checked"] is True
    assert result["verified"] is False
