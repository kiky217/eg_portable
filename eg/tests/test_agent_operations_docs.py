"""Guard agent SKILL/documentation against operational drift from the runtime API."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SKILL = (ROOT / "SKILL.md").read_text(encoding="utf-8")
REFERENCE = (ROOT / "eg/docs/AGENT_OPERATIONS_REFERENCE.md").read_text(encoding="utf-8")
SOURCE = (ROOT / "eg/app/main.py").read_text(encoding="utf-8")
DISPATCH = (ROOT / "eg/tools/governed_agent_dispatcher.py").read_text(encoding="utf-8")


def test_agent_operational_api_routes_match_runtime():
    routes = (
        "/health", "/v1/protocol", "/v1/agent/capabilities",
        "/v1/agent/capability-match", "/v1/tasks/register",
        "/v1/evaluate", "/v1/audit/verify",
        "/v1/tasks/{task_id}", "/v1/tasks/{task_id}/state",
        "/v1/tasks/{task_id}/pause", "/v1/tasks/{task_id}/resume",
        "/v1/tasks/{task_id}/reconcile", "/v1/tasks/{task_id}/abort",
    )
    for route in routes:
        assert route in SOURCE, route
        assert route in REFERENCE, route


def test_skill_supports_creation_replacement_and_registry_without_self_admission():
    for value in (
        "E2", "replace", "previous_sha256", "512 KiB",
        "PRE_EXECUTION", "POST_EXECUTION",
        "RECEIPT_VERIFIED_POST_REQUIRED", "VERIFIED_PASS",
        "SATISFIED", "RECOVERY_PENDING", "NOT_EXECUTED",
        "AGENT_OPERATIONS_REFERENCE.md", "single_agent_workflow",
    ):
        assert value in SKILL or value in REFERENCE, value
    assert "_unique_active_adapter" in DISPATCH
    assert "operator_registry" in DISPATCH
    assert "independent" in SKILL.lower()
    assert "do not" in SKILL.lower()


def test_documentation_links_refer_to_existing_paths():
    for relative in (
        "eg/docs/AGENT_OPERATIONS_REFERENCE.md",
        "eg/docs/AGENT_QUICKSTART.md",
        "eg/docs/EXECUTOR_PROTOCOL.md",
        "eg/docs/OPERATIONS.md",
        "eg/docs/PORTABLE_RUNBOOK.md",
        "eg/docs/ONE_TIME_STAGING_BOOTSTRAP.md",
        "eg/docs/OPERATOR_PROCESS_SERVICE.md",
        "eg/docs/SCOPED_STAGING_APPROVAL.md",
        "eg/docs/GENERIC_EXECUTION_MODEL.md",
        "eg/docs/PRODUCTION_PROMOTION.md",
        "eg/tools/single_agent_workflow.py",
        "eg/tools/governed_agent_dispatcher.py",
    ):
        assert relative in SKILL, relative
        assert (ROOT / relative).is_file(), relative
    assert "AGENT_OPERATIONS_REFERENCE.md" in (ROOT / "README.md").read_text()
    assert "AGENT_OPERATIONS_REFERENCE.md" in (ROOT / "eg/README.md").read_text()
    assert "AGENT_OPERATIONS_REFERENCE.md" in (ROOT / "eg/docs/AGENT_QUICKSTART.md").read_text()


def test_repository_readme_markdown_structure():
    """The repository landing page must start with a real Markdown heading."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert readme.startswith("# Evaluation Gateway (EG)\n\n")
    assert "\\n|" not in readme
    assert readme.count("## Documentation") == 1
    assert "| [Agent operations reference](eg/docs/AGENT_OPERATIONS_REFERENCE.md) |" in readme

def test_generic_skill_json_examples_parse_and_match_actual_runtime_models():
    import json
    import re
    from harness import gw

    appendix = SKILL.split("## Provider-neutral operational cookbook", 1)[1]
    examples = re.findall(r"```json\n(.*?)\n```", appendix, re.S)
    assert len(examples) == 2
    registration = json.loads(examples[0])
    registration["protocol_hash"] = gw.protocol_hash()
    parsed = gw.RegisterRequest.model_validate(registration)
    assert parsed.steps[1].execution_required is True
    assert parsed.steps[1].preconditions

    action = json.loads(examples[1])
    action["payload_sha256"] = "a" * 64
    checked = gw.Action.model_validate(action)
    assert checked.effect_class == "E3"
    assert checked.action_type == "bounded_process_run"


def test_skill_and_core_have_provider_neutral_evidence_contract():
    from harness import gw
    appendix = SKILL.split("## Provider-neutral operational cookbook", 1)[1]
    assert "source_type" in appendix and "independently notarized" in appendix
    assert "E4" in appendix and "E5" in appendix and "NOT_EXECUTED" in appendix
    assert "knid_task" not in SOURCE
    for producer in ("trusted_task", "external_task", "pipeline_task", "historic_task"):
        assert gw.Evidence(source_type=producer, reference="signed-ref").source_type == producer
