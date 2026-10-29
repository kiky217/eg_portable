"""Language-agnostic workspace create policy remains opt-in and fail closed."""
import os
import pytest
from app.executor_policy import parse_suffixes
from harness import gw


def test_default_is_backward_compatible():
    assert parse_suffixes() == (".txt", ".json")


def test_generic_source_extensions_are_operator_opt_in(monkeypatch):
    monkeypatch.setenv("EVALUATION_GATEWAY_EXECUTOR_ALLOWED_SUFFIXES", ".txt,.json,.py,.rs,.toml")
    target = os.path.join(gw.EXECUTOR_OUTPUT_ROOT, "scanner.py")
    a = gw.Action(action_type="write", target=target, effect_class="bounded_change",
                  reversible=True, real_world_effect=False,
                  payload_sha256="a"*64, payload_bytes=5)
    assert gw.worker_capability(a)[0]
    monkeypatch.delenv("EVALUATION_GATEWAY_EXECUTOR_ALLOWED_SUFFIXES")
    assert not gw.worker_capability(a)[0]


@pytest.mark.parametrize("bad", [
    ".txt,,.py", ".py,.py", "py", ".PYC", ".py/../.sh",
    [".py", "../evil"], "."+"x"*50
])
def test_unsafe_suffix_rejected(bad):
    with pytest.raises(ValueError, match="INVALID_EXECUTOR_SUFFIX_POLICY"):
        parse_suffixes(bad)
