"""Shared fail-closed, language-agnostic workspace file policy.

Extension opt-in only affects exclusive bounded file creation; it never grants
shell, process execution, overwrites, writes outside the isolated worker root,
or high-effect capabilities.
"""
from __future__ import annotations
import re

DEFAULT_SUFFIXES = (".txt", ".json")
_VALID = re.compile(r"^\.[a-z0-9]{1,12}$")


def parse_suffixes(value=None) -> tuple[str, ...]:
    if value is None or value == "":
        return DEFAULT_SUFFIXES
    if isinstance(value, str):
        seq = value.split(",")
    elif isinstance(value, list):
        seq = value
    else:
        raise ValueError("INVALID_EXECUTOR_SUFFIX_POLICY")
    if not (1 <= len(seq) <= 32) or any(
        not isinstance(item, str) or not _VALID.fullmatch(item) for item in seq
    ) or len(set(seq)) != len(seq):
        raise ValueError("INVALID_EXECUTOR_SUFFIX_POLICY")
    return tuple(seq)
