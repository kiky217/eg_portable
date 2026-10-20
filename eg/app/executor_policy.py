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


def parse_subdir_depth(value=None) -> int:
    """Operator opt-in: number of existing private directories below output_root."""
    if value is None or value == "":
        return 0
    if type(value) is int:
        depth = value
    elif isinstance(value, str) and value.isascii() and value.isdecimal():
        depth = int(value)
    else:
        raise ValueError("INVALID_EXECUTOR_SUBDIR_DEPTH")
    if not 0 <= depth <= 4:
        raise ValueError("INVALID_EXECUTOR_SUBDIR_DEPTH")
    return depth


def scoped_parts(root, target, max_depth: int) -> tuple[str, ...]:
    """Lexical policy, never authority to traverse a filesystem symlink."""
    from pathlib import Path
    raw = str(target)
    if any(part in ("", ".", "..") for part in raw.split("/")[1:]):
        raise ValueError("TARGET_OUTSIDE_PROVISIONED_BOUNDS")
    root = Path(root)
    target = Path(target)
    if (not root.is_absolute() or not target.is_absolute()):
        raise ValueError("TARGET_OUTSIDE_PROVISIONED_BOUNDS")
    try:
        parts = target.relative_to(root).parts
    except ValueError as exc:
        raise ValueError("TARGET_OUTSIDE_PROVISIONED_BOUNDS") from exc
    if not parts or len(parts) - 1 > max_depth:
        raise ValueError("TARGET_OUTSIDE_PROVISIONED_BOUNDS")
    return parts
