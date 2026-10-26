"""Stable fingerprint of EG runtime Python code, independent of checkout path.

Read-only, deterministic and portable. Does not depend on Git or system accounts.
"""
from __future__ import annotations
import hashlib
from pathlib import Path


def fingerprint(root:Path)->str:
    root=Path(root).resolve(strict=True)
    digest=hashlib.sha256()
    found=0
    for folder in ('app','tools'):
        directory=root/folder
        if not directory.is_dir() or directory.is_symlink():
            raise ValueError('RUNTIME_SOURCE_DIRECTORY_MISSING')
        for path in sorted(directory.rglob('*.py')):
            if path.is_symlink() or not path.is_file():
                raise ValueError('RUNTIME_SOURCE_FILE_NOT_REGULAR')
            relative=path.relative_to(root).as_posix().encode()
            content=path.read_bytes()
            digest.update(len(relative).to_bytes(4,'big'))
            digest.update(relative)
            digest.update(len(content).to_bytes(8,'big'))
            digest.update(content)
            found+=1
    if not found:
        raise ValueError('RUNTIME_SOURCE_EMPTY')
    return digest.hexdigest()
