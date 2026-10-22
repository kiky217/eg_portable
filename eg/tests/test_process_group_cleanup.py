"""A bounded process effect must never leave live descendants after completion."""
import subprocess
import sys
import time
from pathlib import Path

import pytest
from tools.trusted_process_effect import _bounded_process


def _not_running(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1].split()[0] == "Z"
    except FileNotFoundError:
        return True


def _probe(tmp_path, *, wait):
    pid_file = tmp_path / "child.pid"
    program = tmp_path / "worker.py"
    program.write_text("""import subprocess,sys,time
child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],
                       stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
open(sys.argv[1],'w').write(str(child.pid))
if sys.argv[2]=='wait': time.sleep(60)
else: print('OK')
""")
    return program,pid_file,wait


def _assert_cleaned(pid_file):
    child = int(pid_file.read_text())
    for _ in range(60):
        if _not_running(child):break
        time.sleep(.05)
    assert _not_running(child), "bounded process left a live background effect"


def test_timeout_kills_process_group(tmp_path):
    program,pid_file,mode = _probe(tmp_path,wait="wait")
    with pytest.raises(subprocess.TimeoutExpired):
        _bounded_process(sys.executable,(str(program),str(pid_file),mode),b"hello",1.5)
    _assert_cleaned(pid_file)


def test_success_kills_orphaned_background_process(tmp_path):
    program,pid_file,mode = _probe(tmp_path,wait="finish")
    result = _bounded_process(sys.executable,(str(program),str(pid_file),mode),b"hello",3)
    assert result.returncode == 0 and result.stdout.strip() == b"OK"
    _assert_cleaned(pid_file)
