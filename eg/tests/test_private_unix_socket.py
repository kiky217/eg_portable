"""Crash/timeout recovery cannot clobber an active worker or untrusted socket."""
from pathlib import Path
import os
import socket
import pytest
from tools.private_unix_socket import private_socket_lease, SocketBusy


def test_crashed_socket_recovered_with_owned_exclusive_lock(tmp_path):
    path=tmp_path/'worker.sock'
    with socket.socket(socket.AF_UNIX) as dead:
        dead.bind(str(path))
    assert path.is_socket()
    with private_socket_lease(path):
        assert not path.exists()
        with socket.socket(socket.AF_UNIX) as new:
            new.bind(str(path))
            new.listen()
            with pytest.raises(SocketBusy,match='WORKER_ALREADY_RUNNING'):
                with private_socket_lease(path):pass
    path.unlink()


def test_live_and_untrusted_path_remain_untouched(tmp_path):
    path=tmp_path/'worker.sock'
    with socket.socket(socket.AF_UNIX) as active:
        active.bind(str(path));active.listen()
        with pytest.raises(SocketBusy,match='WORKER_ALREADY_LISTENING'):
            with private_socket_lease(path):pass
        assert path.is_socket()
    path.unlink()
    path.symlink_to(tmp_path/'missing')
    with pytest.raises(SocketBusy,match='UNTRUSTED_EXISTING_SOCKET'):
        with private_socket_lease(path):pass
    assert path.is_symlink()
