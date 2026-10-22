"""Recover crashed worker sockets only under a worker-owned exclusive lock."""
from contextlib import contextmanager
import errno
import fcntl
import os
from pathlib import Path
import socket
import stat


class SocketBusy(RuntimeError):
    pass


@contextmanager
def private_socket_lease(path):
    path=Path(path)
    parent=path.parent.lstat()
    if (not path.is_absolute() or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid!=os.getuid() or stat.S_IMODE(parent.st_mode)&0o022):
        raise SocketBusy('UNTRUSTED_SOCKET_DIRECTORY')
    lock=path.with_name('.'+path.name+'.lock')
    fd=os.open(lock,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid()
            or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)&0o077):
            raise SocketBusy('UNTRUSTED_SOCKET_LOCK')
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:raise SocketBusy('WORKER_ALREADY_RUNNING') from exc
        try:old=path.lstat()
        except FileNotFoundError:old=None
        if old is not None:
            if not stat.S_ISSOCK(old.st_mode) or old.st_uid!=os.getuid():
                raise SocketBusy('UNTRUSTED_EXISTING_SOCKET')
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as probe:
                probe.settimeout(.25)
                try:probe.connect(str(path))
                except ConnectionRefusedError:
                    if path.lstat().st_ino!=old.st_ino:raise SocketBusy('SOCKET_CHANGED')
                    path.unlink()  # Exact stale inode, with worker-owned locked parent.
                else:raise SocketBusy('WORKER_ALREADY_LISTENING')
        yield
    finally:os.close(fd)
