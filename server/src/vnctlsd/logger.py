import datetime
import json
import logging
import os
import stat
import traceback as _tb
from itertools import count

_MAX_RECORD_BYTES = 65536


def _utc_isoformat(ts: float) -> str:
    dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
    return dt.strftime('%Y-%m-%dT%H:%M:%S.%f') + 'Z'


def _write_all(fd: int, data: bytes) -> None:
    """Write all bytes to fd, retrying on EINTR and short writes."""
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        try:
            offset += os.write(fd, view[offset:])
        except InterruptedError:
            continue


def _encode_entry(entry: dict) -> bytes:
    """
    JSON-encode entry as a JSONL line.  If the result exceeds _MAX_RECORD_BYTES,
    truncate exc then msg (at the string level, before encoding) so the output
    is always valid JSON.  A 'truncated' field marks modified records.
    """
    data = (json.dumps(entry, separators=(',', ':')) + '\n').encode('utf-8', errors='replace')
    if len(data) <= _MAX_RECORD_BYTES:
        return data

    trimmed = dict(entry)
    trimmed['truncated'] = True

    if 'exc' in trimmed:
        del trimmed['exc']
        data = (json.dumps(trimmed, separators=(',', ':')) + '\n').encode('utf-8', errors='replace')
        if len(data) <= _MAX_RECORD_BYTES:
            return data

    msg = trimmed.get('msg', '')
    for limit in (4000, 1000, 200, 40):
        if len(msg) > limit:
            trimmed['msg'] = msg[:limit] + '…'
            data = (json.dumps(trimmed, separators=(',', ':')) + '\n').encode('utf-8', errors='replace')
            if len(data) <= _MAX_RECORD_BYTES:
                return data

    trimmed['msg'] = '…'
    return (json.dumps(trimmed, separators=(',', ':')) + '\n').encode('utf-8', errors='replace')


class AppendOnlyHandler(logging.Handler):
    """
    Write JSONL records to a pre-opened, O_APPEND fd.

    The fd is opened by the master process before any fork.  This handler
    never opens or reopens a path.  Each record is emitted in a single
    os.write() call; the kernel's O_APPEND positioning guarantee makes
    concurrent writers from the same process's threads safe for records
    that fit within the system's atomic write size.

    emit() is called with the handler lock held (logging.Handler contract),
    so seq increments and writes are serialised across threads.
    """

    def __init__(self, fd: int, component: str) -> None:
        super().__init__()
        self._fd = fd
        self._component = component
        self._seq = count(0)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            entry: dict = {
                'ts':        _utc_isoformat(record.created),
                'seq':       next(self._seq),
                'level':     record.levelname,
                'component': self._component,
                'pid':       record.process,
                'logger':    record.name,
                'msg':       record.getMessage(),
            }
            if record.exc_info and record.exc_info[0] is not None:
                entry['exc'] = _tb.format_exception(*record.exc_info)
            _write_all(self._fd, _encode_entry(entry))
        except Exception:
            self.handleError(record)

    def close(self) -> None:
        try:
            os.fdatasync(self._fd)
        except OSError:
            pass
        super().close()


def _validate_log_dir(path: str) -> None:
    """
    Require that the parent directory of path is not group- or world-writable.
    A writable log directory allows an attacker to replace the log file with a
    symlink or device node before the master opens it.
    """
    dir_path = os.path.dirname(os.path.abspath(path))
    try:
        st = os.lstat(dir_path)
    except OSError as exc:
        raise ValueError(f"log directory {dir_path!r}: {exc}") from exc
    if not stat.S_ISDIR(st.st_mode):
        raise ValueError(f"log directory {dir_path!r} is not a directory")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError(f"log directory {dir_path!r} is group- or world-writable")


def open_log_fd(path: str | None) -> int | None:
    """
    Open path for append-only writing and return the fd.

    O_CLOEXEC is set so the fd is NOT inherited by processes created via
    execve() (e.g. virsh console commands spawned by the monitor).  fork()
    is unaffected — O_CLOEXEC only triggers on exec, not on fork.

    Returns None if path is None (caller keeps existing stderr logging).
    """
    if path is None:
        return None
    _validate_log_dir(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path, flags, 0o640)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise ValueError(f"log path {path!r} is not a regular file")
    return fd


def install_log_handler(fd: int | None, component: str,
                        debug: bool = False) -> None:
    """
    Add AppendOnlyHandler for component to the root logger.

    If fd is None, does nothing (existing handlers, typically stderr, remain).
    If debug is False, existing StreamHandlers are removed so records go only
    to the file.  In debug mode both file and stderr receive records.
    """
    if fd is None:
        return
    root = logging.getLogger()
    handler = AppendOnlyHandler(fd, component)
    handler.setLevel(logging.NOTSET)
    root.addHandler(handler)
    if not debug:
        for h in root.handlers[:]:
            if h is not handler and isinstance(h, logging.StreamHandler):
                root.removeHandler(h)


def close_fd(fd: int | None) -> None:
    """Close fd if not None; ignore errors."""
    if fd is None:
        return
    try:
        os.close(fd)
    except OSError:
        pass
