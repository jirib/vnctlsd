import ctypes
import ctypes.util
import logging
import os
import pwd
import select
import socket
import struct
import threading
import time

from .config import ConsoleConfigStore
from .ipc import ipc_send, ipc_recv
from .process import set_proc_title
from .security import apply_watcher_landlock, apply_watcher_seccomp
from .validation import check_dir_permissions, validate_socket

log = logging.getLogger(__name__)

_IN_CREATE = 0x00000100
_IN_DELETE = 0x00000200
_IN_MOVED_FROM = 0x00000040
_IN_MOVED_TO = 0x00000080
_IN_ONLYDIR = 0x01000000

_INOTIFY_EVENT = struct.Struct('iIII')  # wd, mask, cookie, len


def run_watcher(ctl_sock: socket.socket, watch_sock: socket.socket,
                console_store: ConsoleConfigStore,
                watcher_pw: pwd.struct_passwd,
                no_seccomp: bool = False,
                no_landlock: bool = False):
    set_proc_title(f"watcher ({watcher_pw.pw_name})")
    for h in logging.getLogger().handlers:
        h.setLevel(logging.NOTSET)
    log.info("Watcher started (pid=%d), dropping to %r",
             os.getpid(), watcher_pw.pw_name)

    os.setgid(watcher_pw.pw_gid)
    os.setuid(watcher_pw.pw_uid)

    # Pre-resolve libc before applying landlock/seccomp.
    # ctypes.util.find_library() internally tries to create a temp file
    # in /tmp (via NamedTemporaryFile) which landlock would block since
    # /tmp is not in the watcher's allowed paths.
    libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)

    if no_landlock:
        log.warning("Watcher: skipping landlock")
    else:
        apply_watcher_landlock(console_store.get_watch_dir())

    if no_seccomp:
        log.warning("Watcher: skipping seccomp")
    else:
        apply_watcher_seccomp()

    def inotify_init1(flags: int) -> int:
        return libc.syscall(294, flags)  # SYS_inotify_init1 x86_64

    def inotify_add_watch(fd: int, path: bytes, mask: int) -> int:
        return libc.syscall(254, fd, path, mask)  # SYS_inotify_add_watch

    def inotify_rm_watch(fd: int, wd: int) -> int:
        return libc.syscall(255, fd, wd)  # SYS_inotify_rm_watch

    inotify_fd = -1
    watch_wd = -1
    watch_dir = console_store.get_watch_dir()
    stop_event = threading.Event()

    def start_watch(directory: str) -> bool:
        nonlocal inotify_fd, watch_wd, watch_dir

        if inotify_fd >= 0:
            try:
                os.close(inotify_fd)
            except Exception:
                pass
            inotify_fd = -1
            watch_wd = -1

        watch_dir = directory

        err = check_dir_permissions(directory)
        if err:
            log.error("Watcher: %s", err)
            try:
                ipc_send(ctl_sock, {'type': 'WATCHER_DIR_ERROR', 'error': err})
            except Exception:
                pass
            return False

        fd = inotify_init1(0o4000)  # IN_CLOEXEC
        if fd < 0:
            log.error("Watcher: inotify_init1 failed: %s", ctypes.get_errno())
            return False

        wd = inotify_add_watch(
            fd,
            directory.encode(),
            _IN_CREATE | _IN_DELETE | _IN_MOVED_FROM | _IN_MOVED_TO,
        )
        if wd < 0:
            log.error("Watcher: inotify_add_watch failed on %r: %s",
                      directory, ctypes.get_errno())
            os.close(fd)
            return False

        inotify_fd = fd
        watch_wd = wd
        log.info("Watcher: watching %r", directory)

        try:
            for fname in os.listdir(directory):
                if fname.endswith('.sock'):
                    _handle_appeared(os.path.join(directory, fname))
        except OSError as e:
            log.error("Watcher: directory scan failed: %s", e)

        try:
            ipc_send(ctl_sock, {'type': 'WATCHER_READY', 'watch_dir': directory})
        except Exception:
            pass
        return True

    def _handle_appeared(path: str):
        match = console_store.match_socket(path)
        if match is None:
            log.warning(
                "Watcher: %r does not match any console definition, "
                "ignoring. Define it in consoles.yaml to accept it.",
                path)
            return

        defn, vars_ = match
        trusted_uid = console_store.resolve_trusted_uid(defn, vars_)

        err = validate_socket(path, trusted_uid)
        if err:
            log.warning("Watcher: rejecting %r: %s", path, err)
            return

        console_name = defn.get('console_name', defn.get('_console_name', ''))
        try:
            console_name = console_name.format(**vars_)
        except KeyError:
            pass

        log.info("Watcher: accepted %r as console %r", path, console_name)
        try:
            ipc_send(watch_sock, {
                'type': 'SOCKET_APPEARED',
                'path': path,
                'console_name': console_name,
                'defn': {k: v for k, v in defn.items()
                         if not k.startswith('_')},
                'vars': vars_,
            })
        except Exception as exc:
            log.error("Watcher: failed to send SOCKET_APPEARED: %s", exc)

    def _handle_disappeared(path: str):
        log.info("Watcher: socket disappeared: %r", path)
        try:
            ipc_send(watch_sock, {
                'type': 'SOCKET_DISAPPEARED',
                'path': path,
            })
        except Exception as exc:
            log.error("Watcher: failed to send SOCKET_DISAPPEARED: %s", exc)

    def ctl_listener():
        while not stop_event.is_set():
            try:
                msg, _ = ipc_recv(ctl_sock)
            except EOFError:
                log.info("Watcher: monitor closed ctl socket")
                stop_event.set()
                break
            except Exception:
                log.exception("Watcher: ctl recv error")
                break

            if msg.get('type') == 'RELOAD_WATCH':
                new_dir = msg.get('watch_dir', watch_dir)
                log.info("Watcher: RELOAD_WATCH → %r", new_dir)
                start_watch(new_dir)

    threading.Thread(target=ctl_listener, daemon=True,
                     name='watcher-ctl').start()

    if not start_watch(watch_dir):
        log.error("Watcher: initial watch failed, waiting for RELOAD_WATCH")

    buf_size = 4096
    while not stop_event.is_set():
        if inotify_fd < 0:
            time.sleep(1)
            continue

        try:
            r, _, _ = select.select([inotify_fd, ctl_sock.fileno()], [], [], 5.0)
        except Exception:
            continue

        if inotify_fd not in r:
            continue

        try:
            raw = os.read(inotify_fd, buf_size)
        except OSError:
            continue

        offset = 0
        while offset < len(raw):
            if offset + _INOTIFY_EVENT.size > len(raw):
                break
            wd, mask, cookie, name_len = _INOTIFY_EVENT.unpack_from(raw, offset)
            offset += _INOTIFY_EVENT.size
            name = b''
            if name_len > 0:
                name = raw[offset:offset + name_len].rstrip(b'\x00')
                offset += name_len

            if not name:
                continue

            fname = name.decode('utf-8', errors='replace')
            if not fname.endswith('.sock'):
                continue

            path = os.path.join(watch_dir, fname)

            if mask & (_IN_CREATE | _IN_MOVED_TO):
                _handle_appeared(path)
            elif mask & (_IN_DELETE | _IN_MOVED_FROM):
                _handle_disappeared(path)

    log.info("Watcher exiting")
