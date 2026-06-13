import logging
import socket
import threading
import time

from .acl import ACLResolver
from .config import ConsoleConfigStore
from .glob_patterns import match_glob_pattern

log = logging.getLogger(__name__)


class SessionRegistry:
    def __init__(self):
        self._sessions: dict[str, dict] = {}
        self._socks: dict[str, socket.socket] = {}
        self._lock = threading.Lock()

    def add(self, sid: str, username: str, state: str,
            sock: socket.socket, console: str | None = None,
            read_only: bool = False):
        with self._lock:
            self._sessions[sid] = {
                'id':        sid,
                'username':  username,
                'state':     state,
                'console':   console,
                'read_only': read_only,
                'started':   time.monotonic(),
            }
            self._socks[sid] = sock

    def update(self, sid: str, **kwargs):
        with self._lock:
            if sid in self._sessions:
                self._sessions[sid].update(kwargs)

    def remove(self, sid: str):
        with self._lock:
            self._sessions.pop(sid, None)
            self._socks.pop(sid, None)

    def snapshot(self) -> list[dict]:
        with self._lock:
            return [dict(s) for s in self._sessions.values()]

    def kill_stale(self, acl_resolver: ACLResolver,
                   console_store: ConsoleConfigStore) -> tuple[list, list]:
        """
        Disconnect sessions whose console access has been revoked.
        Called on SIGUSR2 after config reload.
        """
        killed = []
        retained = []
        with self._lock:
            stale = []
            for sid, s in self._sessions.items():
                if s['state'] != 'console' or not s.get('console'):
                    retained.append(f"{s['username']} (at prompt)")
                    continue
                console_name = s['console']
                cfg = console_store.get()
                defn = cfg.get('consoles', {}).get(console_name)
                vars_ = {}
                if defn is None:
                    for pat in cfg.get('console_patterns', []):
                        sock_path = (cfg.get('consoles', {})
                                     .get(console_name, {})
                                     .get('socket', ''))
                        if '_fnmatch' in pat:
                            v = match_glob_pattern(
                                sock_path, pat['_fnmatch'], pat['_regex'])
                            if v is not None:
                                defn = pat
                                vars_ = v
                                break
                if defn is None:
                    stale.append(sid)
                    killed.append(
                        f"{s['username']} → {console_name} (console removed)")
                    continue
                level = acl_resolver.resolve_access(
                    s['username'], console_name, defn, vars_)
                if level is None:
                    stale.append(sid)
                    killed.append(
                        f"{s['username']} → {console_name} (access revoked)")
                else:
                    retained.append(f"{s['username']} → {console_name}")

            for sid in stale:
                sock = self._socks.get(sid)
                if sock:
                    try:
                        sock.sendall(
                            b"\r\n[INFO] Your access has been revoked."
                            b" Disconnecting.\r\n")
                        sock.shutdown(socket.SHUT_RDWR)
                        sock.close()
                    except Exception:
                        pass
                del self._sessions[sid]
                self._socks.pop(sid, None)

        return killed, retained
