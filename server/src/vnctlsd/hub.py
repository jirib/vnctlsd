import logging
import os
import socket
import threading

log = logging.getLogger(__name__)


class ConsoleHub:
    """
    One hub per active console.  A single background thread reads from
    the console fd and broadcasts to all connected clients.
    Read-write clients write keystrokes back; read-only clients receive only.
    """

    def __init__(self, name: str, fd: int, grace_period: int = 30):
        self.name = name
        self.fd = fd
        self._grace = grace_period
        self._lock = threading.Lock()
        self._clients: dict[str, dict] = {}
        self._done = threading.Event()
        self._grace_timer: threading.Timer | None = None

        threading.Thread(target=self._reader, daemon=True,
                         name=f"hub-{name}-reader").start()

    def add_client(self, cid: str, sock: socket.socket, read_only: bool):
        with self._lock:
            if self._grace_timer is not None:
                self._grace_timer.cancel()
                self._grace_timer = None
            self._clients[cid] = {'sock': sock, 'read_only': read_only}
        log.info("Hub[%s]: +client %s ro=%r total=%d",
                 self.name, cid[:8], read_only, len(self._clients))

    def remove_client(self, cid: str):
        with self._lock:
            self._clients.pop(cid, None)
            remaining = len(self._clients)
        log.info("Hub[%s]: -client %s remaining=%d",
                 self.name, cid[:8], remaining)
        if remaining == 0:
            self._arm_grace()

    def _arm_grace(self):
        with self._lock:
            if self._grace_timer is not None:
                self._grace_timer.cancel()
            t = threading.Timer(self._grace, self._teardown)
            t.daemon = True
            t.start()
            self._grace_timer = t
        log.info("Hub[%s]: grace period armed (%ds)", self.name, self._grace)

    def _teardown(self):
        with self._lock:
            if self._clients:
                return
            self._grace_timer = None
        log.info("Hub[%s]: grace expired, tearing down", self.name)
        self._done.set()

    def write_input(self, data: bytes):
        try:
            os.write(self.fd, data)
        except OSError:
            self._done.set()

    def _reader(self):
        while not self._done.is_set():
            try:
                data = os.read(self.fd, 4096)
            except OSError:
                self._done.set()
                break
            if not data:
                self._done.set()
                break

            with self._lock:
                dead = []
                for cid, c in self._clients.items():
                    try:
                        c['sock'].sendall(data)
                    except Exception:
                        dead.append(cid)
                for cid in dead:
                    log.info("Hub[%s]: dead client %s removed", self.name, cid[:8])
                    del self._clients[cid]
                if not self._clients:
                    threading.Thread(target=self._arm_grace, daemon=True).start()

        with self._lock:
            for c in self._clients.values():
                try:
                    c['sock'].sendall(b"\r\n[INFO] Console terminated\r\n")
                except Exception:
                    pass
            self._clients.clear()

        try:
            os.close(self.fd)
        except Exception:
            pass
        log.info("Hub[%s]: reader exited", self.name)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                'name': self.name,
                'clients': [{'id': cid[:8], 'ro': c['read_only']}
                            for cid, c in self._clients.items()],
            }

    @property
    def is_done(self) -> bool:
        return self._done.is_set()


class HubRegistry:
    def __init__(self):
        self._hubs: dict[str, ConsoleHub] = {}
        self._lock = threading.Lock()

    def get_or_create(self, name: str, fd: int,
                      grace: int = 30) -> tuple[ConsoleHub, bool]:
        with self._lock:
            hub = self._hubs.get(name)
            if hub is not None and not hub.is_done:
                try:
                    os.close(fd)
                except Exception:
                    pass
                return hub, False
            hub = ConsoleHub(name, fd, grace_period=grace)
            self._hubs[name] = hub
            return hub, True

    def get(self, name: str) -> ConsoleHub | None:
        with self._lock:
            hub = self._hubs.get(name)
            return hub if hub and not hub.is_done else None

    def remove_if_done(self, name: str):
        with self._lock:
            hub = self._hubs.get(name)
            if hub is not None and hub.is_done:
                del self._hubs[name]

    def snapshot(self) -> list[dict]:
        with self._lock:
            return [h.snapshot() for h in self._hubs.values()
                    if not h.is_done]

    def teardown_all(self):
        with self._lock:
            for hub in self._hubs.values():
                hub._done.set()
            self._hubs.clear()
