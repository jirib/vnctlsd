import configparser
import logging
import os
import select
import socket
import threading
import time
import uuid

from .acl import ACLResolver
from .auth import RateLimiter
from .config import ConsoleConfigStore, UserMapStore
from .constants import BANNER, HELP_TEXT, PROMPT
from .hub import ConsoleHub, HubRegistry
from .ipc import ipc_send, ipc_recv
from .process import set_proc_title
from .security import apply_landlock, apply_seccomp
from .session import SessionRegistry
from .validation import validate_socket

log = logging.getLogger(__name__)


class MonitorProxy:
    def __init__(self, rpc_sock: socket.socket):
        self._sock = rpc_sock
        self._lock = threading.Lock()
        self._seq = 0
        self._poisoned = False

    def _next_seq(self) -> int:
        self._seq = (self._seq + 1) & 0xFFFFFFFF
        return self._seq

    def _call(self, req: dict, expect_type: str) -> tuple[dict, list[int]]:
        if self._poisoned:
            raise RuntimeError("rpc channel poisoned")
        seq = self._next_seq()
        req['seq'] = seq
        ipc_send(self._sock, req)
        resp, fds = ipc_recv(self._sock)
        if resp.get('seq') != seq:
            self._poisoned = True
            raise RuntimeError("rpc seq mismatch")
        if resp.get('type') != expect_type:
            self._poisoned = True
            raise RuntimeError(f"rpc type mismatch: got {resp.get('type')!r}")
        return resp, fds

    def auth(self, username: str, password: str) -> bool:
        try:
            with self._lock:
                resp, _ = self._call({'type': 'AUTH_REQ',
                                      'username': username,
                                      'password': password}, 'AUTH_RESP')
            return resp.get('ok', False)
        except RuntimeError:
            return False

    def spawn(self, username: str,
              console_name: str) -> tuple[bool, int | None, str]:
        """
        Ask the monitor to spawn an exec console.  The monitor resolves cmd
        and run_as from its own config — the worker never passes a command
        string so a compromised worker cannot cause arbitrary exec as root.
        """
        try:
            with self._lock:
                resp, fds = self._call({
                    'type': 'SPAWN_REQ',
                    'username': username,
                    'console': console_name,
                }, 'SPAWN_RESP')
            if resp.get('ok') and fds:
                return True, fds[0], ''
            return False, None, resp.get('error', 'unknown error')
        except RuntimeError as e:
            return False, None, str(e)

    def run_action(self, action: str, console_name: str) -> str:
        """
        Ask the monitor to run a management action on a console.
        The monitor validates action against its own config and builds
        the command itself — the worker never constructs or passes
        a command string.
        Returns a pre-rendered terminal string ready to send to the client.
        """
        try:
            with self._lock:
                resp, _ = self._call({
                    'type': 'CMD_REQ',
                    'action': action,
                    'console': console_name,
                }, 'CMD_RESP')
            return resp.get('rendered', '')
        except RuntimeError as e:
            return f"✗ RPC error: {e}\r\n"


def worker_validate_socket(path: str, console_store: ConsoleConfigStore,
                            defn: dict, vars_: dict) -> str | None:
    """
    Worker independently re-validates a socket path reported by the watcher.
    Returns None if valid, error string if not.
    This ensures a compromised watcher cannot cause the worker to connect
    to an untrusted socket.
    """
    trusted_uid = console_store.resolve_trusted_uid(defn, vars_)
    return validate_socket(path, trusted_uid)


def monitor_push_listener(push_sock: socket.socket,
                           watch_sock: socket.socket,
                           registry: SessionRegistry,
                           hub_registry: HubRegistry,
                           acl_resolver: ACLResolver,
                           console_store: ConsoleConfigStore,
                           user_map: UserMapStore,
                           monitor: MonitorProxy,
                           config: configparser.ConfigParser):
    """
    Handles:
      push_sock: SESSION_LIST_REQ, ENFORCE_REQ (from monitor)
      watch_sock: SOCKET_APPEARED, SOCKET_DISAPPEARED (from watcher)
    """
    grace = config.getint('core', 'hub_grace_period', fallback=30)

    while True:
        try:
            readable, _, _ = select.select([push_sock, watch_sock], [], [])
        except Exception:
            log.exception("push_listener select error")
            break

        for sock in readable:
            try:
                msg, _ = ipc_recv(sock)
            except EOFError:
                log.info("Push listener: socket closed, exiting")
                os._exit(0)
            except Exception:
                log.exception("Push listener recv error")
                continue

            mtype = msg.get('type')

            if mtype == 'SESSION_LIST_REQ':
                ipc_send(push_sock, {
                    'type': 'SESSION_LIST_RESP',
                    'sessions': registry.snapshot(),
                    'hubs': hub_registry.snapshot(),
                })

            elif mtype == 'CONFIG_UPDATE':
                raw = msg.get('console_config')
                if raw:
                    console_store.update(raw)
                    log.info("Push listener: console config updated from monitor")

            elif mtype == 'ENFORCE_REQ':
                # Apply the refreshed user map the monitor just pushed so
                # ACL enforcement uses current data, not the post-fork copy.
                fresh_map = msg.get('user_map')
                if fresh_map:
                    user_map.update(fresh_map)
                killed, retained = registry.kill_stale(
                    acl_resolver, console_store)
                ipc_send(push_sock, {
                    'type': 'ENFORCE_RESP',
                    'killed': killed,
                    'retained': retained,
                })

            elif mtype == 'SOCKET_APPEARED':
                path = msg.get('path', '')
                console_name = msg.get('console_name', '')
                defn = msg.get('defn', {})
                vars_ = msg.get('vars', {})

                # Re-validate independently — don't trust watcher's judgement
                err = worker_validate_socket(path, console_store, defn, vars_)
                if err:
                    log.warning(
                        "Worker: rejecting socket %r from watcher: %s "
                        "(independent re-validation failed)",
                        path, err)
                    continue

                if defn.get('type') != 'qemu_unix':
                    continue

                try:
                    qemu_sock = socket.socket(socket.AF_UNIX,
                                              socket.SOCK_STREAM)
                    qemu_sock.connect(path)
                    fd = qemu_sock.detach()
                    hub, created = hub_registry.get_or_create(
                        console_name, fd, grace=grace)
                    if created:
                        log.info("Worker: hub created for %r via %r",
                                 console_name, path)
                    else:
                        log.info("Worker: hub already exists for %r, "
                                 "discarded new fd", console_name)
                except Exception as exc:
                    log.error("Worker: failed to connect to QEMU socket %r: %s",
                              path, exc)

            elif mtype == 'SOCKET_DISAPPEARED':
                path = msg.get('path', '')
                match = console_store.match_socket(path)
                if match:
                    defn, vars_ = match
                    name = defn.get('console_name', '')
                    try:
                        name = name.format(**vars_)
                    except KeyError:
                        pass
                    hub = hub_registry.get(name)
                    if hub:
                        log.info(
                            "Worker: socket %r disappeared, "
                            "tearing down hub %r immediately",
                            path, name)
                        hub.shutdown()
                        hub_registry.remove_if_done(name)

            else:
                log.warning("Push listener: unknown message %r", mtype)


def sock_readline(sock: socket.socket, echo: bool = True,
                  max_len: int = 256) -> bytes | None:
    buf = bytearray()
    while True:
        try:
            ch = sock.recv(1)
        except OSError:
            return None
        if not ch:
            return None
        b = ch[0]
        if b in (0x0d, 0x0a):
            if echo:
                sock.sendall(b"\r\n")
            break
        if b in (0x7f, 0x08):
            if buf:
                buf.pop()
                if echo:
                    sock.sendall(b"\b \b")
            continue
        if b == 0x03:
            return None
        if len(buf) < max_len:
            buf.append(b)
            if echo:
                sock.sendall(ch)
    return bytes(buf)


def run_console_session(sock: socket.socket, hub: ConsoleHub,
                        sid: str, read_only: bool,
                        registry: SessionRegistry):
    hub.add_client(sid, sock, read_only=read_only)
    registry.update(sid, state='console')

    if not read_only:
        escape = 0
        try:
            while not hub.is_done:
                try:
                    data = sock.recv(4096)
                except OSError:
                    break
                if not data:
                    break
                out = bytearray()
                for b in data:
                    if escape == 0:
                        if b == ord('~'):
                            escape = 1
                        else:
                            out.append(b)
                    else:
                        escape = 0
                        if b == ord('.'):
                            if out:
                                hub.write_input(bytes(out))
                            hub.remove_client(sid)
                            return
                        elif b == ord('~'):
                            out.append(ord('~'))
                        else:
                            out.append(ord('~'))
                            out.append(b)
                if out:
                    hub.write_input(bytes(out))
        except Exception:
            pass
    else:
        try:
            while not hub.is_done:
                r, _, _ = select.select([sock], [], [], 1.0)
                if r:
                    data = sock.recv(4096)
                    if not data:
                        break
                    # Discard — read-only clients cannot send input
        except Exception:
            pass

    hub.remove_client(sid)


def authenticate_client_pam(
        client_sock: socket.socket,
        monitor: MonitorProxy,
        user_map: UserMapStore,
        rate_limiter: RateLimiter,
        config: configparser.ConfigParser,
) -> str | None:
    """
    Drive the PAM login flow on client_sock.

    Sends the banner, reads username and password, applies rate limiting,
    verifies credentials via the monitor subprocess, and checks the user map.
    Returns the authenticated username on success, None on any failure or
    disconnection.  Sets login_timeout on the socket for the duration.

    Callers do not need to handle TimeoutError — it is caught and causes a
    None return with "[Login timeout.]" sent to the client.
    """
    login_timeout = config.getint('core', 'login_timeout', fallback=30)
    _MIN_LOGIN_TIME = 2.0

    try:
        client_sock.settimeout(login_timeout)
        client_sock.sendall(BANNER)

        client_sock.sendall(b"Username: ")
        ub = sock_readline(client_sock, echo=True)
        if not ub:
            return None
        username = ub.decode('utf-8', errors='replace').strip()
        if not username:
            return None

        client_sock.sendall(b"Password: ")
        pb = sock_readline(client_sock, echo=False)
        if pb is None:
            return None
        password = pb.decode('utf-8', errors='replace')

        if rate_limiter.is_limited(username):
            time.sleep(2)
            client_sock.sendall(b"\r\nLogin failed.\r\n")
            return None

        # All failure paths produce the same message and take the same
        # minimum time — an attacker cannot distinguish wrong password,
        # user not in users.yaml, or no role assigned.
        _login_start = time.monotonic()

        def _fail(reason: str) -> None:
            log.warning("Login denied: user=%r reason=%s", username, reason)
            rate_limiter.record_failure(username)
            remaining = _MIN_LOGIN_TIME - (time.monotonic() - _login_start)
            if remaining > 0:
                time.sleep(remaining)
            client_sock.sendall(b"\r\nLogin failed.\r\n")

        if not monitor.auth(username, password):
            _fail("bad_credentials")
            return None

        if not user_map.user_exists(username):
            _fail("not_in_usermap")
            return None

        role = user_map.get_role(username)
        if role is None:
            _fail("no_role")
            return None

        rate_limiter.record_success(username)
        log.info("Login: user=%r role=%r", username, role)
        return username

    except TimeoutError:
        try:
            client_sock.sendall(b"\r\n[Login timeout.]\r\n")
        except Exception:
            pass
        return None


def run_authenticated_session(
        client_sock: socket.socket,
        username: str,
        sid: str,
        monitor: MonitorProxy,
        user_map: UserMapStore,
        acl_resolver: ACLResolver,
        console_store: ConsoleConfigStore,
        registry: SessionRegistry,
        hub_registry: HubRegistry,
        config: configparser.ConfigParser,
) -> None:
    """
    Run the command loop for an already-authenticated user.

    Assumes identity has been verified by the caller.  Does not prompt for
    credentials.  Registers the session, sends "Login successful.", and runs
    the interactive command loop until the user quits, disconnects, or idles
    out.  Does not close the socket — that is the caller's responsibility.
    """
    idle_timeout = config.getint('core', 'idle_timeout', fallback=300)
    grace = config.getint('core', 'hub_grace_period', fallback=30)

    registry.add(sid, username, state='prompt', sock=client_sock)

    client_sock.settimeout(idle_timeout)
    client_sock.sendall(b"\r\nLogin successful.\r\n")

    while True:
        client_sock.sendall(PROMPT)

        try:
            line_b = sock_readline(client_sock, echo=True)
        except TimeoutError:
            client_sock.sendall(b"\r\n[Idle timeout. Disconnecting.]\r\n")
            break

        if line_b is None:
            break

        line = line_b.decode('utf-8', errors='replace').strip()
        parts = line.split()
        if not parts:
            continue
        action = parts[0].lower()

        if action in ('quit', 'exit'):
            client_sock.sendall(b"Goodbye.\r\n")
            break

        elif action == 'help':
            client_sock.sendall(HELP_TEXT)

        elif action == 'list':
            cfg = console_store.get()
            all_consoles: dict[str, tuple[dict, dict]] = {}

            for cname, defn in cfg.get('consoles', {}).items():
                all_consoles[cname] = (defn, {})

            for hub_snap in hub_registry.snapshot():
                cname = hub_snap['name']
                if cname not in all_consoles:
                    all_consoles[cname] = ({}, {})

            if not all_consoles:
                client_sock.sendall(b"No consoles defined.\r\n")
                continue

            lines = []
            for cname, (defn, vars_) in sorted(all_consoles.items()):
                level = acl_resolver.resolve_access(
                    username, cname, defn, vars_)
                if level is None:
                    continue
                hub = hub_registry.get(cname)
                clients = len(hub.snapshot()['clients']) if hub else 0
                active = "live" if hub else "idle"
                lines.append(
                    f"  {cname:<30} [{active}]  "
                    f"{clients} client(s)  [{level}]\r\n")

            if not lines:
                client_sock.sendall(b"No accessible consoles.\r\n")
            else:
                client_sock.sendall(''.join(lines).encode())

        elif action == 'console':
            if len(parts) < 2:
                client_sock.sendall(b"Usage: console <name>\r\n")
                continue

            cname = parts[1]
            cfg = console_store.get()

            defn = cfg.get('consoles', {}).get(cname)
            vars_: dict = {}
            if defn is None:
                # Try reverse-matching console_patterns by console name.
                match = console_store.match_console_name(cname)
                if match is not None:
                    defn, vars_ = match

            if defn is None:
                hub = hub_registry.get(cname)
                if hub is None:
                    # Last resort: use the defaults.console exec fallback.
                    # This lets any configured VM name be reached without
                    # an explicit definition or pattern.
                    defn = console_store.get_default_exec()
                    if defn is None:
                        client_sock.sendall(
                            b"Console not found or not active.\r\n")
                        continue

            level = acl_resolver.resolve_access(
                username, cname, defn or {}, vars_)
            if level is None:
                client_sock.sendall(b"Access denied to this console.\r\n")
                continue

            read_only = (level == 'read_only')
            hub = hub_registry.get(cname)

            if hub is None:
                if defn is None:
                    client_sock.sendall(
                        b"Console not active and no exec definition.\r\n")
                    continue

                ctype = defn.get('type', 'exec')
                if ctype != 'exec':
                    client_sock.sendall(
                        b"Console not yet active. "
                        b"Wait for the VM to connect.\r\n")
                    continue

                # Worker sends only the console name; the monitor resolves
                # cmd and run_as from its own config.
                ok, master_fd, err = monitor.spawn(username, cname)
                if not ok:
                    client_sock.sendall(f"Spawn failed: {err}\r\n".encode())
                    continue

                hub, _ = hub_registry.get_or_create(
                    cname, master_fd, grace=grace)

            mode_str = 'read-only' if read_only else 'read-write'
            client_sock.sendall(
                f"\r\n[Attached to {cname} ({mode_str}). "
                f"Escape: ~. to detach  ~~ for literal ~]\r\n".encode())
            registry.update(sid, state='console', console=cname,
                            read_only=read_only)

            client_sock.settimeout(None)
            run_console_session(client_sock, hub, sid, read_only, registry)
            hub_registry.remove_if_done(cname)

            client_sock.settimeout(idle_timeout)
            registry.update(sid, state='prompt', console=None)
            client_sock.sendall(f"\r\n[Detached from {cname}]\r\n".encode())

        elif action in console_store.get_all_commands():
            if len(parts) < 2:
                client_sock.sendall(
                    f"Usage: {action} <console_name>\r\n".encode())
                continue

            cname = parts[1]
            cfg = console_store.get()
            cmd_defn = cfg.get('consoles', {}).get(cname)
            cmd_vars: dict = {}
            if cmd_defn is None:
                # Check console_patterns so pattern rw/ro lists are
                # honoured instead of falling back to the user-map role.
                match = console_store.match_console_name(cname)
                if match is not None:
                    cmd_defn, cmd_vars = match

            level = acl_resolver.resolve_access(
                username, cname, cmd_defn or {}, cmd_vars)
            if level is None:
                client_sock.sendall(b"Access denied.\r\n")
                continue

            rendered = monitor.run_action(action, cname)
            client_sock.sendall(rendered.encode())

        else:
            client_sock.sendall(
                f"Unknown command: {action!r}. Type 'help'.\r\n".encode())


def _close_client_socket(sock: socket.socket) -> None:
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass
    try:
        sock.close()
    except Exception:
        pass


def handle_client(client_sock: socket.socket,
                  monitor: MonitorProxy,
                  user_map: UserMapStore,
                  acl_resolver: ACLResolver,
                  console_store: ConsoleConfigStore,
                  registry: SessionRegistry,
                  hub_registry: HubRegistry,
                  rate_limiter: RateLimiter,
                  config: configparser.ConfigParser):
    log.debug("handle_client: fd=%d", client_sock.fileno())
    sid = str(uuid.uuid4())
    try:
        username = authenticate_client_pam(
            client_sock, monitor, user_map, rate_limiter, config)
        if username is None:
            return
        run_authenticated_session(
            client_sock, username, sid,
            monitor, user_map, acl_resolver, console_store,
            registry, hub_registry, config)
    except Exception:
        log.exception("handle_client error")
    finally:
        registry.remove(sid)
        _close_client_socket(client_sock)


def run_worker(rpc_sock: socket.socket, push_sock: socket.socket,
               watch_sock: socket.socket,
               server_sock: socket.socket,
               config: configparser.ConfigParser,
               user_map: UserMapStore,
               console_store: ConsoleConfigStore,
               worker_pw,
               no_seccomp: bool = False,
               no_landlock: bool = False):
    set_proc_title(f"worker ({worker_pw.pw_name})")
    for h in logging.getLogger().handlers:
        h.setLevel(logging.NOTSET)
    log.info("Worker started (pid=%d), dropping to %r",
             os.getpid(), worker_pw.pw_name)

    os.setgroups([])
    os.setgid(worker_pw.pw_gid)
    os.setuid(worker_pw.pw_uid)

    socket_path = config.get('core', 'socket_path')
    max_threads = config.getint('core', 'max_threads', fallback=64)
    max_failures = config.getint('auth', 'max_failures', fallback=5)
    fail_window = config.getfloat('auth', 'failure_window', fallback=120)
    lockout_dur = config.getfloat('auth', 'lockout_duration', fallback=60)
    watch_dir = console_store.get_watch_dir()

    registry = SessionRegistry()
    hub_registry = HubRegistry()
    acl_resolver = ACLResolver(user_map)
    monitor = MonitorProxy(rpc_sock)
    rate_limiter = RateLimiter(max_failures, fail_window, lockout_dur)

    if no_landlock:
        log.warning("Worker: skipping landlock")
    else:
        apply_landlock(socket_path, watch_dir)

    if no_seccomp:
        log.warning("Worker: skipping seccomp")
    else:
        apply_seccomp()

    threading.Thread(
        target=monitor_push_listener,
        args=(push_sock, watch_sock, registry, hub_registry,
              acl_resolver, console_store, user_map, monitor, config),
        daemon=True,
        name='push-listener',
    ).start()

    def reaper():
        while True:
            time.sleep(60)
            rate_limiter.reap()

    threading.Thread(target=reaper, daemon=True, name='reaper').start()

    semaphore = threading.Semaphore(max_threads)
    log.info("Worker accepting on %s", socket_path)

    while True:
        try:
            client_sock, peer = server_sock.accept()
            if not semaphore.acquire(blocking=False):
                log.warning("Thread limit, dropping connection")
                try:
                    client_sock.sendall(b"Server at capacity.\r\n")
                    client_sock.close()
                except Exception:
                    pass
                continue

            def dispatch(sock):
                try:
                    handle_client(sock, monitor, user_map, acl_resolver,
                                  console_store, registry, hub_registry,
                                  rate_limiter, config)
                finally:
                    semaphore.release()

            threading.Thread(
                target=dispatch, args=(client_sock,),
                daemon=True, name=f"conn-{peer}",
            ).start()

        except KeyboardInterrupt:
            break
        except Exception:
            log.exception("Accept error")

    log.info("Worker exiting")
