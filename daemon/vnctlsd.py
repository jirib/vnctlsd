#!/usr/bin/env python3
"""
vnctlsd — privileged-separated virsh console dispatcher
        — Conserver-style: server drives the terminal, client is a dumb pipe

Architecture
------------
  Must be started as root.  Forks into three processes:

  MONITOR (root)
    - PAM auth in short-lived subprocess per attempt
    - virsh console spawn (fork + setuid + exec)
    - management commands
    - SIGHUP: reload user map + console config + send RELOAD_WATCH to watcher
    - SIGUSR1: request session list from worker
    - SIGUSR2: reload + enforce ACL (kill stale sessions)
    - socketpairs: rpc↔worker, push↔worker, ctl↔watcher

  WORKER (_vnctlsd)
    - unix socket listener (TLS terminated by ghostunnel/stunnel upstream)
    - server-side terminal per connection: login prompt, vnctlsd> prompt,
      console attach/detach inline
    - ConsoleHub fan-out: one fd shared across multiple clients
    - receives SOCKET_APPEARED/DISAPPEARED from watcher, re-validates
      independently before acting
    - seccomp: socket I/O, futex, clone, rseq — no inotify, no openat
    - landlock: watch_dir + client socket dir + /dev

  WATCHER (_vnctlsd-watch or same user as worker)
    - inotify on configured watch directories
    - directory permission check (world-writable = error, refuse to watch)
    - lstat validation of appeared sockets (uid, not world-writable, S_ISSOCK)
    - glob pattern matching against console definitions
    - sends SOCKET_APPEARED/DISAPPEARED to worker
    - receives RELOAD_WATCH from monitor → restarts inotify on new path
    - seccomp: inotify_*, read, write, openat, lstat, sendmsg, futex, rseq
    - landlock: watch directories read-only

Client
------
  Any TLS raw socket in raw terminal mode:
    socat $(tty),raw,echo=0 OPENSSL:host:8443,verify=0

  Or the minimal Go client (vnctl) for Windows compatibility.

Console definitions  (consoles.yaml)
-------------------------------------
  socket_validation:           # global defaults
    trusted_uid: libvirt-qemu
    watch_dir: /run/vnctlsd/

  consoles:                    # explicit definitions (highest priority)
    vm-special:
      type: qemu_unix
      socket: /run/vnctlsd/console-vm-special.sock
      validation:
        trusted_uid: root      # override for this console
      rw: [admin]
      ro: []

  console_patterns:            # glob-based (matched when no explicit def)
    - socket_glob: /run/vnctlsd/console-{name}.sock
      type: qemu_unix
      console_name: "{name}"
      validation:
        trusted_uid: libvirt-qemu
      rw: ["{name}"]
      ro: [mentors]

    - socket_glob: /run/vnctlsd/exec-{name}.sock
      type: exec
      console_name: "{name}"
      cmd: "virsh -c qemu:///system console {name} --force"
      rw: ["{name}"]
      ro: [mentors]

User map  (users.yaml)
-----------------------
  users:
    student01:
      groups: [lab-a]
    jbelka:
      groups: [mentors]

  groups:
    lab-a:
      role: read_write
    mentors:
      role: read_only

Signals
-------
  SIGHUP  → reload config (non-destructive)
  SIGUSR1 → log active sessions + hub state
  SIGUSR2 → reload + kill sessions for revoked consoles

Usage
-----
  vnctlsd [--config vnctlsd.ini] [--users users.yaml]
           [--consoles consoles.yaml]
           [--no-privsep] [--no-seccomp] [--no-landlock] [--debug]
"""

import argparse
import array
import configparser
import ctypes
import ctypes.util
import fnmatch
import json
import logging
import os
import pty
import pwd
import re
import resource
import select
import shlex
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import uuid

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(process)d/%(processName)s/%(threadName)s: %(message)s',
    handlers=[logging.StreamHandler(sys.stderr)],
)
# Set handler level to NOTSET so the root logger level is the sole gate.
# Without this, basicConfig sets the handler to INFO and --debug's
# setLevel(DEBUG) on the root logger has no effect.
logging.getLogger().handlers[0].setLevel(logging.NOTSET)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Process title
# ---------------------------------------------------------------------------

def set_proc_title(title: str):
    import multiprocessing
    multiprocessing.current_process().name = title
    try:
        import setproctitle
        setproctitle.setproctitle(f"vnctlsd: {title}")
        return
    except ImportError:
        pass
    try:
        argv0 = f"vnctlsd: {title}".encode()
        buf   = (ctypes.c_char * len(sys.argv[0])).from_address(
            ctypes.cast(ctypes.c_char_p(sys.argv[0].encode()),
                        ctypes.c_void_p).value)
        buf.value = argv0[:len(sys.argv[0]) - 1] + b'\x00'
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Default daemon INI config
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = """
[core]
socket_path      = /run/vnctlsd/vnctlsd.sock
socket_mode      = 0660
socket_group     = _vnctlsd
worker_user      = _vnctlsd
watcher_user     = _vnctlsd
pidfile          = /run/vnctlsd/vnctlsd.pid
max_threads      = 64
hub_grace_period = 30
login_timeout    = 30
idle_timeout     = 300

[auth]
max_failures     = 5
lockout_duration = 60
failure_window   = 120
"""

BANNER = (
    b"\r\nvnctlsd - virsh console dispatcher\r\n"
    b"Type 'help' for available commands.\r\n\r\n"
)

HELP_TEXT = (
    b"Commands:\r\n"
    b"  list                  list accessible consoles and their state\r\n"
    b"  console <name>        attach to a console\r\n"
    b"  status  <name>        show VM power state\r\n"
    b"  start   <name>        start VM\r\n"
    b"  reset   <name>        graceful reboot\r\n"
    b"  force_reset <name>    hard reset\r\n"
    b"  poweroff <name>       hard poweroff\r\n"
    b"  help                  this text\r\n"
    b"  quit / exit           disconnect\r\n"
    b"\r\n"
    b"Console escape sequences (while attached):\r\n"
    b"  ~.    detach and return to prompt\r\n"
    b"  ~~    send a literal ~ to the console\r\n"
    b"\r\n"
)

PROMPT = b"vnctlsd> "

# ---------------------------------------------------------------------------
# Glob pattern matching with named captures
#
# Supports {name} placeholders in glob patterns.
# Example: /run/vnctlsd/console-{name}.sock
# Converted to fnmatch pattern and regex for capture extraction.
# ---------------------------------------------------------------------------

def compile_glob_pattern(glob_str: str) -> tuple[str, re.Pattern]:
    """
    Convert a glob string with {name} placeholders to:
    - an fnmatch pattern (for fast pre-filtering)
    - a regex (for capture extraction)

    Example:
      "/run/vnctlsd/console-{name}.sock"
      → fnmatch: "/run/vnctlsd/console-*.sock"
      → regex:   r"^/run/vnctlsd/console-(?P<name>[^/]+)[.]sock$"
    """
    # Build fnmatch pattern: replace {x} with *
    fnmatch_pat = re.sub(r'\{[^}]+\}', '*', glob_str)

    # Build regex: escape everything, then replace \{name\} with named group
    escaped = re.escape(glob_str)
    # re.escape turns { } into \{ \}, so we search for \\\{name\\\}
    regex_str = re.sub(
        r'\\{([^}]+)\\}',
        lambda m: f'(?P<{m.group(1)}>[^/]+)',
        escaped
    )
    regex = re.compile(f'^{regex_str}$')
    return fnmatch_pat, regex


def match_glob_pattern(path: str, fnmatch_pat: str,
                        regex: re.Pattern) -> dict | None:
    """
    Returns dict of captured variables if path matches, else None.
    """
    if not fnmatch.fnmatch(path, fnmatch_pat):
        return None
    m = regex.match(path)
    if not m:
        return None
    return m.groupdict()

# ---------------------------------------------------------------------------
# Console configuration loader
# ---------------------------------------------------------------------------

def load_console_config(path: str) -> dict:
    """
    Load consoles.yaml / consoles.toml.
    Returns:
    {
      'socket_validation': {
          'trusted_uid': 'libvirt-qemu',
          'watch_dir':   '/run/vnctlsd/',
      },
      'consoles': {
          'vm-special': {
              'type': 'qemu_unix',
              'socket': '/run/vnctlsd/console-vm-special.sock',
              'validation': {'trusted_uid': 'root'},
              'rw': ['admin'],
              'ro': [],
          },
      },
      'console_patterns': [
          {
              'socket_glob': '/run/vnctlsd/console-{name}.sock',
              'type': 'qemu_unix',
              'console_name': '{name}',
              'validation': {'trusted_uid': 'libvirt-qemu'},
              'rw': ['{name}'],
              'ro': ['mentors'],
              '_fnmatch': '...',   # compiled
              '_regex':   ...,     # compiled
          },
      ],
    }
    """
    ext = os.path.splitext(path)[1].lower()
    if ext in ('.yaml', '.yml'):
        try:
            import yaml
        except ImportError:
            raise RuntimeError("PyYAML required: pip install pyyaml")
        with open(path, 'r') as fh:
            data = yaml.safe_load(fh) or {}
    elif ext == '.toml':
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib
            except ImportError:
                raise RuntimeError("tomli required: pip install tomli")
        with open(path, 'rb') as fh:
            data = tomllib.load(fh)
    else:
        raise ValueError(f"Unsupported format: {ext}")

    # Compile glob patterns
    for pat in data.get('console_patterns', []):
        if 'socket_glob' in pat:
            fnmatch_pat, regex = compile_glob_pattern(pat['socket_glob'])
            pat['_fnmatch'] = fnmatch_pat
            pat['_regex']   = regex

    return data


class ConsoleConfigStore:
    """Thread-safe, hot-reloadable console configuration."""

    def __init__(self, initial: dict):
        self._cfg  = initial
        self._lock = threading.RLock()

    def get(self) -> dict:
        with self._lock:
            return self._cfg

    def reload(self, path: str) -> dict:
        new_cfg = load_console_config(path)
        with self._lock:
            self._cfg = new_cfg
        return new_cfg

    def match_socket(self, socket_path: str) -> tuple[dict, dict] | None:
        """
        Find the console definition matching socket_path.
        Returns (definition, template_vars) or None.
        Checks explicit consoles first, then patterns.
        """
        with self._lock:
            cfg = self._cfg

        # Explicit consoles — match by socket path
        for name, defn in cfg.get('consoles', {}).items():
            if defn.get('socket') == socket_path:
                return dict(defn, _console_name=name), {}

        # Pattern-based
        for pat in cfg.get('console_patterns', []):
            if '_fnmatch' not in pat:
                continue
            vars_ = match_glob_pattern(
                socket_path, pat['_fnmatch'], pat['_regex'])
            if vars_ is not None:
                return dict(pat), vars_

        return None

    def resolve_trusted_uid(self, defn: dict, vars_: dict) -> int | None:
        """
        Resolve trusted_uid from definition or global default.
        Template vars are substituted.  Returns numeric uid or None.
        """
        with self._lock:
            global_uid_name = (self._cfg
                               .get('socket_validation', {})
                               .get('trusted_uid', ''))

        uid_name = (defn.get('validation', {})
                    .get('trusted_uid', global_uid_name))

        if not uid_name:
            return None

        # Substitute template vars
        try:
            uid_name = uid_name.format(**vars_)
        except KeyError:
            pass

        # Resolve name to uid
        try:
            return pwd.getpwnam(uid_name).pw_uid
        except KeyError:
            try:
                return int(uid_name)
            except ValueError:
                log.error("Cannot resolve trusted_uid %r to a uid", uid_name)
                return None

    def get_watch_dir(self) -> str:
        with self._lock:
            return (self._cfg
                    .get('socket_validation', {})
                    .get('watch_dir', '/run/vnctlsd/'))

# ---------------------------------------------------------------------------
# User map loader
# ---------------------------------------------------------------------------

def load_user_map(path: str) -> dict:
    """
    Load users.yaml / users.toml.

    Format:
      users:
        student01:
          groups: [lab-a]
        jbelka:
          groups: [mentors]

      groups:
        lab-a:
          role: read_write
        mentors:
          role: read_only
    """
    ext = os.path.splitext(path)[1].lower()
    if ext in ('.yaml', '.yml'):
        try:
            import yaml
        except ImportError:
            raise RuntimeError("PyYAML required: pip install pyyaml")
        with open(path, 'r') as fh:
            data = yaml.safe_load(fh) or {}
    elif ext == '.toml':
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib
            except ImportError:
                raise RuntimeError("tomli required: pip install tomli")
        with open(path, 'rb') as fh:
            data = tomllib.load(fh)
    else:
        raise ValueError(f"Unsupported format: {ext}")

    return data


class UserMapStore:
    """Thread-safe, hot-reloadable user/group map."""

    def __init__(self, initial: dict):
        self._map  = initial
        self._lock = threading.RLock()

    def reload(self, path: str) -> dict:
        new_map = load_user_map(path)
        with self._lock:
            self._map = new_map
        return new_map

    def get_groups(self, username: str) -> list[str]:
        with self._lock:
            entry = self._map.get('users', {}).get(username, {})
            if isinstance(entry, dict):
                return list(entry.get('groups', []))
            return []

    def get_role(self, username: str) -> str | None:
        """
        Resolve the user's effective role from their group memberships.
        read_write takes priority over read_only if user is in both.
        Returns None if user has no groups or no role defined.
        """
        with self._lock:
            groups     = self.get_groups(username)
            group_defs = self._map.get('groups', {})

        if not groups:
            return None

        roles = set()
        for g in groups:
            gdef = group_defs.get(g, {})
            role = gdef.get('role') if isinstance(gdef, dict) else None
            if role:
                roles.add(role)

        if not roles:
            return None
        if 'read_write' in roles:
            return 'read_write'
        return 'read_only'

    def user_exists(self, username: str) -> bool:
        with self._lock:
            return username in self._map.get('users', {})

    def get_map(self) -> dict:
        with self._lock:
            return dict(self._map)

# ---------------------------------------------------------------------------
# ACL Resolver
# ---------------------------------------------------------------------------

class ACLResolver:
    """
    Determines whether a user can access a console and in what mode.

    resolve_access(username, console_name, console_def, template_vars)
      → 'read_write' | 'read_only' | None (denied)

    Resolution order:
      1. console definition rw/ro lists (explicit or pattern-derived)
         - list entries can be usernames, group names, or '*'
         - template vars substituted (e.g. rw: ["{name}"] → rw: ["vm-lab01"])
      2. user's group role (from user map)

    Console definition wins if it has explicit rw/ro entries.
    User map role is the fallback.
    """

    def __init__(self, user_map: UserMapStore):
        self._user_map = user_map

    def resolve_access(self, username: str, console_name: str,
                        console_def: dict, template_vars: dict
                        ) -> str | None:
        if not self._user_map.user_exists(username):
            return None

        user_groups = set(self._user_map.get_groups(username))

        def matches_principal(principals: list[str]) -> bool:
            for p in principals:
                try:
                    p_resolved = p.format(**template_vars)
                except KeyError:
                    p_resolved = p
                if p_resolved == '*':
                    return True
                if p_resolved == username:
                    return True
                if p_resolved in user_groups:
                    return True
            return False

        rw_list = console_def.get('rw', [])
        ro_list = console_def.get('ro', [])

        # If the console has explicit ACL entries, they take priority
        if rw_list or ro_list:
            if matches_principal(rw_list):
                return 'read_write'
            if matches_principal(ro_list):
                return 'read_only'
            # Console has ACL but user not in it
            return None

        # No console ACL — fall back to user map role
        return self._user_map.get_role(username)

# ---------------------------------------------------------------------------
# ConsoleHub — shared fd fan-out
# ---------------------------------------------------------------------------

class ConsoleHub:
    """
    One hub per active console.  A single background thread reads from
    the console fd and broadcasts to all connected clients.
    Read-write clients write keystrokes back; read-only clients receive only.
    """

    def __init__(self, name: str, fd: int, grace_period: int = 30):
        self.name      = name
        self.fd        = fd        # pty master or connected unix socket
        self._grace    = grace_period
        self._lock     = threading.Lock()
        self._clients: dict[str, dict] = {}
        self._done     = threading.Event()
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
                    c['sock'].sendall(
                        b"\r\n[INFO] Console terminated\r\n")
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
                'name':    self.name,
                'clients': [{'id': cid[:8], 'ro': c['read_only']}
                            for cid, c in self._clients.items()],
            }

    @property
    def is_done(self) -> bool:
        return self._done.is_set()

# ---------------------------------------------------------------------------
# HubRegistry
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# SessionRegistry
# ---------------------------------------------------------------------------

class SessionRegistry:
    def __init__(self):
        self._sessions: dict[str, dict] = {}
        self._socks:    dict[str, socket.socket] = {}
        self._lock      = threading.Lock()

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

    def kill_stale(self, acl_resolver: 'ACLResolver',
                   console_store: ConsoleConfigStore) -> tuple[list, list]:
        """
        Disconnect sessions whose console access has been revoked.
        Called on SIGUSR2 after config reload.
        """
        killed   = []
        retained = []
        with self._lock:
            stale = []
            for sid, s in self._sessions.items():
                if s['state'] != 'console' or not s.get('console'):
                    retained.append(f"{s['username']} (at prompt)")
                    continue
                console_name = s['console']
                cfg          = console_store.get()
                # Find console definition
                defn = cfg.get('consoles', {}).get(console_name)
                vars_ = {}
                if defn is None:
                    # Try patterns
                    for pat in cfg.get('console_patterns', []):
                        sock_path = (cfg.get('consoles', {})
                                     .get(console_name, {})
                                     .get('socket', ''))
                        if '_fnmatch' in pat:
                            v = match_glob_pattern(
                                sock_path,
                                pat['_fnmatch'], pat['_regex'])
                            if v is not None:
                                defn  = pat
                                vars_ = v
                                break
                if defn is None:
                    # Console no longer defined — kill session
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

# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    def __init__(self, max_failures: int, failure_window: float,
                 lockout_duration: float):
        self._max     = max_failures
        self._window  = failure_window
        self._lockout = lockout_duration
        self._lock    = threading.Lock()
        self._state: dict = {}

    def is_limited(self, username: str) -> bool:
        now = time.monotonic()
        with self._lock:
            s = self._state.get(username)
            return s is not None and s.get('locked_until', 0) > now

    def record_failure(self, username: str):
        now = time.monotonic()
        with self._lock:
            s = self._state.setdefault(username,
                                       {'failures': [], 'locked_until': 0.0})
            s['failures'] = [t for t in s['failures']
                             if now - t < self._window]
            s['failures'].append(now)
            if len(s['failures']) >= self._max:
                s['locked_until'] = now + self._lockout
                log.warning("Rate limit: locked out %r for %.0fs",
                            username, self._lockout)
                s['failures'] = []

    def record_success(self, username: str):
        with self._lock:
            self._state.pop(username, None)

    def reap(self):
        now = time.monotonic()
        with self._lock:
            stale = [
                u for u, s in self._state.items()
                if s.get('locked_until', 0) < now and
                   all(now - t > self._window for t in s.get('failures', []))
            ]
            for u in stale:
                del self._state[u]

# ---------------------------------------------------------------------------
# Monitor↔worker/watcher IPC
# ---------------------------------------------------------------------------

_IPC_MAX_FDS    = 4
_IPC_MAX_MSG    = 65536
_IPC_CMSG_SPACE = socket.CMSG_SPACE(_IPC_MAX_FDS * __import__('array').array('i').itemsize)


def ipc_send(sock: socket.socket, msg: dict,
             fds: list[int] | None = None):
    import array as _array
    payload  = json.dumps(msg).encode()
    fd_count = len(fds) if fds else 0
    header   = struct.pack('>BI', fd_count, len(payload))
    log.debug("ipc_send: type=%r fd_count=%d", msg.get('type'), fd_count)
    if fds:
        cmsg = _array.array('i', fds)
        sock.sendmsg(
            [header + payload],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, cmsg)],
        )
    else:
        sock.sendall(header + payload)


def ipc_recv(sock: socket.socket) -> tuple[dict, list[int]]:
    import array as _array
    data, ancdata, _, _ = sock.recvmsg(_IPC_MAX_MSG, _IPC_CMSG_SPACE)
    if not data:
        raise EOFError("IPC socket closed")
    if len(data) < 5:
        raise EOFError(f"IPC short read: {len(data)} bytes")

    fd_count, length = struct.unpack('>BI', data[:5])
    payload = data[5:]

    while len(payload) < length:
        chunk = sock.recv(length - len(payload))
        if not chunk:
            raise EOFError("IPC closed during payload read")
        payload += chunk

    fds = []
    for lvl, typ, cmsg_data in ancdata:
        if lvl == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS:
            arr = _array.array('i')
            arr.frombytes(
                cmsg_data[:len(cmsg_data) - (len(cmsg_data) % arr.itemsize)])
            fds.extend(arr)

    msg = json.loads(payload)
    log.debug("ipc_recv: type=%r fds=%r", msg.get('type'), fds)
    return msg, fds

# ---------------------------------------------------------------------------
# PAM authentication
# ---------------------------------------------------------------------------

PAM_SUCCESS         = 0
PAM_PROMPT_ECHO_OFF = 1
PAM_PROMPT_ECHO_ON  = 2
PAM_ERROR_MSG       = 3
PAM_TEXT_INFO       = 4


class _PamMessage(ctypes.Structure):
    _fields_ = [("msg_style", ctypes.c_int), ("msg", ctypes.c_char_p)]

class _PamResponse(ctypes.Structure):
    _fields_ = [("resp", ctypes.c_void_p), ("resp_retcode", ctypes.c_int)]

_CONV_FUNC = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.c_int,
    ctypes.POINTER(ctypes.POINTER(_PamMessage)),
    ctypes.POINTER(ctypes.POINTER(_PamResponse)),
    ctypes.c_void_p,
)

class _PamConv(ctypes.Structure):
    _fields_ = [("conv", _CONV_FUNC), ("appdata_ptr", ctypes.c_void_p)]

_libc = ctypes.CDLL(ctypes.util.find_library("c"))
_libc.calloc.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
_libc.calloc.restype  = ctypes.c_void_p
_libc.strdup.argtypes = [ctypes.c_char_p]
_libc.strdup.restype  = ctypes.c_void_p

_pam_lib = ctypes.util.find_library("pam")
if not _pam_lib:
    log.error("libpam not found")
    sys.exit(1)

_pam = ctypes.CDLL(_pam_lib)
_pam.pam_start.argtypes        = [ctypes.c_char_p, ctypes.c_char_p,
                                   ctypes.POINTER(_PamConv),
                                   ctypes.POINTER(ctypes.c_void_p)]
_pam.pam_start.restype         = ctypes.c_int
_pam.pam_authenticate.argtypes = [ctypes.c_void_p, ctypes.c_int]
_pam.pam_authenticate.restype  = ctypes.c_int
_pam.pam_acct_mgmt.argtypes    = [ctypes.c_void_p, ctypes.c_int]
_pam.pam_acct_mgmt.restype     = ctypes.c_int
_pam.pam_end.argtypes          = [ctypes.c_void_p, ctypes.c_int]
_pam.pam_end.restype           = ctypes.c_int


def verify_credentials(username: str, password: str,
                        service: str = "login") -> bool:
    u, p, s = username.encode(), password.encode(), service.encode()

    def conv_cb(num_msg, msg, resp, _):
        addr = _libc.calloc(num_msg, ctypes.sizeof(_PamResponse))
        if not addr:
            return 1
        arr = ctypes.cast(addr, ctypes.POINTER(_PamResponse))
        for i in range(num_msg):
            style = msg[i].contents.msg_style
            if style == PAM_PROMPT_ECHO_OFF:
                arr[i].resp = _libc.strdup(p); arr[i].resp_retcode = 0
            elif style == PAM_PROMPT_ECHO_ON:
                arr[i].resp = _libc.strdup(u); arr[i].resp_retcode = 0
            elif style in (PAM_ERROR_MSG, PAM_TEXT_INFO):
                arr[i].resp = None; arr[i].resp_retcode = 0
            else:
                return 1
        resp[0] = arr
        return PAM_SUCCESS

    cb     = _CONV_FUNC(conv_cb)
    conv   = _PamConv(cb, None)
    handle = ctypes.c_void_p()

    if _pam.pam_start(s, u, ctypes.byref(conv),
                      ctypes.byref(handle)) != PAM_SUCCESS:
        return False
    rc = _pam.pam_authenticate(handle, 0)
    if rc != PAM_SUCCESS:
        _pam.pam_end(handle, rc)
        return False
    rc = _pam.pam_acct_mgmt(handle, 0)
    _pam.pam_end(handle, PAM_SUCCESS)
    return rc == PAM_SUCCESS


def verify_credentials_subprocess(username: str, password: str) -> bool:
    """PAM in a short-lived child — password freed by OS on exit."""
    r_fd, w_fd = os.pipe()
    pid        = os.fork()
    if pid == 0:
        try:
            os.close(r_fd)
            prctl_no_new_privs()
            resource.setrlimit(resource.RLIMIT_NPROC,  (0, 0))
            resource.setrlimit(resource.RLIMIT_NOFILE, (16, 16))
            ok = verify_credentials(username, password)
            os.write(w_fd, b'\x01' if ok else b'\x00')
        except Exception:
            try:
                os.write(w_fd, b'\x00')
            except Exception:
                pass
        finally:
            try:
                os.close(w_fd)
            except Exception:
                pass
        os._exit(0)

    os.close(w_fd)
    try:
        result = os.read(r_fd, 1)
    except OSError:
        result = b'\x00'
    finally:
        os.close(r_fd)
    try:
        os.waitpid(pid, 0)
    except Exception:
        pass
    return result == b'\x01'

# ---------------------------------------------------------------------------
# prctl
# ---------------------------------------------------------------------------

def prctl_no_new_privs():
    libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:
        log.warning("prctl(PR_SET_NO_NEW_PRIVS) failed")
    else:
        log.info("PR_SET_NO_NEW_PRIVS set")

# ---------------------------------------------------------------------------
# Monitor process
# ---------------------------------------------------------------------------

def run_monitor(rpc_sock: socket.socket, push_sock: socket.socket,
                ctl_sock: socket.socket,
                users_path: str, consoles_path: str,
                config: configparser.ConfigParser,
                user_map_store: UserMapStore,
                console_store: ConsoleConfigStore):
    set_proc_title("monitor")
    # Re-apply root logger level after fork — the level is inherited but
    # re-asserting it ensures handler levels are also correct.
    for h in logging.getLogger().handlers:
        h.setLevel(logging.NOTSET)
    log.info("Monitor started (pid=%d)", os.getpid())

    def reload_all():
        try:
            user_map_store.reload(users_path)
            log.info("User map reloaded from %s", users_path)
        except Exception as exc:
            log.error("User map reload failed: %s", exc)
        try:
            console_store.reload(consoles_path)
            log.info("Console config reloaded from %s", consoles_path)
        except Exception as exc:
            log.error("Console config reload failed: %s", exc)
        # Tell watcher to restart on (possibly changed) watch_dir
        try:
            ipc_send(ctl_sock, {
                'type':     'RELOAD_WATCH',
                'watch_dir': console_store.get_watch_dir(),
            })
        except Exception as exc:
            log.error("RELOAD_WATCH send failed: %s", exc)

    def handle_sighup(signum, frame):
        log.info("SIGHUP — reloading config")
        reload_all()

    def handle_sigusr1(signum, frame):
        log.info("SIGUSR1 — requesting session list")
        try:
            ipc_send(push_sock, {'type': 'SESSION_LIST_REQ'})
        except Exception as exc:
            log.error("SESSION_LIST_REQ failed: %s", exc)

    def handle_sigusr2(signum, frame):
        log.info("SIGUSR2 — reloading and enforcing ACL")
        reload_all()
        try:
            ipc_send(push_sock, {
                'type':     'ENFORCE_REQ',
                'user_map': user_map_store.get_map(),
            })
        except Exception as exc:
            log.error("ENFORCE_REQ failed: %s", exc)

    def handle_sigchld(signum, frame):
        try:
            while True:
                pid, status = os.waitpid(-1, os.WNOHANG)
                if pid == 0:
                    break
                log.debug("Reaped child pid=%d status=%d", pid, status)
        except ChildProcessError:
            pass

    signal.signal(signal.SIGHUP,  handle_sighup)
    signal.signal(signal.SIGUSR1, handle_sigusr1)
    signal.signal(signal.SIGUSR2, handle_sigusr2)
    signal.signal(signal.SIGCHLD, handle_sigchld)

    # MonitorProxy for the monitor's own sequence number tracking
    seq = [0]

    def next_seq():
        seq[0] = (seq[0] + 1) & 0xFFFFFFFF
        return seq[0]

    while True:
        try:
            readable, _, _ = select.select(
                [rpc_sock, push_sock, ctl_sock], [], [])
        except Exception:
            log.exception("select error in monitor")
            break

        for active in readable:
            try:
                msg, fds = ipc_recv(active)
            except EOFError:
                log.info("IPC socket closed, monitor exiting")
                return
            except Exception:
                log.exception("IPC recv error")
                return

            mtype = msg.get('type')

            # -- rpc_sock messages -------------------------------------------

            if mtype == 'AUTH_REQ':
                ok = verify_credentials_subprocess(
                    msg['username'], msg['password'])
                log.info("AUTH %s: %s", msg['username'],
                         "ok" if ok else "FAILED")
                ipc_send(rpc_sock, {'type': 'AUTH_RESP', 'ok': ok,
                                    'seq': msg.get('seq')})

            elif mtype == 'CMD_REQ':
                cmd = msg.get('cmd', [])
                log.debug("CMD_REQ: %r", cmd)
                try:
                    out = subprocess.check_output(
                        cmd, stderr=subprocess.STDOUT
                    ).decode('utf-8', errors='replace').strip()
                except subprocess.CalledProcessError as e:
                    out = f"ERROR: {e.output.decode('utf-8', errors='replace').strip()}"
                except Exception as e:
                    out = f"ERROR: {e}"
                ipc_send(rpc_sock, {'type': 'CMD_RESP', 'output': out,
                                    'seq': msg.get('seq')})

            elif mtype == 'SPAWN_REQ':
                username    = msg['username']
                console_name = msg['console']
                cmd_template = msg['cmd']
                run_as_name  = msg['run_as']

                try:
                    pw = pwd.getpwnam(run_as_name)
                except KeyError:
                    log.error("SPAWN_REQ: unknown run_as %r", run_as_name)
                    ipc_send(rpc_sock, {'type': 'SPAWN_RESP', 'ok': False,
                                        'error': f"unknown user {run_as_name!r}",
                                        'seq': msg.get('seq')})
                    continue

                cmd = shlex.split(cmd_template)
                try:
                    master_fd, slave_fd = pty.openpty()
                    child = os.fork()
                    if child == 0:
                        try:
                            import fcntl as _fcntl
                            os.close(master_fd)
                            os.setgid(pw.pw_gid)
                            os.setuid(pw.pw_uid)
                            os.setsid()
                            _fcntl.ioctl(slave_fd, 0x540E, 0)  # TIOCSCTTY
                            for fd in (0, 1, 2):
                                os.dup2(slave_fd, fd)
                            os.close(slave_fd)
                            os.execvp(cmd[0], cmd)
                        except Exception as e:
                            os.write(2, f"spawn error: {e}\n".encode())
                        os._exit(1)

                    os.close(slave_fd)
                    log.info("Spawned: console=%r cmd=%r pid=%d user=%r",
                             console_name, cmd_template, child, run_as_name)
                    ipc_send(rpc_sock, {'type': 'SPAWN_RESP', 'ok': True,
                                        'pid': child,
                                        'seq': msg.get('seq')},
                             fds=[master_fd])
                    os.close(master_fd)

                except Exception as exc:
                    log.exception("SPAWN_REQ failed")
                    try:
                        ipc_send(rpc_sock, {'type': 'SPAWN_RESP', 'ok': False,
                                            'error': str(exc),
                                            'seq': msg.get('seq')})
                    except Exception:
                        pass

            # -- push_sock messages ------------------------------------------

            elif mtype == 'SESSION_LIST_RESP':
                sessions = msg.get('sessions', [])
                hubs     = msg.get('hubs', [])
                log.info("Sessions (%d):", len(sessions))
                for s in sessions:
                    elapsed = time.monotonic() - s['started']
                    h, m    = divmod(int(elapsed), 3600)
                    m, sec  = divmod(m, 60)
                    log.info("  %-20s %-25s [%s] %02d:%02d:%02d",
                             s['username'],
                             s.get('console') or '(prompt)',
                             'ro' if s.get('read_only') else 'rw',
                             h, m, sec)
                log.info("Hubs (%d):", len(hubs))
                for hub in hubs:
                    log.info("  %-25s clients=%d", hub['name'],
                             len(hub['clients']))

            elif mtype == 'ENFORCE_RESP':
                for desc in msg.get('killed', []):
                    log.info("KILLED: %s", desc)
                log.info("Enforcement: %d killed, %d retained",
                         len(msg.get('killed', [])),
                         len(msg.get('retained', [])))

            # -- ctl_sock messages (from watcher) ----------------------------

            elif mtype == 'WATCHER_READY':
                log.info("Watcher ready, watching: %r", msg.get('watch_dir'))

            elif mtype == 'WATCHER_DIR_ERROR':
                log.error("Watcher: %s", msg.get('error'))

            else:
                log.warning("Monitor: unknown message type %r", mtype)

    log.info("Monitor exiting")

# ---------------------------------------------------------------------------
# Watcher process
# ---------------------------------------------------------------------------

# inotify constants
_IN_CREATE      = 0x00000100
_IN_DELETE      = 0x00000200
_IN_MOVED_FROM  = 0x00000040
_IN_MOVED_TO    = 0x00000080
_IN_ONLYDIR     = 0x01000000

_INOTIFY_EVENT  = struct.Struct('iIII')  # wd, mask, cookie, len


def _check_dir_permissions(watch_dir: str) -> str | None:
    """
    Check watch directory permissions.
    Returns error string if world-writable (must refuse to watch),
    None if OK.
    """
    try:
        st = os.lstat(watch_dir)
    except OSError as e:
        return f"Cannot stat watch directory {watch_dir!r}: {e}"

    if not stat.S_ISDIR(st.st_mode):
        return f"{watch_dir!r} is not a directory"

    if st.st_mode & stat.S_IWOTH:
        return (
            f"Watch directory {watch_dir!r} is world-writable "
            f"(mode={oct(stat.S_IMODE(st.st_mode))}).\n"
            f"  An attacker could create fake console sockets.\n"
            f"  Users may unknowingly send credentials to a rogue stream.\n"
            f"  Fix: chmod 0750 {watch_dir} && "
            f"chown root:_vnctlsd {watch_dir}\n"
            f"  Refusing to watch this directory."
        )

    if st.st_mode & stat.S_IROTH:
        log.warning(
            "Watcher: directory %r is world-readable (mode=%s). "
            "Socket names (VM names) are visible to all local users.",
            watch_dir, oct(stat.S_IMODE(st.st_mode)))

    return None


def _validate_socket(path: str, trusted_uid: int | None) -> str | None:
    """
    Validate a socket file before accepting it.
    Returns None if valid, error string if not.
    Does not follow symlinks.
    """
    try:
        st = os.lstat(path)
    except OSError as e:
        return f"lstat failed: {e}"

    if not stat.S_ISSOCK(st.st_mode):
        return f"not a socket (mode={oct(stat.S_IMODE(st.st_mode))})"

    if trusted_uid is not None and st.st_uid != trusted_uid:
        return (f"owned by uid={st.st_uid}, expected uid={trusted_uid}. "
                f"Check that QEMU runs as the correct user.")

    if st.st_mode & stat.S_IWOTH:
        return ("world-writable socket. "
                "Use filesystem ACLs for group access instead.")

    return None


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

    # Apply restrictions after privilege drop and after all library
    # resolution that touches the filesystem.
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

    # State
    inotify_fd  = -1
    watch_wd    = -1
    watch_dir   = console_store.get_watch_dir()
    stop_event  = threading.Event()

    def start_watch(directory: str) -> bool:
        nonlocal inotify_fd, watch_wd, watch_dir

        # Close existing watch
        if inotify_fd >= 0:
            try:
                os.close(inotify_fd)
            except Exception:
                pass
            inotify_fd = -1
            watch_wd   = -1

        watch_dir = directory

        # Check directory permissions — world-writable is a hard error
        err = _check_dir_permissions(directory)
        if err:
            log.error("Watcher: %s", err)
            try:
                ipc_send(ctl_sock, {'type': 'WATCHER_DIR_ERROR',
                                    'error': err})
            except Exception:
                pass
            return False

        # Open inotify
        fd = inotify_init1(0o4000)  # IN_CLOEXEC
        if fd < 0:
            log.error("Watcher: inotify_init1 failed: %s",
                      ctypes.get_errno())
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
        watch_wd   = wd
        log.info("Watcher: watching %r", directory)

        # Scan existing sockets — send SOCKET_APPEARED for each valid one
        try:
            for fname in os.listdir(directory):
                if fname.endswith('.sock'):
                    _handle_appeared(os.path.join(directory, fname))
        except OSError as e:
            log.error("Watcher: directory scan failed: %s", e)

        try:
            ipc_send(ctl_sock, {'type': 'WATCHER_READY',
                                'watch_dir': directory})
        except Exception:
            pass
        return True

    def _handle_appeared(path: str):
        """Called when a .sock file appears. Validate and notify worker."""
        # Find console definition
        match = console_store.match_socket(path)
        if match is None:
            log.warning(
                "Watcher: %r does not match any console definition, "
                "ignoring. Define it in consoles.yaml to accept it.",
                path)
            return

        defn, vars_ = match

        # Resolve trusted_uid for this socket
        trusted_uid = console_store.resolve_trusted_uid(defn, vars_)

        # Validate socket
        err = _validate_socket(path, trusted_uid)
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
                'type':         'SOCKET_APPEARED',
                'path':         path,
                'console_name': console_name,
                'defn':         {k: v for k, v in defn.items()
                                 if not k.startswith('_')},
                'vars':         vars_,
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

    # IPC listener thread — handles RELOAD_WATCH from monitor
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

    # Start initial watch
    if not start_watch(watch_dir):
        log.error("Watcher: initial watch failed, waiting for RELOAD_WATCH")

    # Main inotify event loop
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
            wd, mask, cookie, name_len = _INOTIFY_EVENT.unpack_from(
                raw, offset)
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

# ---------------------------------------------------------------------------
# Worker — MonitorProxy
# ---------------------------------------------------------------------------

class MonitorProxy:
    def __init__(self, rpc_sock: socket.socket):
        self._sock     = rpc_sock
        self._lock     = threading.Lock()
        self._seq      = 0
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

    def spawn(self, username: str, console_name: str,
              cmd: str, run_as: str) -> tuple[bool, int | None, str]:
        try:
            with self._lock:
                resp, fds = self._call({
                    'type':    'SPAWN_REQ',
                    'username': username,
                    'console':  console_name,
                    'cmd':      cmd,
                    'run_as':   run_as,
                }, 'SPAWN_RESP')
            if resp.get('ok') and fds:
                return True, fds[0], ''
            return False, None, resp.get('error', 'unknown error')
        except RuntimeError as e:
            return False, None, str(e)

    def cmd(self, cmd_list: list) -> str:
        try:
            with self._lock:
                resp, _ = self._call({'type': 'CMD_REQ',
                                      'cmd': cmd_list}, 'CMD_RESP')
            return resp.get('output', '')
        except RuntimeError as e:
            return f"ERROR: {e}"

# ---------------------------------------------------------------------------
# Worker — socket validation (re-validates watcher messages independently)
# ---------------------------------------------------------------------------

def worker_validate_socket(path: str, console_store: ConsoleConfigStore,
                            defn: dict, vars_: dict) -> str | None:
    """
    Worker independently re-validates a socket path reported by the watcher.
    Returns None if valid, error string if not.
    This ensures a compromised watcher cannot cause the worker to connect
    to an untrusted socket.
    """
    trusted_uid = console_store.resolve_trusted_uid(defn, vars_)
    return _validate_socket(path, trusted_uid)

# ---------------------------------------------------------------------------
# Worker — push socket listener
# ---------------------------------------------------------------------------

def monitor_push_listener(push_sock: socket.socket,
                           watch_sock: socket.socket,
                           registry: SessionRegistry,
                           hub_registry: HubRegistry,
                           acl_resolver: ACLResolver,
                           console_store: ConsoleConfigStore,
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

            # -- From monitor ------------------------------------------------
            if mtype == 'SESSION_LIST_REQ':
                ipc_send(push_sock, {
                    'type':     'SESSION_LIST_RESP',
                    'sessions': registry.snapshot(),
                    'hubs':     hub_registry.snapshot(),
                })

            elif mtype == 'ENFORCE_REQ':
                killed, retained = registry.kill_stale(
                    acl_resolver, console_store)
                ipc_send(push_sock, {
                    'type':     'ENFORCE_RESP',
                    'killed':   killed,
                    'retained': retained,
                })

            # -- From watcher ------------------------------------------------
            elif mtype == 'SOCKET_APPEARED':
                path         = msg.get('path', '')
                console_name = msg.get('console_name', '')
                defn         = msg.get('defn', {})
                vars_        = msg.get('vars', {})

                # Re-validate independently — don't trust watcher's judgement
                err = worker_validate_socket(path, console_store, defn, vars_)
                if err:
                    log.warning(
                        "Worker: rejecting socket %r from watcher: %s "
                        "(independent re-validation failed)",
                        path, err)
                    continue

                # Only handle qemu_unix type here — exec type hubs are created
                # on user demand, not on socket appearance
                if defn.get('type') != 'qemu_unix':
                    continue

                # Connect to the QEMU socket and create a hub
                try:
                    qemu_sock = socket.socket(socket.AF_UNIX,
                                              socket.SOCK_STREAM)
                    qemu_sock.connect(path)
                    fd = qemu_sock.detach()  # take the raw fd
                    hub, created = hub_registry.get_or_create(
                        console_name, fd, grace=grace)
                    if created:
                        log.info(
                            "Worker: hub created for %r via %r",
                            console_name, path)
                    else:
                        log.info(
                            "Worker: hub already exists for %r, "
                            "discarded new fd", console_name)
                except Exception as exc:
                    log.error(
                        "Worker: failed to connect to QEMU socket %r: %s",
                        path, exc)

            elif mtype == 'SOCKET_DISAPPEARED':
                path = msg.get('path', '')
                # Find hub by socket path — look through console_store
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
                        hub._done.set()
                        hub_registry.remove_if_done(name)

            else:
                log.warning("Push listener: unknown message %r", mtype)

# ---------------------------------------------------------------------------
# Worker — terminal I/O helpers
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Worker — console attach loop
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Worker — client handler
# ---------------------------------------------------------------------------

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

    login_timeout = config.getint('core', 'login_timeout', fallback=30)
    idle_timeout  = config.getint('core', 'idle_timeout',  fallback=300)
    grace         = config.getint('core', 'hub_grace_period', fallback=30)
    sid           = str(uuid.uuid4())

    try:
        client_sock.settimeout(login_timeout)
        client_sock.sendall(BANNER)

        # -- Login -----------------------------------------------------------
        client_sock.sendall(b"Username: ")
        ub = sock_readline(client_sock, echo=True)
        if not ub:
            return
        username = ub.decode('utf-8', errors='replace').strip()
        if not username:
            return

        client_sock.sendall(b"Password: ")
        pb = sock_readline(client_sock, echo=False)
        if pb is None:
            return
        password = pb.decode('utf-8', errors='replace')

        if rate_limiter.is_limited(username):
            time.sleep(2)
            client_sock.sendall(b"\r\nLogin failed.\r\n")
            return

        # All failure paths produce the same message and take the same
        # minimum time — an attacker cannot distinguish wrong password,
        # user not in users.yaml, or no role assigned.
        # The real reason is logged server-side only.
        _login_start    = time.monotonic()
        _MIN_LOGIN_TIME = 2.0

        def _fail(reason: str):
            log.warning("Login denied: user=%r reason=%s", username, reason)
            rate_limiter.record_failure(username)
            remaining = _MIN_LOGIN_TIME - (time.monotonic() - _login_start)
            if remaining > 0:
                time.sleep(remaining)
            client_sock.sendall(b"\r\nLogin failed.\r\n")

        if not monitor.auth(username, password):
            _fail("bad_credentials")
            return

        if not user_map.user_exists(username):
            _fail("not_in_usermap")
            return

        role = user_map.get_role(username)
        if role is None:
            _fail("no_role")
            return

        rate_limiter.record_success(username)
        log.info("Login: user=%r role=%r", username, role)
        registry.add(sid, username, state='prompt', sock=client_sock)

        client_sock.settimeout(idle_timeout)
        client_sock.sendall(b"\r\nLogin successful.\r\n")

        # -- Command prompt --------------------------------------------------
        while True:
            client_sock.sendall(PROMPT)

            try:
                line_b = sock_readline(client_sock, echo=True)
            except TimeoutError:
                client_sock.sendall(
                    b"\r\n[Idle timeout. Disconnecting.]\r\n")
                break

            if line_b is None:
                break

            line   = line_b.decode('utf-8', errors='replace').strip()
            parts  = line.split()
            if not parts:
                continue
            action = parts[0].lower()

            if action in ('quit', 'exit'):
                client_sock.sendall(b"Goodbye.\r\n")
                break

            elif action == 'help':
                client_sock.sendall(HELP_TEXT)

            elif action == 'list':
                # Collect all defined consoles (explicit + patterns from
                # current socket directory scan) and filter by ACL
                cfg         = console_store.get()
                all_consoles: dict[str, tuple[dict, dict]] = {}

                # Explicit consoles
                for cname, defn in cfg.get('consoles', {}).items():
                    all_consoles[cname] = (defn, {})

                # Pattern-derived from active hubs
                for hub_snap in hub_registry.snapshot():
                    cname = hub_snap['name']
                    if cname not in all_consoles:
                        # Try to find its definition via socket path
                        # (we don't store path in hub, so use name matching)
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
                    hub      = hub_registry.get(cname)
                    watchers = len(hub.snapshot()['clients']) if hub else 0
                    active   = "live" if hub else "idle"
                    lines.append(
                        f"  {cname:<30} [{active}]  "
                        f"{watchers} watcher(s)  [{level}]\r\n")

                if not lines:
                    client_sock.sendall(b"No accessible consoles.\r\n")
                else:
                    client_sock.sendall(''.join(lines).encode())

            elif action == 'console':
                if len(parts) < 2:
                    client_sock.sendall(b"Usage: console <name>\r\n")
                    continue

                cname = parts[1]
                cfg   = console_store.get()

                # Find console definition
                defn  = cfg.get('consoles', {}).get(cname)
                vars_ = {}
                if defn is None:
                    # Try to find via patterns by name
                    # (reverse-match: name → pattern → defn)
                    for pat in cfg.get('console_patterns', []):
                        pname = pat.get('console_name', '')
                        # Check if cname could come from this pattern
                        # by trying to match a synthesised socket path
                        # This is imperfect for name-only lookup;
                        # the authoritative lookup is socket_path based.
                        # For now: check hubs and known sockets.
                        pass

                    # Check if there's an active hub (socket already connected)
                    hub = hub_registry.get(cname)
                    if hub is None:
                        client_sock.sendall(
                            b"Console not found or not active.\r\n")
                        continue
                    defn = {}  # hub exists, ACL from user map role

                # ACL check
                level = acl_resolver.resolve_access(
                    username, cname, defn or {}, vars_)
                if level is None:
                    client_sock.sendall(
                        b"Access denied to this console.\r\n")
                    continue

                read_only = (level == 'read_only')

                # Get or create hub
                hub = hub_registry.get(cname)

                if hub is None:
                    # exec type — spawn virsh
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

                    cmd_template = defn.get('cmd', '')
                    try:
                        cmd_str = cmd_template.format(
                            name=cname, **vars_)
                    except KeyError as e:
                        client_sock.sendall(
                            f"Console cmd template error: {e}\r\n".encode())
                        continue

                    run_as = defn.get('run_as',
                                      config.get('spawn', 'run_as',
                                                 fallback='_vnctlsd')
                                      if config.has_option('spawn', 'run_as')
                                      else '_vnctlsd')

                    ok, master_fd, err = monitor.spawn(
                        username, cname, cmd_str, run_as)
                    if not ok:
                        client_sock.sendall(
                            f"Spawn failed: {err}\r\n".encode())
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
                run_console_session(client_sock, hub, sid,
                                    read_only, registry)
                hub_registry.remove_if_done(cname)

                client_sock.settimeout(idle_timeout)
                registry.update(sid, state='prompt', console=None)
                client_sock.sendall(
                    f"\r\n[Detached from {cname}]\r\n".encode())

            elif action in ('status', 'start', 'reset',
                            'force_reset', 'poweroff'):
                if len(parts) < 2:
                    client_sock.sendall(
                        f"Usage: {action} <console_name>\r\n".encode())
                    continue

                cname = parts[1]
                cfg   = console_store.get()
                defn  = cfg.get('consoles', {}).get(cname, {})

                level = acl_resolver.resolve_access(
                    username, cname, defn, {})
                if level is None:
                    client_sock.sendall(b"Access denied.\r\n")
                    continue

                # Build virsh command from console cmd template
                # Extract VM name from console name (best effort)
                vm_name = cname
                cmd_map = {
                    'status':     f"virsh -c qemu:///system domstate {vm_name}",
                    'start':      f"virsh -c qemu:///system start {vm_name}",
                    'reset':      f"virsh -c qemu:///system reboot {vm_name}",
                    'force_reset': f"virsh -c qemu:///system reset {vm_name}",
                    'poweroff':   f"virsh -c qemu:///system destroy {vm_name}",
                }
                result = monitor.cmd(shlex.split(cmd_map[action]))
                client_sock.sendall(f"{result}\r\n".encode())

            else:
                client_sock.sendall(
                    f"Unknown command: {action!r}. "
                    f"Type 'help'.\r\n".encode())

    except TimeoutError:
        try:
            client_sock.sendall(b"\r\n[Login timeout.]\r\n")
        except Exception:
            pass
    except Exception:
        log.exception("handle_client error")
    finally:
        registry.remove(sid)
        try:
            client_sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            client_sock.close()
        except Exception:
            pass

# ---------------------------------------------------------------------------
# Worker — seccomp
# ---------------------------------------------------------------------------

def apply_seccomp():
    try:
        import seccomp
    except ImportError:
        log.warning("python-seccomp not installed, skipping")
        return
    f = seccomp.SyscallFilter(defaction=seccomp.KILL)
    for sc in [
        'read', 'write', 'readv', 'writev',
        'recv', 'send', 'recvfrom', 'sendto',
        'recvmsg', 'sendmsg', 'recvmmsg', 'sendmmsg',
        'accept', 'accept4', 'close', 'shutdown',
        'getsockopt', 'setsockopt', 'getpeername', 'getsockname',
        'connect',                      # worker connects to QEMU unix sockets
        'socket',                       # for QEMU unix socket connect
        'fstat', 'fstat64', 'stat', 'stat64', 'lstat', 'newfstatat',
        'fstatfs', 'statx', 'lseek', 'pread64', 'pwrite64',
        'ioctl', 'fcntl', 'dup', 'dup2', 'dup3',
        'poll', 'ppoll', 'select', 'pselect6',
        'epoll_wait', 'epoll_pwait', 'epoll_ctl',
        'epoll_create', 'epoll_create1',
        'eventfd', 'eventfd2', 'pipe', 'pipe2',
        'futex', 'futex_waitv', 'clone', 'clone3',
        'mmap', 'mmap2', 'munmap', 'mprotect', 'mremap', 'brk',
        'madvise', 'mincore', 'msync',
        'rt_sigaction', 'rt_sigprocmask', 'rt_sigreturn',
        'rt_sigpending', 'rt_sigsuspend', 'rt_sigtimedwait',
        'sigaltstack',
        'clock_gettime', 'clock_getres', 'gettimeofday',
        'nanosleep', 'clock_nanosleep',
        'timer_create', 'timer_settime', 'timer_gettime', 'timer_delete',
        'getpid', 'getppid', 'gettid',
        'getuid', 'getgid', 'geteuid', 'getegid',
        'getgroups', 'getresuid', 'getresgid',
        'getrandom',
        'set_robust_list', 'get_robust_list', 'set_tid_address',
        'restart_syscall',
        'sched_getaffinity', 'sched_setaffinity', 'sched_yield',
        'uname', 'umask',
        'wait4', 'waitpid', 'waitid',
        'rseq',
        'exit', 'exit_group',
    ]:
        try:
            f.add_rule(seccomp.ALLOW, sc)
        except Exception:
            pass
    f.load()
    log.info("seccomp filter applied")

# ---------------------------------------------------------------------------
# Worker — landlock
# ---------------------------------------------------------------------------

def apply_landlock(socket_path: str, watch_dir: str):
    SYS_landlock_create_ruleset = 444
    SYS_landlock_add_rule       = 445
    SYS_landlock_restrict_self  = 446
    LANDLOCK_CREATE_RULESET_VERSION = 1 << 0
    LANDLOCK_RULE_PATH_BENEATH      = 1
    LANDLOCK_ACCESS_FS_READ_FILE    = 1 << 2
    LANDLOCK_ACCESS_FS_READ_DIR     = 1 << 3
    LANDLOCK_ACCESS_FS_WRITE_FILE   = 1 << 1

    libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
    abi  = libc.syscall(SYS_landlock_create_ruleset, None, 0,
                        LANDLOCK_CREATE_RULESET_VERSION)
    if abi < 0:
        log.warning("Landlock not supported, skipping")
        return

    handled = (LANDLOCK_ACCESS_FS_READ_FILE |
               LANDLOCK_ACCESS_FS_READ_DIR  |
               LANDLOCK_ACCESS_FS_WRITE_FILE)

    class RulesetAttr(ctypes.Structure):
        _fields_ = [("handled_access_fs", ctypes.c_uint64)]

    attr = RulesetAttr(handled_access_fs=handled)
    ruleset_fd = libc.syscall(SYS_landlock_create_ruleset,
                              ctypes.byref(attr), ctypes.sizeof(attr), 0)
    if ruleset_fd < 0:
        log.warning("Failed to create landlock ruleset, skipping")
        return

    class PathBeneathAttr(ctypes.Structure):
        _fields_ = [("allowed_access", ctypes.c_uint64),
                    ("parent_fd",      ctypes.c_int32)]

    def add_path(path: str, access: int):
        try:
            fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
        except OSError as e:
            log.warning("Landlock: cannot open %r: %s", path, e)
            return
        a   = PathBeneathAttr(allowed_access=access, parent_fd=fd)
        ret = libc.syscall(SYS_landlock_add_rule, ruleset_fd,
                           LANDLOCK_RULE_PATH_BENEATH, ctypes.byref(a), 0)
        os.close(fd)
        if ret < 0:
            log.warning("Landlock: failed to add rule for %r", path)

    rw = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE
    add_path(os.path.dirname(socket_path), rw)
    add_path(watch_dir, rw)
    add_path('/dev', rw)

    prctl_no_new_privs()
    ret = libc.syscall(SYS_landlock_restrict_self, ruleset_fd, 0)
    if ret < 0:
        log.warning("Failed to apply landlock, skipping")
    else:
        log.info("Landlock applied")
    os.close(ruleset_fd)

# ---------------------------------------------------------------------------
# Worker — watcher seccomp (tighter than worker)
# ---------------------------------------------------------------------------

def apply_watcher_seccomp():
    try:
        import seccomp
    except ImportError:
        log.warning("python-seccomp not installed, skipping")
        return
    f = seccomp.SyscallFilter(defaction=seccomp.KILL)
    for sc in [
        # inotify
        'inotify_init1', 'inotify_add_watch', 'inotify_rm_watch',
        # file inspection — lstat only, no symlink following
        'lstat', 'lstat64', 'newfstatat', 'statx',
        'fstat', 'fstat64',
        'openat',           # os.listdir initial scan
        'getdents64',       # os.listdir
        'close',
        # IPC to worker/monitor
        'read', 'write', 'readv', 'writev',
        'recvmsg', 'sendmsg', 'sendto', 'recvfrom',
        'select', 'pselect6', 'poll', 'ppoll',
        'epoll_wait', 'epoll_pwait', 'epoll_ctl',
        'epoll_create', 'epoll_create1',
        # Python threading/memory
        'futex', 'futex_waitv', 'clone', 'clone3',
        'mmap', 'mmap2', 'munmap', 'mprotect', 'mremap', 'brk',
        'madvise', 'mincore',
        'rt_sigaction', 'rt_sigprocmask', 'rt_sigreturn',
        'rt_sigpending', 'sigaltstack',
        'clock_gettime', 'clock_getres', 'gettimeofday', 'nanosleep',
        'clock_nanosleep',
        'timer_create', 'timer_settime', 'timer_gettime', 'timer_delete',
        'getpid', 'getppid', 'gettid',
        'getuid', 'getgid', 'geteuid', 'getegid',
        'getgroups', 'getresuid', 'getresgid',
        'set_robust_list', 'get_robust_list', 'set_tid_address',
        'restart_syscall',
        'sched_getaffinity', 'sched_setaffinity', 'sched_yield',
        'uname', 'umask',
        'getrandom', 'rseq',
        'fcntl',            # Python file descriptor management
        'ioctl',            # terminal/fd operations
        'exit', 'exit_group',
    ]:
        try:
            f.add_rule(seccomp.ALLOW, sc)
        except Exception:
            pass
    f.load()
    log.info("Watcher seccomp filter applied")

# ---------------------------------------------------------------------------
# Worker — watcher landlock (read-only on watch dir)
# ---------------------------------------------------------------------------

def apply_watcher_landlock(watch_dir: str):
    SYS_landlock_create_ruleset = 444
    SYS_landlock_add_rule       = 445
    SYS_landlock_restrict_self  = 446
    LANDLOCK_CREATE_RULESET_VERSION = 1 << 0
    LANDLOCK_RULE_PATH_BENEATH      = 1
    LANDLOCK_ACCESS_FS_READ_FILE    = 1 << 2
    LANDLOCK_ACCESS_FS_READ_DIR     = 1 << 3

    libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
    abi  = libc.syscall(SYS_landlock_create_ruleset, None, 0,
                        LANDLOCK_CREATE_RULESET_VERSION)
    if abi < 0:
        return

    handled = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR

    class RulesetAttr(ctypes.Structure):
        _fields_ = [("handled_access_fs", ctypes.c_uint64)]

    attr = RulesetAttr(handled_access_fs=handled)
    ruleset_fd = libc.syscall(SYS_landlock_create_ruleset,
                              ctypes.byref(attr), ctypes.sizeof(attr), 0)
    if ruleset_fd < 0:
        return

    class PathBeneathAttr(ctypes.Structure):
        _fields_ = [("allowed_access", ctypes.c_uint64),
                    ("parent_fd",      ctypes.c_int32)]

    ro = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR
    try:
        fd = os.open(watch_dir, os.O_PATH | os.O_CLOEXEC)
        a  = PathBeneathAttr(allowed_access=ro, parent_fd=fd)
        libc.syscall(SYS_landlock_add_rule, ruleset_fd,
                     LANDLOCK_RULE_PATH_BENEATH, ctypes.byref(a), 0)
        os.close(fd)
    except OSError:
        pass

    prctl_no_new_privs()
    ret = libc.syscall(SYS_landlock_restrict_self, ruleset_fd, 0)
    if ret >= 0:
        log.info("Watcher landlock applied (read-only on %r)", watch_dir)
    os.close(ruleset_fd)

# ---------------------------------------------------------------------------
# Worker process
# ---------------------------------------------------------------------------

def run_worker(rpc_sock: socket.socket, push_sock: socket.socket,
               watch_sock: socket.socket,
               server_sock: socket.socket,
               config: configparser.ConfigParser,
               user_map: UserMapStore,
               console_store: ConsoleConfigStore,
               worker_pw: pwd.struct_passwd,
               no_seccomp: bool = False,
               no_landlock: bool = False):
    set_proc_title(f"worker ({worker_pw.pw_name})")
    for h in logging.getLogger().handlers:
        h.setLevel(logging.NOTSET)
    log.info("Worker started (pid=%d), dropping to %r",
             os.getpid(), worker_pw.pw_name)

    os.setgid(worker_pw.pw_gid)
    os.setuid(worker_pw.pw_uid)

    socket_path  = config.get('core', 'socket_path')
    max_threads  = config.getint('core', 'max_threads',       fallback=64)
    max_failures = config.getint('auth', 'max_failures',      fallback=5)
    fail_window  = config.getfloat('auth', 'failure_window',  fallback=120)
    lockout_dur  = config.getfloat('auth', 'lockout_duration', fallback=60)
    watch_dir    = console_store.get_watch_dir()

    registry     = SessionRegistry()
    hub_registry = HubRegistry()
    acl_resolver = ACLResolver(user_map)
    monitor      = MonitorProxy(rpc_sock)
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
              acl_resolver, console_store, monitor, config),
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

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    if os.geteuid() != 0:
        print("[ERROR] must be started as root", file=sys.stderr)
        sys.exit(1)

    set_proc_title("master")
    script_dir = os.path.dirname(os.path.abspath(__file__))

    parser = argparse.ArgumentParser(
        description="vnctlsd — Conserver-style virsh console dispatcher")
    parser.add_argument('--config',
        default=os.path.join(script_dir, 'vnctlsd.ini'))
    parser.add_argument('--users',
        default=os.path.join(script_dir, 'users.yaml'))
    parser.add_argument('--consoles',
        default=os.path.join(script_dir, 'consoles.yaml'))
    parser.add_argument('--no-privsep', action='store_true', default=False)
    parser.add_argument('--no-seccomp', action='store_true', default=False)
    parser.add_argument('--no-landlock', action='store_true', default=False)
    parser.add_argument('--debug', action='store_true', default=False)
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        # Ensure the handler level doesn't filter out DEBUG messages
        for h in logging.getLogger().handlers:
            h.setLevel(logging.NOTSET)
        log.debug("Debug logging enabled")
    if args.no_privsep:
        log.warning("*** --no-privsep: seccomp+landlock DISABLED ***")

    # -- Config --------------------------------------------------------------
    config = configparser.ConfigParser()
    config.read_string(DEFAULT_CONFIG)
    if os.path.exists(args.config):
        config.read(args.config)
        log.info("Loaded config from %s", args.config)

    # -- User map ------------------------------------------------------------
    if not os.path.exists(args.users):
        log.error("User map not found: %s", args.users)
        sys.exit(1)
    try:
        user_map = UserMapStore(load_user_map(args.users))
        log.info("Loaded user map from %s", args.users)
    except Exception as exc:
        log.error("User map load failed: %s", exc)
        sys.exit(1)

    # -- Console config ------------------------------------------------------
    if not os.path.exists(args.consoles):
        log.warning("Console config not found: %s — no consoles defined",
                    args.consoles)
        console_cfg = {}
    else:
        try:
            console_cfg = load_console_config(args.consoles)
            log.info("Loaded console config from %s", args.consoles)
        except Exception as exc:
            log.error("Console config load failed: %s", exc)
            sys.exit(1)

    console_store = ConsoleConfigStore(console_cfg)

    # -- Worker + watcher accounts -------------------------------------------
    for role_name, key in [('worker', 'worker_user'),
                            ('watcher', 'watcher_user')]:
        uname = config.get('core', key, fallback='_vnctlsd')
        try:
            pw = pwd.getpwnam(uname)
            if role_name == 'worker':
                worker_pw = pw
            else:
                watcher_pw = pw
        except KeyError:
            log.error("%s user %r not found", role_name, uname)
            sys.exit(1)

    # -- Unix socket ---------------------------------------------------------
    socket_path = config.get('core', 'socket_path')
    socket_dir  = os.path.dirname(socket_path)
    os.makedirs(socket_dir, mode=0o750, exist_ok=True)

    if os.path.exists(socket_path):
        os.unlink(socket_path)

    server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(socket_path)
    server_sock.listen(128)

    socket_mode  = int(config.get('core', 'socket_mode',  fallback='0660'), 8)
    socket_group = config.get('core', 'socket_group', fallback='')
    os.chmod(socket_path, socket_mode)
    if socket_group:
        try:
            import grp as _grp
            gid = _grp.getgrnam(socket_group).gr_gid
            os.chown(socket_path, 0, gid)
            log.info("Socket group: %r (gid=%d)", socket_group, gid)
        except KeyError:
            log.warning("Socket group %r not found", socket_group)

    # -- Socketpairs ---------------------------------------------------------
    # rpc:   worker ↔ monitor (AUTH, CMD, SPAWN)
    # push:  monitor → worker (SESSION_LIST, ENFORCE)
    # ctl:   monitor ↔ watcher (RELOAD_WATCH, WATCHER_READY/ERROR)
    # watch: watcher → worker (SOCKET_APPEARED/DISAPPEARED)
    rpc_m,   rpc_w   = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    push_m,  push_w  = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    ctl_m,   ctl_w   = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    watch_w2, watch_worker = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

    # -- PID file ------------------------------------------------------------
    pidfile = config.get('core', 'pidfile', fallback=None)

    # -- Sanitise environment ------------------------------------------------
    _KEEP = {'PATH', 'LIBVIRT_DEFAULT_URI', 'LANG', 'LC_ALL'}
    for k in list(os.environ.keys()):
        if k not in _KEEP:
            del os.environ[k]
    os.environ['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
    os.environ['HOME'] = '/nonexistent'

    # Pre-load seccomp
    try:
        import seccomp as _sp  # noqa
        log.info("seccomp pre-loaded")
    except ImportError:
        log.warning("python-seccomp not available")

    # -- Fork watcher --------------------------------------------------------
    watcher_pid = os.fork()
    if watcher_pid == 0:
        rpc_m.close(); rpc_w.close()
        push_m.close(); push_w.close()
        watch_worker.close()
        server_sock.close()
        os.setsid()

        run_watcher(ctl_w, watch_w2, console_store, watcher_pw,
                    no_seccomp=args.no_seccomp or args.no_privsep,
                    no_landlock=args.no_landlock or args.no_privsep)
        os._exit(0)

    # -- Fork worker ---------------------------------------------------------
    worker_pid = os.fork()
    if worker_pid == 0:
        rpc_m.close()
        push_m.close()
        ctl_m.close(); ctl_w.close()
        watch_w2.close()
        os.setsid()

        run_worker(rpc_w, push_w, watch_worker, server_sock,
                   config, user_map, console_store, worker_pw,
                   no_seccomp=args.no_seccomp or args.no_privsep,
                   no_landlock=args.no_landlock or args.no_privsep)
        os._exit(0)

    # -- Monitor (parent) ----------------------------------------------------
    rpc_w.close()
    push_w.close()
    ctl_w.close()
    watch_w2.close()
    watch_worker.close()
    server_sock.close()

    if pidfile:
        try:
            with open(pidfile, 'w') as fh:
                fh.write(f"{os.getpid()}\n")
            log.info("PID file: %s", pidfile)
        except Exception as exc:
            log.warning("PID file write failed: %s", exc)

    log.info("Monitor pid=%d  worker pid=%d  watcher pid=%d",
             os.getpid(), worker_pid, watcher_pid)

    run_monitor(rpc_m, push_m, ctl_m,
                args.users, args.consoles,
                config, user_map, console_store)

    for pid in (worker_pid, watcher_pid):
        try:
            os.waitpid(pid, 0)
        except Exception:
            pass

    if pidfile:
        try:
            os.unlink(pidfile)
        except Exception:
            pass


if __name__ == '__main__':
    main()
