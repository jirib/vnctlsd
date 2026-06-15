"""
Tests for run_authenticated_session().

Exercised via real socket pairs.  A _StubMonitor replaces MonitorProxy so
no IPC or subprocess is needed.
"""
import configparser
import socket
import threading
import time

from vnctlsd.config import ConsoleConfigStore, UserMapStore
from vnctlsd.session import SessionRegistry
from vnctlsd.worker import run_authenticated_session


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(**kwargs):
    cfg = configparser.ConfigParser()
    cfg.read_string("[core]\n" + "\n".join(f"{k} = {v}"
                                           for k, v in kwargs.items()))
    return cfg


def _make_user_map(username="alice", role="read_write"):
    group = "staff"
    return UserMapStore({
        "users": {username: {"groups": [group]}},
        "groups": {group: {"role": role}},
    })


class _StubMonitor:
    def spawn(self, username, console):
        raise NotImplementedError

    def run_action(self, action, console):
        raise NotImplementedError

    def lookup_uid(self, uid):
        return None


class _StubHubRegistry:
    def snapshot(self):
        return []

    def get(self, name):
        return None

    def get_or_create(self, name, fd, grace=30):
        raise NotImplementedError

    def remove_if_done(self, name):
        pass


def _send_line(sock, text):
    """Send CR-terminated line; sock_readline breaks on first CR or LF."""
    sock.sendall((text + "\r").encode())


def _recv_all_timeout(sock, timeout=0.5):
    buf = b""
    sock.settimeout(timeout)
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
    except (TimeoutError, socket.timeout):
        pass
    return buf


# ---------------------------------------------------------------------------
# run_authenticated_session
# ---------------------------------------------------------------------------

def test_run_authenticated_session_skips_auth_prompts():
    """
    run_authenticated_session must NOT send "Username:" or "Password:".
    It sends "Login successful." immediately then the prompt.
    """
    server, client = socket.socketpair()
    config = _make_config(idle_timeout=5, hub_grace_period=10)
    user_map = _make_user_map("alice")
    registry = SessionRegistry()
    console_store = ConsoleConfigStore({"consoles": {}, "commands": {}})

    from vnctlsd.acl import ACLResolver
    acl = ACLResolver(user_map)
    sid = "test-sid-1"

    def target():
        run_authenticated_session(
            server, "alice", sid,
            monitor=_StubMonitor(),
            user_map=user_map,
            acl_resolver=acl,
            console_store=console_store,
            registry=registry,
            hub_registry=_StubHubRegistry(),
            config=config,
        )

    t = threading.Thread(target=target, daemon=True)
    t.start()

    time.sleep(0.1)
    banner = _recv_all_timeout(client, timeout=0.5)

    assert b"Username" not in banner
    assert b"Password" not in banner
    assert b"Login successful" in banner

    _send_line(client, "quit")
    t.join(timeout=5)

    response = _recv_all_timeout(client)
    assert b"Goodbye" in response

    for s in (server, client):
        try:
            s.close()
        except OSError:
            pass


def test_run_authenticated_session_registers_session():
    """Session must appear in the registry immediately after login."""
    server, client = socket.socketpair()
    config = _make_config(idle_timeout=5, hub_grace_period=10)
    user_map = _make_user_map("alice")
    registry = SessionRegistry()
    console_store = ConsoleConfigStore({"consoles": {}, "commands": {}})

    from vnctlsd.acl import ACLResolver
    acl = ACLResolver(user_map)
    sid = "test-sid-2"

    def target():
        run_authenticated_session(
            server, "alice", sid,
            monitor=_StubMonitor(),
            user_map=user_map,
            acl_resolver=acl,
            console_store=console_store,
            registry=registry,
            hub_registry=_StubHubRegistry(),
            config=config,
        )

    t = threading.Thread(target=target, daemon=True)
    t.start()

    time.sleep(0.1)
    _recv_all_timeout(client, timeout=0.3)

    snap = registry.snapshot()
    session = next((s for s in snap if s['id'] == sid), None)
    assert session is not None
    assert session['username'] == 'alice'
    assert session['state'] == 'prompt'

    _send_line(client, "quit")
    t.join(timeout=5)

    for s in (server, client):
        try:
            s.close()
        except OSError:
            pass
