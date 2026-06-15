"""
Tests for authenticate_client_pam() and run_authenticated_session().

Both functions are exercised via real socket pairs (same pattern as
test_session_validation.py).  A _StubMonitor replaces MonitorProxy so
no IPC or subprocess is needed.
"""
import configparser
import io
import socket
import threading
import time
from unittest.mock import patch

from vnctlsd.auth import RateLimiter
from vnctlsd.config import ConsoleConfigStore, UserMapStore
from vnctlsd.session import SessionRegistry
from vnctlsd.worker import authenticate_client_pam, run_authenticated_session


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
    """Minimal stand-in for MonitorProxy used in authenticate_client_pam."""

    def __init__(self, auth_result=True):
        self._auth_result = auth_result

    def auth(self, username, password):
        return self._auth_result

    def spawn(self, username, console):
        raise NotImplementedError

    def run_action(self, action, console):
        raise NotImplementedError


def _send_line(sock, text):
    """Write a CR-terminated line as if a terminal user pressed Enter.

    sock_readline breaks on the first of CR or LF and leaves the other byte in
    the buffer, which would be consumed as the next line's first character.
    Send CR only so the buffer is empty after the read.
    """
    sock.sendall((text + "\r").encode())


def _recv_all_timeout(sock, timeout=0.5):
    """Read everything available on sock within timeout seconds."""
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
# authenticate_client_pam
# ---------------------------------------------------------------------------

def _run_auth(server_sock, monitor, user_map, rate_limiter, config):
    """Run authenticate_client_pam on server_sock in a background thread."""
    result = [None]

    def target():
        result[0] = authenticate_client_pam(
            server_sock, monitor, user_map, rate_limiter, config)

    t = threading.Thread(target=target, daemon=True)
    t.start()
    return t, result


def test_authenticate_pam_returns_username_on_success():
    server, client = socket.socketpair()
    config = _make_config(login_timeout=5)
    user_map = _make_user_map("alice")
    rate_limiter = RateLimiter(5, 60.0, 300.0)
    monitor = _StubMonitor(auth_result=True)

    try:
        t, result = _run_auth(server, monitor, user_map, rate_limiter, config)

        buf = _recv_all_timeout(client, timeout=1.0)
        assert b"Username:" in buf or b"Username" in buf

        _send_line(client, "alice")
        time.sleep(0.05)
        _recv_all_timeout(client, timeout=0.3)  # drain "Password:" prompt

        _send_line(client, "secret")
        t.join(timeout=5)

        assert result[0] == "alice"
    finally:
        for s in (server, client):
            try:
                s.close()
            except OSError:
                pass


def test_authenticate_pam_returns_none_on_bad_credentials():
    server, client = socket.socketpair()
    config = _make_config(login_timeout=5)
    user_map = _make_user_map("alice")
    rate_limiter = RateLimiter(5, 60.0, 300.0)
    monitor = _StubMonitor(auth_result=False)

    try:
        with patch("vnctlsd.worker.time.sleep"):
            t, result = _run_auth(
                server, monitor, user_map, rate_limiter, config)

            _recv_all_timeout(client, timeout=1.0)
            _send_line(client, "alice")
            time.sleep(0.05)
            _recv_all_timeout(client, timeout=0.3)
            _send_line(client, "wrongpassword")
            t.join(timeout=5)
            # Read the response while server is still open (thread has returned
            # but socket is closed by handle_client, not authenticate_client_pam).
            response = _recv_all_timeout(client)

        assert result[0] is None
        assert b"Login failed" in response
    finally:
        for s in (server, client):
            try:
                s.close()
            except OSError:
                pass


def test_authenticate_pam_returns_none_when_user_not_in_map():
    server, client = socket.socketpair()
    config = _make_config(login_timeout=5)
    # "alice" passes PAM but is absent from user map
    user_map = UserMapStore({"users": {}, "groups": {}})
    rate_limiter = RateLimiter(5, 60.0, 300.0)
    monitor = _StubMonitor(auth_result=True)

    try:
        with patch("vnctlsd.worker.time.sleep"):
            t, result = _run_auth(
                server, monitor, user_map, rate_limiter, config)

            _recv_all_timeout(client, timeout=1.0)
            _send_line(client, "alice")
            time.sleep(0.05)
            _recv_all_timeout(client, timeout=0.3)
            _send_line(client, "secret")
            t.join(timeout=5)
            response = _recv_all_timeout(client)

        assert result[0] is None
        assert b"Login failed" in response
    finally:
        for s in (server, client):
            try:
                s.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# run_authenticated_session
# ---------------------------------------------------------------------------

def test_run_authenticated_session_skips_auth_prompts():
    """
    run_authenticated_session must NOT send "Username:" or "Password:".
    It sends "Login successful." and then the prompt.
    """
    server, client = socket.socketpair()
    config = _make_config(idle_timeout=5, hub_grace_period=10)
    user_map = _make_user_map("alice")
    registry = SessionRegistry()
    console_store = ConsoleConfigStore({"consoles": {}, "commands": {}})
    hub_registry_stub = _StubHubRegistry()

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
            hub_registry=hub_registry_stub,
            config=config,
        )

    t = threading.Thread(target=target, daemon=True)
    t.start()

    # Give the function a moment to send its greeting.
    time.sleep(0.1)
    banner = _recv_all_timeout(client, timeout=0.5)

    assert b"Username" not in banner
    assert b"Password" not in banner
    assert b"Login successful" in banner

    # Clean quit.
    _send_line(client, "quit")
    t.join(timeout=5)

    response = _recv_all_timeout(client)
    assert b"Goodbye" in response

    for s in (server, client):
        try:
            s.close()
        except OSError:
            pass


class _StubHubRegistry:
    """Minimal hub registry that claims no hubs are live."""

    def snapshot(self):
        return []

    def get(self, name):
        return None

    def get_or_create(self, name, fd, grace=30):
        raise NotImplementedError

    def remove_if_done(self, name):
        pass
