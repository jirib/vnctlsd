import os
import socket
import stat

from vnctlsd.acl import ACLResolver
from vnctlsd.config import ConsoleConfigStore, UserMapStore
from vnctlsd.session import SessionRegistry
from vnctlsd.validation import check_dir_permissions, validate_socket


def test_check_dir_permissions_rejects_world_writable_directory(tmp_path):
    tmp_path.chmod(0o777)

    err = check_dir_permissions(str(tmp_path))

    assert err is not None
    assert "world-writable" in err


def test_validate_socket_accepts_socket_and_rejects_symlink(tmp_path):
    sock_path = tmp_path / "console.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(sock_path))

        assert validate_socket(str(sock_path), os.getuid()) is None

        link_path = tmp_path / "linked.sock"
        link_path.symlink_to(sock_path)
        err = validate_socket(str(link_path), os.getuid())
        assert err is not None
        assert "not a socket" in err
    finally:
        server.close()


def test_validate_socket_rejects_world_writable_socket(tmp_path):
    sock_path = tmp_path / "console.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(sock_path))
        sock_path.chmod(stat.S_IFSOCK | 0o666)

        err = validate_socket(str(sock_path), None)

        assert err is not None
        assert "world-writable socket" in err
    finally:
        server.close()


def test_session_registry_kill_stale_closes_revoked_console_sessions():
    registry = SessionRegistry()
    revoked_server, revoked_client = socket.socketpair()
    prompt_server, prompt_client = socket.socketpair()
    allowed_server, allowed_client = socket.socketpair()

    users = UserMapStore(
        {
            "users": {
                "alice": {"groups": ["revoked"]},
                "bob": {"groups": ["allowed"]},
            },
            "groups": {
                "revoked": {"role": "read_only"},
                "allowed": {"role": "read_only"},
            },
        }
    )
    acl = ACLResolver(users)
    consoles = ConsoleConfigStore(
        {
            "consoles": {
                "lab01": {"ro": ["allowed"]},
                "lab02": {"ro": ["allowed"]},
            }
        }
    )

    try:
        registry.add("revoked", "alice", "console", revoked_server, console="lab01")
        registry.add("prompt", "alice", "prompt", prompt_server)
        registry.add("allowed", "bob", "console", allowed_server, console="lab02")

        killed, retained = registry.kill_stale(acl, consoles)

        assert killed == ["alice \u2192 lab01 (access revoked)"]
        assert retained == ["alice (at prompt)", "bob \u2192 lab02"]
        assert [s["id"] for s in registry.snapshot()] == ["prompt", "allowed"]
        assert b"access has been revoked" in revoked_client.recv(1024)
    finally:
        for sock in (
            revoked_client,
            prompt_server,
            prompt_client,
            allowed_server,
            allowed_client,
        ):
            try:
                sock.close()
            except OSError:
                pass
