import os
import socket

import pytest

from vnctlsd.ipc import ipc_recv, ipc_send


def test_ipc_round_trips_json_message_over_socketpair():
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        ipc_send(left, {"type": "PING", "seq": 7, "payload": {"ok": True}})
        msg, fds = ipc_recv(right)
    finally:
        left.close()
        right.close()

    assert msg == {"type": "PING", "seq": 7, "payload": {"ok": True}}
    assert fds == []


def test_ipc_round_trips_file_descriptors_with_payload():
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    read_fd, write_fd = os.pipe()
    received_fds = []
    try:
        ipc_send(left, {"type": "FD"}, fds=[write_fd])
        msg, received_fds = ipc_recv(right)

        os.write(received_fds[0], b"hello")
        assert os.read(read_fd, 5) == b"hello"
        assert msg == {"type": "FD"}
    finally:
        for fd in received_fds:
            os.close(fd)
        os.close(read_fd)
        os.close(write_fd)
        left.close()
        right.close()


def test_ipc_recv_raises_eof_on_closed_socket():
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    left.close()
    try:
        with pytest.raises(EOFError):
            ipc_recv(right)
    finally:
        right.close()
