import array
import json
import logging
import os
import socket
import struct

log = logging.getLogger(__name__)

_IPC_MAX_FDS = 4
_IPC_MAX_MSG = 65536
_IPC_HDR = struct.Struct('>BI')   # 1-byte fd_count + 4-byte payload length
_IPC_CMSG_SPACE = socket.CMSG_SPACE(_IPC_MAX_FDS * array.array('i').itemsize)


def ipc_send(sock: socket.socket, msg: dict, fds: list[int] | None = None):
    payload = json.dumps(msg).encode()
    fd_count = len(fds) if fds else 0
    header = _IPC_HDR.pack(fd_count, len(payload))
    log.debug("ipc_send: type=%r fd_count=%d", msg.get('type'), fd_count)
    if fds:
        cmsg = array.array('i', fds)
        sock.sendmsg(
            [header + payload],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, cmsg)],
        )
    else:
        sock.sendall(header + payload)


def _recv_bytes(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from a stream socket."""
    buf = bytearray(n)
    view = memoryview(buf)
    pos = 0
    while pos < n:
        got = sock.recv_into(view[pos:], n - pos)
        if not got:
            raise EOFError("IPC socket closed during read")
        pos += got
    return bytes(buf)


def ipc_recv(sock: socket.socket) -> tuple[dict, list[int]]:
    # Read exactly the 5-byte header via recvmsg so ancdata (SCM_RIGHTS fds)
    # are captured in the same call as the first bytes of the message.
    hdr_data, ancdata, _, _ = sock.recvmsg(_IPC_HDR.size, _IPC_CMSG_SPACE)
    if not hdr_data:
        raise EOFError("IPC socket closed")

    # recvmsg may return fewer than 5 bytes on SOCK_STREAM; read the rest
    # with plain recv (ancdata will not appear again for this message).
    header_buf = bytearray(hdr_data)
    while len(header_buf) < _IPC_HDR.size:
        chunk = sock.recv(_IPC_HDR.size - len(header_buf))
        if not chunk:
            raise EOFError("IPC closed during header read")
        header_buf.extend(chunk)

    fd_count, length = _IPC_HDR.unpack(bytes(header_buf))

    if fd_count > _IPC_MAX_FDS:
        raise ValueError(
            f"IPC: fd_count {fd_count} exceeds maximum {_IPC_MAX_FDS}")
    if length > _IPC_MAX_MSG:
        raise ValueError(
            f"IPC: payload length {length} exceeds maximum {_IPC_MAX_MSG}")

    payload = _recv_bytes(sock, length)

    # Extract file descriptors from ancillary data.
    fds: list[int] = []
    for lvl, typ, cmsg_data in ancdata:
        if lvl == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS:
            arr = array.array('i')
            arr.frombytes(
                cmsg_data[:len(cmsg_data) - (len(cmsg_data) % arr.itemsize)])
            fds.extend(arr)

    # Close any fds beyond what the header declared to prevent fd leaks.
    while len(fds) > fd_count:
        extra = fds.pop()
        try:
            os.close(extra)
        except OSError:
            pass
        log.warning("ipc_recv: closed unexpected extra fd %d", extra)

    # Detect the opposite: header promised fds that never arrived.
    if len(fds) < fd_count:
        raise ValueError(
            f"IPC: header declared {fd_count} fds but only {len(fds)} received")

    msg = json.loads(payload)
    log.debug("ipc_recv: type=%r fds=%r", msg.get('type'), fds)
    return msg, fds
