import array
import json
import logging
import socket
import struct

log = logging.getLogger(__name__)

_IPC_MAX_FDS = 4
_IPC_MAX_MSG = 65536
_IPC_CMSG_SPACE = socket.CMSG_SPACE(_IPC_MAX_FDS * array.array('i').itemsize)


def ipc_send(sock: socket.socket, msg: dict, fds: list[int] | None = None):
    payload = json.dumps(msg).encode()
    fd_count = len(fds) if fds else 0
    header = struct.pack('>BI', fd_count, len(payload))
    log.debug("ipc_send: type=%r fd_count=%d", msg.get('type'), fd_count)
    if fds:
        cmsg = array.array('i', fds)
        sock.sendmsg(
            [header + payload],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, cmsg)],
        )
    else:
        sock.sendall(header + payload)


def ipc_recv(sock: socket.socket) -> tuple[dict, list[int]]:
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
            arr = array.array('i')
            arr.frombytes(
                cmsg_data[:len(cmsg_data) - (len(cmsg_data) % arr.itemsize)])
            fds.extend(arr)

    msg = json.loads(payload)
    log.debug("ipc_recv: type=%r fds=%r", msg.get('type'), fds)
    return msg, fds
