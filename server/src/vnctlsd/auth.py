import ctypes
import ctypes.util
import logging
import os
import resource
import sys
import threading
import time

from .security import prctl_no_new_privs

log = logging.getLogger(__name__)

PAM_SUCCESS = 0
PAM_PROMPT_ECHO_OFF = 1
PAM_PROMPT_ECHO_ON = 2
PAM_ERROR_MSG = 3
PAM_TEXT_INFO = 4


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
_libc.calloc.restype = ctypes.c_void_p
_libc.strdup.argtypes = [ctypes.c_char_p]
_libc.strdup.restype = ctypes.c_void_p

_pam_lib = ctypes.util.find_library("pam")
if not _pam_lib:
    log.error("libpam not found")
    sys.exit(1)

_pam = ctypes.CDLL(_pam_lib)
_pam.pam_start.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                            ctypes.POINTER(_PamConv),
                            ctypes.POINTER(ctypes.c_void_p)]
_pam.pam_start.restype = ctypes.c_int
_pam.pam_authenticate.argtypes = [ctypes.c_void_p, ctypes.c_int]
_pam.pam_authenticate.restype = ctypes.c_int
_pam.pam_acct_mgmt.argtypes = [ctypes.c_void_p, ctypes.c_int]
_pam.pam_acct_mgmt.restype = ctypes.c_int
_pam.pam_end.argtypes = [ctypes.c_void_p, ctypes.c_int]
_pam.pam_end.restype = ctypes.c_int


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
                arr[i].resp = _libc.strdup(p)
                arr[i].resp_retcode = 0
            elif style == PAM_PROMPT_ECHO_ON:
                arr[i].resp = _libc.strdup(u)
                arr[i].resp_retcode = 0
            elif style in (PAM_ERROR_MSG, PAM_TEXT_INFO):
                arr[i].resp = None
                arr[i].resp_retcode = 0
            else:
                return 1
        resp[0] = arr
        return PAM_SUCCESS

    cb = _CONV_FUNC(conv_cb)
    conv = _PamConv(cb, None)
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
    pid = os.fork()
    if pid == 0:
        try:
            os.close(r_fd)
            prctl_no_new_privs()
            resource.setrlimit(resource.RLIMIT_NPROC, (0, 0))
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


class RateLimiter:
    def __init__(self, max_failures: int, failure_window: float,
                 lockout_duration: float):
        self._max = max_failures
        self._window = failure_window
        self._lockout = lockout_duration
        self._lock = threading.Lock()
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
