import ctypes
import logging
import multiprocessing
import sys

log = logging.getLogger(__name__)


def set_proc_title(title: str):
    multiprocessing.current_process().name = title
    try:
        import setproctitle
        setproctitle.setproctitle(f"vnctlsd: {title}")
        return
    except ImportError:
        pass
    try:
        argv0 = f"vnctlsd: {title}".encode()
        buf = (ctypes.c_char * len(sys.argv[0])).from_address(
            ctypes.cast(ctypes.c_char_p(sys.argv[0].encode()),
                        ctypes.c_void_p).value)
        buf.value = argv0[:len(sys.argv[0]) - 1] + b'\x00'
    except Exception:
        pass
