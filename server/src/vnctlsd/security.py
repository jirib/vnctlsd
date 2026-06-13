import ctypes
import ctypes.util
import logging
import os

log = logging.getLogger(__name__)


def prctl_no_new_privs():
    libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:
        log.warning("prctl(PR_SET_NO_NEW_PRIVS) failed")
    else:
        log.info("PR_SET_NO_NEW_PRIVS set")


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
        'connect',
        'socket',
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


def apply_landlock(socket_path: str, watch_dir: str):
    SYS_landlock_create_ruleset = 444
    SYS_landlock_add_rule = 445
    SYS_landlock_restrict_self = 446
    LANDLOCK_CREATE_RULESET_VERSION = 1 << 0
    LANDLOCK_RULE_PATH_BENEATH = 1
    LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2
    LANDLOCK_ACCESS_FS_READ_DIR = 1 << 3
    LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1

    libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
    abi = libc.syscall(SYS_landlock_create_ruleset, None, 0,
                       LANDLOCK_CREATE_RULESET_VERSION)
    if abi < 0:
        log.warning("Landlock not supported, skipping")
        return

    handled = (LANDLOCK_ACCESS_FS_READ_FILE |
               LANDLOCK_ACCESS_FS_READ_DIR |
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
                    ("parent_fd", ctypes.c_int32)]

    def add_path(path: str, access: int):
        try:
            fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
        except OSError as e:
            log.warning("Landlock: cannot open %r: %s", path, e)
            return
        a = PathBeneathAttr(allowed_access=access, parent_fd=fd)
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


def apply_watcher_seccomp():
    try:
        import seccomp
    except ImportError:
        log.warning("python-seccomp not installed, skipping")
        return
    f = seccomp.SyscallFilter(defaction=seccomp.KILL)
    for sc in [
        'inotify_init1', 'inotify_add_watch', 'inotify_rm_watch',
        'lstat', 'lstat64', 'newfstatat', 'statx',
        'fstat', 'fstat64',
        'openat',
        'getdents64',
        'close',
        'read', 'write', 'readv', 'writev',
        'recvmsg', 'sendmsg', 'sendto', 'recvfrom',
        'select', 'pselect6', 'poll', 'ppoll',
        'epoll_wait', 'epoll_pwait', 'epoll_ctl',
        'epoll_create', 'epoll_create1',
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
        'fcntl',
        'ioctl',
        'exit', 'exit_group',
    ]:
        try:
            f.add_rule(seccomp.ALLOW, sc)
        except Exception:
            pass
    f.load()
    log.info("Watcher seccomp filter applied")


def apply_watcher_landlock(watch_dir: str):
    SYS_landlock_create_ruleset = 444
    SYS_landlock_add_rule = 445
    SYS_landlock_restrict_self = 446
    LANDLOCK_CREATE_RULESET_VERSION = 1 << 0
    LANDLOCK_RULE_PATH_BENEATH = 1
    LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2
    LANDLOCK_ACCESS_FS_READ_DIR = 1 << 3

    libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
    abi = libc.syscall(SYS_landlock_create_ruleset, None, 0,
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
                    ("parent_fd", ctypes.c_int32)]

    ro = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR
    try:
        fd = os.open(watch_dir, os.O_PATH | os.O_CLOEXEC)
        a = PathBeneathAttr(allowed_access=ro, parent_fd=fd)
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
