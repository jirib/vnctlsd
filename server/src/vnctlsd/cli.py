import argparse
import configparser
import logging
import os
import pwd
import socket
import sys

from .config import ConsoleConfigStore, UserMapStore, load_console_config, load_user_map
from .constants import DEFAULT_CONFIG
from .monitor import run_monitor
from .process import set_proc_title
from .watcher import run_watcher
from .worker import run_worker

log = logging.getLogger(__name__)


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
        for h in logging.getLogger().handlers:
            h.setLevel(logging.NOTSET)
        log.debug("Debug logging enabled")
    if args.no_privsep:
        log.warning("*** --no-privsep: seccomp+landlock DISABLED ***")

    config = configparser.ConfigParser()
    config.read_string(DEFAULT_CONFIG)
    if os.path.exists(args.config):
        config.read(args.config)
        log.info("Loaded config from %s", args.config)

    if not os.path.exists(args.users):
        log.error("User map not found: %s", args.users)
        sys.exit(1)
    try:
        user_map = UserMapStore(load_user_map(args.users))
        log.info("Loaded user map from %s", args.users)
    except Exception as exc:
        log.error("User map load failed: %s", exc)
        sys.exit(1)

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

    worker_pw = watcher_pw = None
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

    socket_path = config.get('core', 'socket_path')
    socket_dir = os.path.dirname(socket_path)
    os.makedirs(socket_dir, mode=0o750, exist_ok=True)

    if os.path.exists(socket_path):
        os.unlink(socket_path)

    # The daemon listens on a Unix socket reachable by any local user.
    # Mode 0o666: world-connectable; identity is established exclusively via
    # SO_PEERCRED — the kernel-reported uid of the connecting process.
    trusted_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    trusted_sock.bind(socket_path)
    trusted_sock.listen(128)
    os.chmod(socket_path, 0o666)
    os.chown(socket_path, 0, 0)
    log.info("Socket: %s", socket_path)

    # rpc:   worker ↔ monitor (AUTH, CMD, SPAWN)
    # push:  monitor → worker (SESSION_LIST, ENFORCE)
    # ctl:   monitor ↔ watcher (RELOAD_WATCH, WATCHER_READY/ERROR)
    # watch: watcher → worker (SOCKET_APPEARED/DISAPPEARED)
    rpc_m,    rpc_w    = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    push_m,   push_w   = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    ctl_m,    ctl_w    = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    watch_w2, watch_worker = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

    pidfile = config.get('core', 'pidfile', fallback=None)

    _KEEP = {'PATH', 'LIBVIRT_DEFAULT_URI', 'LANG', 'LC_ALL'}
    for k in list(os.environ.keys()):
        if k not in _KEEP:
            del os.environ[k]
    os.environ['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
    os.environ['HOME'] = '/nonexistent'

    try:
        import seccomp as _sp  # noqa: F401
        log.info("seccomp pre-loaded")
    except ImportError:
        log.warning("python-seccomp not available")

    watcher_pid = os.fork()
    if watcher_pid == 0:
        rpc_m.close(); rpc_w.close()
        push_m.close(); push_w.close()
        watch_worker.close()
        trusted_sock.close()
        os.setsid()

        run_watcher(ctl_w, watch_w2, console_store, watcher_pw,
                    no_seccomp=args.no_seccomp or args.no_privsep,
                    no_landlock=args.no_landlock or args.no_privsep)
        os._exit(0)

    worker_pid = os.fork()
    if worker_pid == 0:
        rpc_m.close()
        push_m.close()
        ctl_m.close(); ctl_w.close()
        watch_w2.close()
        os.setsid()

        run_worker(rpc_w, push_w, watch_worker, trusted_sock,
                   config, user_map, console_store, worker_pw,
                   no_seccomp=args.no_seccomp or args.no_privsep,
                   no_landlock=args.no_landlock or args.no_privsep)
        os._exit(0)

    rpc_w.close()
    push_w.close()
    ctl_w.close()
    watch_w2.close()
    watch_worker.close()
    trusted_sock.close()

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
