import configparser
import logging
import os
import pwd
import re
import select
import shlex
import signal
import socket
import subprocess
import time

from .acl import ACLResolver
from .config import ConsoleConfigStore, UserMapStore
from .ipc import ipc_send, ipc_recv
from .output import apply_filter, render_normalized
from .process import set_proc_title

log = logging.getLogger(__name__)

_VALID_VM_NAME = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_\-\.]{0,252}$')


def validate_vm_name(name: str) -> bool:
    return bool(_VALID_VM_NAME.match(name))


def run_monitor(rpc_sock: socket.socket, push_sock: socket.socket,
                ctl_sock: socket.socket,
                users_path: str, consoles_path: str,
                config: configparser.ConfigParser,
                user_map_store: UserMapStore,
                console_store: ConsoleConfigStore):
    set_proc_title("monitor")
    for h in logging.getLogger().handlers:
        h.setLevel(logging.NOTSET)
    log.info("Monitor started (pid=%d)", os.getpid())

    def reload_all():
        try:
            user_map_store.reload(users_path)
            log.info("User map reloaded from %s", users_path)
        except Exception as exc:
            log.error("User map reload failed: %s", exc)
        try:
            console_store.reload(consoles_path)
            log.info("Console config reloaded from %s", consoles_path)
        except Exception as exc:
            log.error("Console config reload failed: %s", exc)
        raw_cfg = console_store.get_raw()
        # Push refreshed console config to worker so its local copy stays
        # in sync (ACLs, patterns, commands, socket validation rules).
        try:
            ipc_send(push_sock, {
                'type': 'CONFIG_UPDATE',
                'console_config': raw_cfg,
            })
        except Exception as exc:
            log.error("CONFIG_UPDATE send failed: %s", exc)
        # Push refreshed watch_dir + console config to watcher so its
        # pattern matching and trusted_uid resolution stay current.
        try:
            ipc_send(ctl_sock, {
                'type': 'RELOAD_WATCH',
                'watch_dir': console_store.get_watch_dir(),
                'console_config': raw_cfg,
            })
        except Exception as exc:
            log.error("RELOAD_WATCH send failed: %s", exc)

    def handle_sighup(signum, frame):
        log.info("SIGHUP — reloading config")
        reload_all()

    def handle_sigusr1(signum, frame):
        log.info("SIGUSR1 — requesting session list")
        try:
            ipc_send(push_sock, {'type': 'SESSION_LIST_REQ'})
        except Exception as exc:
            log.error("SESSION_LIST_REQ failed: %s", exc)

    def handle_sigusr2(signum, frame):
        log.info("SIGUSR2 — reloading and enforcing ACL")
        reload_all()
        try:
            ipc_send(push_sock, {
                'type': 'ENFORCE_REQ',
                'user_map': user_map_store.get_map(),
            })
        except Exception as exc:
            log.error("ENFORCE_REQ failed: %s", exc)

    def handle_sigchld(signum, frame):
        try:
            while True:
                pid, status = os.waitpid(-1, os.WNOHANG)
                if pid == 0:
                    break
                log.debug("Reaped child pid=%d status=%d", pid, status)
        except ChildProcessError:
            pass

    signal.signal(signal.SIGHUP, handle_sighup)
    signal.signal(signal.SIGUSR1, handle_sigusr1)
    signal.signal(signal.SIGUSR2, handle_sigusr2)
    signal.signal(signal.SIGCHLD, handle_sigchld)

    seq = [0]

    def next_seq():
        seq[0] = (seq[0] + 1) & 0xFFFFFFFF
        return seq[0]

    while True:
        try:
            readable, _, _ = select.select(
                [rpc_sock, push_sock, ctl_sock], [], [])
        except Exception:
            log.exception("select error in monitor")
            break

        for active in readable:
            try:
                msg, fds = ipc_recv(active)
            except EOFError:
                log.info("IPC socket closed, monitor exiting")
                return
            except Exception:
                log.exception("IPC recv error")
                return

            mtype = msg.get('type')

            if mtype == 'CMD_REQ':
                # The worker sends {action, console} — never a raw command.
                # The monitor validates action against its own config,
                # builds the command, executes, processes output.
                # This ensures a compromised worker cannot cause the monitor
                # to run arbitrary commands as root.
                action = msg.get('action', '')
                console_name = msg.get('console', '')

                cmd_def = console_store.get_command(action)
                if cmd_def is None:
                    log.warning("CMD_REQ: unknown action %r from worker "
                                "(not in consoles.yaml commands section)",
                                action)
                    rendered = f"✗ Unknown command: {action!r}\r\n"
                    ipc_send(rpc_sock, {'type': 'CMD_RESP',
                                        'rendered': rendered,
                                        'seq': msg.get('seq')})
                    continue

                if not validate_vm_name(console_name):
                    log.warning("CMD_REQ: invalid console name %r",
                                console_name)
                    rendered = "✗ Invalid console name\r\n"
                    ipc_send(rpc_sock, {'type': 'CMD_RESP',
                                        'rendered': rendered,
                                        'seq': msg.get('seq')})
                    continue

                cmd_template = cmd_def.get('cmd', '')
                try:
                    cmd_str = cmd_template.format(name=console_name)
                except KeyError as e:
                    log.error("CMD_REQ: cmd template error for %r: %s",
                              action, e)
                    rendered = f"✗ Command template error: {e}\r\n"
                    ipc_send(rpc_sock, {'type': 'CMD_RESP',
                                        'rendered': rendered,
                                        'seq': msg.get('seq')})
                    continue

                cmd = shlex.split(cmd_str)
                log.debug("CMD_REQ: action=%r console=%r cmd=%r",
                          action, console_name, cmd)

                try:
                    raw = subprocess.check_output(
                        cmd, stderr=subprocess.STDOUT
                    ).decode('utf-8', errors='replace').strip()
                except subprocess.CalledProcessError as e:
                    raw = e.output.decode('utf-8', errors='replace').strip()
                except Exception as e:
                    raw = f"ERROR: {e}"

                fmt = cmd_def.get('format', 'raw')
                filter_def = cmd_def.get('filter')
                try:
                    normalized = apply_filter(raw, fmt, filter_def)
                except Exception:
                    log.exception("CMD_REQ: apply_filter failed")
                    normalized = {'type': 'string', 'value': raw}

                rendered = render_normalized(normalized)
                log.debug("CMD_REQ: rendered %r", rendered[:80])
                ipc_send(rpc_sock, {'type': 'CMD_RESP',
                                    'rendered': rendered,
                                    'seq': msg.get('seq')})

            elif mtype == 'SPAWN_REQ':
                # The worker sends only {username, console} — never a raw cmd
                # or run_as.  The monitor validates against its own refreshed
                # config so a compromised worker cannot cause arbitrary exec.
                username = msg.get('username', '')
                console_name = msg.get('console', '')

                if not validate_vm_name(console_name):
                    log.warning("SPAWN_REQ: invalid console name %r",
                                console_name)
                    ipc_send(rpc_sock, {'type': 'SPAWN_RESP', 'ok': False,
                                        'error': 'invalid console name',
                                        'seq': msg.get('seq')})
                    continue

                # Look up definition from monitor's own config.
                cfg = console_store.get()
                defn = cfg.get('consoles', {}).get(console_name)
                vars_: dict = {}
                if defn is None:
                    match = console_store.match_console_name(console_name)
                    if match:
                        defn, vars_ = match

                if defn is None:
                    # Fall back to defaults.console exec backend.
                    defn = console_store.get_default_exec()

                if defn is None:
                    log.warning("SPAWN_REQ: console %r not in config",
                                console_name)
                    ipc_send(rpc_sock, {'type': 'SPAWN_RESP', 'ok': False,
                                        'error': (f"console {console_name!r} "
                                                  f"not defined"),
                                        'seq': msg.get('seq')})
                    continue

                if defn.get('type', 'exec') != 'exec':
                    log.warning("SPAWN_REQ: console %r is not exec type",
                                console_name)
                    ipc_send(rpc_sock, {'type': 'SPAWN_RESP', 'ok': False,
                                        'error': (f"console {console_name!r} "
                                                  f"is not exec type"),
                                        'seq': msg.get('seq')})
                    continue

                # Re-verify ACL using the monitor's own current config so a
                # compromised worker cannot spawn consoles on behalf of users
                # who don't have access.
                acl = ACLResolver(user_map_store)
                if acl.resolve_access(username, console_name,
                                      defn, vars_) is None:
                    log.warning(
                        "SPAWN_REQ: user %r denied access to %r "
                        "(monitor ACL re-check)",
                        username, console_name)
                    ipc_send(rpc_sock, {'type': 'SPAWN_RESP', 'ok': False,
                                        'error': 'access denied',
                                        'seq': msg.get('seq')})
                    continue

                cmd_template = defn.get('cmd', '')
                if not cmd_template:
                    log.warning("SPAWN_REQ: console %r has no cmd",
                                console_name)
                    ipc_send(rpc_sock, {'type': 'SPAWN_RESP', 'ok': False,
                                        'error': (f"console {console_name!r} "
                                                  f"has no cmd"),
                                        'seq': msg.get('seq')})
                    continue

                try:
                    cmd_str = cmd_template.format(name=console_name, **vars_)
                except KeyError as e:
                    log.error("SPAWN_REQ: cmd template error for %r: %s",
                              console_name, e)
                    ipc_send(rpc_sock, {'type': 'SPAWN_RESP', 'ok': False,
                                        'error': f"cmd template error: {e}",
                                        'seq': msg.get('seq')})
                    continue

                import pty as _pty
                cmd = shlex.split(cmd_str)
                try:
                    master_fd, slave_fd = _pty.openpty()
                    child = os.fork()
                    if child == 0:
                        try:
                            import fcntl as _fcntl
                            os.close(master_fd)
                            os.setsid()
                            _fcntl.ioctl(slave_fd, 0x540E, 0)  # TIOCSCTTY
                            for fd in (0, 1, 2):
                                os.dup2(slave_fd, fd)
                            os.close(slave_fd)
                            os.execvp(cmd[0], cmd)
                        except Exception as e:
                            os.write(2, f"spawn error: {e}\n".encode())
                        os._exit(1)

                    os.close(slave_fd)
                    log.info("Spawned: console=%r cmd=%r pid=%d",
                             console_name, cmd_str, child)
                    ipc_send(rpc_sock, {'type': 'SPAWN_RESP', 'ok': True,
                                        'pid': child,
                                        'seq': msg.get('seq')},
                             fds=[master_fd])
                    os.close(master_fd)

                except Exception as exc:
                    log.exception("SPAWN_REQ failed")
                    try:
                        ipc_send(rpc_sock, {'type': 'SPAWN_RESP', 'ok': False,
                                            'error': str(exc),
                                            'seq': msg.get('seq')})
                    except Exception:
                        pass

            elif mtype == 'PEERCRED_LOOKUP_REQ':
                uid = msg.get('uid')
                username = None
                try:
                    if uid is not None:
                        username = pwd.getpwuid(uid).pw_name
                except KeyError:
                    pass
                ipc_send(rpc_sock, {'type': 'PEERCRED_LOOKUP_RESP',
                                    'username': username,
                                    'seq': msg.get('seq')})

            elif mtype == 'SESSION_LIST_RESP':
                sessions = msg.get('sessions', [])
                hubs = msg.get('hubs', [])
                log.info("Sessions (%d):", len(sessions))
                for s in sessions:
                    elapsed = time.monotonic() - s['started']
                    h, m = divmod(int(elapsed), 3600)
                    m, sec = divmod(m, 60)
                    log.info("  %-20s %-25s [%s] %02d:%02d:%02d",
                             s['username'],
                             s.get('console') or '(prompt)',
                             'ro' if s.get('read_only') else 'rw',
                             h, m, sec)
                log.info("Hubs (%d):", len(hubs))
                for hub in hubs:
                    log.info("  %-25s clients=%d", hub['name'],
                             len(hub['clients']))

            elif mtype == 'ENFORCE_RESP':
                for desc in msg.get('killed', []):
                    log.info("KILLED: %s", desc)
                log.info("Enforcement: %d killed, %d retained",
                         len(msg.get('killed', [])),
                         len(msg.get('retained', [])))

            elif mtype == 'WATCHER_READY':
                log.info("Watcher ready, watching: %r", msg.get('watch_dir'))

            elif mtype == 'WATCHER_DIR_ERROR':
                log.error("Watcher: %s", msg.get('error'))

            else:
                log.warning("Monitor: unknown message type %r", mtype)

    log.info("Monitor exiting")
