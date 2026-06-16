# vnctlsd PAM bridge

## Overview

The PAM bridge provides password-based (PAM) login for vnctlsd without
requiring the daemon itself to run as root.  Responsibility is split across
three components, each with the minimum privilege needed for its role.

## Architecture

```
TLS terminator        _vnctlsd process        setuid binary         daemon worker
(HAProxy/stunnel)     vnctlsd-pam-bridge      vnctl-user-pipe       vnctlsd

[network client] ──► [PAM bridge] ──exec──► [helper] ──socket──► [worker]
  plain TCP           auth only              uid drop only          authz only
                      _vnctlsd uid           root→user, briefly     _vnctlsd uid
```

### Component responsibilities

| Component           | Runs as       | Privilege           | Responsibility                        |
|---------------------|---------------|---------------------|---------------------------------------|
| vnctlsd-pam-bridge  | `_vnctlsd`    | none                | Prompt for credentials, verify via PAM |
| vnctl-user-pipe     | `_vnctlsd`    | setuid root briefly | Identity transition to target user    |
| vnctlsd (worker)    | `_vnctlsd`    | none                | Authorise console operations          |

### Why three separate pieces?

- The PAM bridge is **network-facing** — it must not run as root.
- After PAM succeeds, something must call `setuid(2)` to become the target
  user so the daemon's SO_PEERCRED check sees the right uid.  Non-root
  processes cannot `setuid()` to an arbitrary third user.
- A setuid C binary (not a script — the kernel ignores the setuid bit on
  interpreted files) provides that one capability without exposing a
  long-lived root process to the network.

## Identity model

The daemon socket is world-connectable (mode `0666`).  The **only** identity
claim the daemon trusts is the kernel-reported `struct ucred` from
`SO_PEERCRED` — `uid`, `gid`, `pid` of the connecting process.  No token,
secret, or header is sent over the socket; anything the client sends would be
controlled by the client.

After `vnctl-user-pipe` drops to the authenticated user, the socket connection
it opens to the daemon carries that user's uid in SO_PEERCRED.  Authorization
(which consoles the user may access) is decided entirely by the daemon using
`users.yaml`.

## Components

### 1. vnctlsd-pam-bridge

A Python daemon running as `_vnctlsd`.  For each inbound connection it:

1. Sends a login banner and prompts for username and password.
2. Forks a short-lived grandchild that calls `pam_authenticate()`, writes
   the result to a pipe, and exits.  The password never outlives that process.
3. On success, forks a child and immediately `execv()`s `vnctl-user-pipe
   --user USERNAME` with the client socket wired to stdin/stdout.
4. The parent closes its fd copy and returns — the helper owns the session.

PAM auth runs in a grandchild (not the main thread) so the plaintext password
is freed by the OS when the grandchild exits.  `RLIMIT_NPROC=0` prevents the
grandchild from spawning its own children.

Rate limiting tracks per-username failure counts over a sliding window.  After
`--max-failures` failures in `--failure-window` seconds the account is locked
out for `--lockout-duration` seconds.  A constant minimum login time
(2 seconds) is enforced regardless of how quickly PAM returns, to slow
credential testing.

### 2. vnctl-user-pipe (setuid helper)

A small C binary.  Its startup sequence is strictly ordered:

1. **Caller validation** — real uid must equal the `_vnctlsd` system account
   uid.  Any other caller gets an error and the process exits.
2. **Argument parsing** — only `--user USERNAME` is accepted.  No other flags.
   Username is validated against `[a-zA-Z0-9._-]{1,64}`.
3. **User resolution** — `getpwnam(username)` to obtain uid/gid.  Resolving
   to uid 0 is rejected.
4. **Socket validation** — `lstat(DAEMON_SOCKET)` verifies the socket is not
   a symlink, is owned by `_vnctlsd`, and lives in a `_vnctlsd`-owned,
   non-writable directory.  Done while still euid=root (setuid bit) so tight
   directory permissions do not block the check, and done before connecting to
   bound the TOCTOU window: a `_vnctlsd`-owned parent directory means only
   `_vnctlsd` can replace the socket after this check.
5. **Privilege drop** — `setgroups()` → `setgid()` → `setuid()`.  Effective
   root from the setuid bit is consumed here and nowhere else.
6. **Verification** — `setuid(0)` must return `EPERM`.  If it succeeds, the
   process aborts.
7. **Connect** — `connect(AF_UNIX, DAEMON_SOCKET)` as the target user.  The
   daemon socket is mode `0666` so any uid can connect; access control is done
   server-side.  Because `connect()` runs after `setuid()`, SO_PEERCRED on the
   server side reports the target uid, not root.
8. **FD cleanup** — all file descriptors above stderr except the socket fd are
   closed.
9. **NO_NEW_PRIVS** — `prctl(PR_SET_NO_NEW_PRIVS, 1)` prevents any further
   privilege gain via setuid/setcap binaries.
10. **Landlock** — the kernel ABI version is probed with the documented form
    `landlock_create_ruleset(NULL, 0, VERSION)`.  An empty ruleset is applied
    covering all access rights supported by the detected ABI version
    (V1 rights on 5.13+, REFER on 5.19+, TRUNCATE on 6.2+, IOCTL_DEV on
    6.7+).  If landlock is unavailable the process aborts — fail-closed for a
    setuid helper.
11. **Seccomp** — an allowlist is loaded that permits only: `read`, `write`,
    `poll`/`ppoll`, `shutdown`, `close`, `recvfrom`/`sendto`, `recvmsg`/
    `sendmsg`, `exit`/`exit_group`, `rt_sigreturn`, `restart_syscall`, and
    a small set of glibc memory management syscalls (`brk`, `mmap`, `munmap`,
    `mprotect`, `futex`, `clock_gettime`).  Any other syscall kills the process
    with `SCMP_ACT_KILL_PROCESS`.
12. **Bridge loop** — `poll()` on stdin and the socket fd, copying data between
    them until either side closes.  `EINTR` is retried on read/write;
    `POLLERR`/`POLLNVAL` on either fd terminates the loop.

### 3. vnctlsd daemon

Unchanged.  The worker process accepts connections on a Unix socket (mode
`0666`), reads `SO_PEERCRED` to determine the caller's uid, resolves that to
a username via the monitor (which can read `/etc/passwd`), and applies ACL
rules from `users.yaml`.

The daemon does not know or care how the client authenticated.  A PAM-bridge
session and an SSH session (via vnctlsd-ssh-bridge) are indistinguishable to the daemon;
both are identified by uid alone.

## Installation

### System account

```sh
useradd -r -s /sbin/nologin -d /nonexistent -M _vnctlsd
```

### Build the helper

```sh
cc -O2 -Wall -Wextra \
   -o vnctl-user-pipe bridge/vnctl-user-pipe.c \
   -lseccomp
```

Requirements:
- Linux kernel ≥ 5.13 for Landlock (older kernels fall back to no filesystem
  restriction, logging a warning).
- `libseccomp` development headers and library (`libseccomp-dev` /
  `libseccomp-devel`).
- `linux/landlock.h` from the kernel headers package (`linux-libc-dev` /
  `kernel-headers`).

### Install the helper

```sh
install -m 4750 -o root -g _vnctlsd vnctl-user-pipe /usr/libexec/
```

The `4750` mode sets the setuid bit, makes the file root-owned, and restricts
execution to the `_vnctlsd` group — exactly the PAM bridge's group.

### Install the PAM bridge

```sh
install -m 755 bridge/vnctlsd-pam-bridge /usr/local/sbin/
```

## Systemd service

```ini
[Unit]
Description=vnctlsd PAM authentication bridge
After=network.target vnctlsd.service
Requires=vnctlsd.service

[Service]
Type=simple
User=_vnctlsd
Group=_vnctlsd

ExecStart=/usr/local/sbin/vnctlsd-pam-bridge \
    --listen 127.0.0.1:8023 \
    --helper /usr/libexec/vnctl-user-pipe

Restart=on-failure
RestartSec=5

# Hardening — NOTE: NoNewPrivileges must NOT be set here.
# The bridge forks children that exec the setuid helper; NoNewPrivileges
# would prevent the setuid bit from taking effect, breaking the privilege
# transition.  The helper applies NoNewPrivileges itself after the drop.
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service fork execve
SystemCallErrorAction=kill
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
```

## TLS termination

The PAM bridge accepts plain TCP; TLS must be terminated upstream.  Example
with HAProxy:

```
frontend vnctlsd-tls
    bind *:8022 ssl crt /etc/haproxy/vnctlsd.pem
    default_backend vnctlsd-pam

backend vnctlsd-pam
    server pam 127.0.0.1:8023
```

Or with stunnel:

```ini
[vnctlsd]
accept  = 8022
connect = 127.0.0.1:8023
cert    = /etc/stunnel/vnctlsd.pem
```

## PAM configuration

The bridge uses the PAM service name `login` by default.  Create a dedicated
service to control authentication separately from the system login:

`/etc/pam.d/vnctlsd`:
```
auth    required  pam_unix.so
account required  pam_unix.so
```

The `pam_authenticate()` call runs in a short-lived grandchild process that
immediately exits after writing the result to a pipe.  This is the same
approach used by `unix_chkpwd(8)` — the password is freed when the grandchild
exits and its memory is reclaimed by the OS.

## Security properties

| Property | How achieved |
|---|---|
| Bridge not root | Runs as `_vnctlsd`; setuid helper does the uid transition |
| Network-facing code not root | PAM bridge is `_vnctlsd`; TLS terminator is separate |
| Password not resident long-term | PAM runs in a short-lived grandchild per login attempt |
| Identity not forgeable by bridge | Daemon uses SO_PEERCRED (kernel-reported uid), not any claim |
| Helper cannot be exec'd by untrusted users | `chmod 4750`, `chgrp _vnctlsd` — only `_vnctlsd` can exec it |
| Helper cannot open new files after drop | Landlock deny-all ruleset (fail-closed; aborts if kernel < 5.13) |
| Helper cannot use non-I/O syscalls | Seccomp allowlist; any unlisted syscall kills the process |
| Helper cannot re-gain privileges | NO_NEW_PRIVS + permanent uid drop verified with `setuid(0)` |
| Socket path cannot be swapped | `lstat()` before `connect()` + non-world-writable socket dir |

## Attack surface summary

```
Internet  →  TLS terminator  →  PAM bridge (_vnctlsd)
                                      │ fork+exec (setuid)
                                      ▼
                               vnctl-user-pipe (root→user)
                                      │ Unix socket (SO_PEERCRED)
                                      ▼
                               vnctlsd worker (_vnctlsd)
```

An attacker who compromises the PAM bridge gains the `_vnctlsd` account, which
can only exec `vnctl-user-pipe` on behalf of PAM-authenticated users.  It
cannot connect to the daemon socket under an arbitrary uid without going through
the helper (which validates the caller's real uid), and it cannot impersonate
another user's uid to the daemon (SO_PEERCRED is set by the kernel to the
helper's uid after the drop, not by the bridge).
