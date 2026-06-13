# vnctlsd

A privilege-separated virsh serial console dispatcher written in Python,
inspired by [Conserver](https://www.conserver.com/) but designed for
KVM/QEMU virtual machines managed by libvirt.

The daemon drives the terminal server-side. The client is a dumb TLS pipe —
`socat` works on Linux and macOS, and a minimal Go binary (`vnctl`) is
provided for Windows compatibility.

---

## Features

- **Conserver-style server-driven terminal** — login prompt, command menu,
  and console attach/detach all happen on the server. The client sends raw
  keystrokes and displays raw output.
- **Console fan-out** — multiple users can attach to the same VM console
  simultaneously. Read-write users type; read-only users watch.
- **Privilege separation** — three processes with distinct trust levels:
  - **monitor** (root): PAM authentication, virsh spawning, management commands
  - **worker** (`_vnctlsd`): network socket, client sessions, console hubs
  - **watcher** (`_vnctlsd`): inotify on the socket directory, validates
    QEMU unix sockets as they appear
- **PAM authentication in isolated subprocesses** — each auth attempt forks
  a short-lived child. Password memory is freed by the OS on exit; it never
  persists in the long-lived monitor process.
- **landlock + seccomp** — each process is restricted to the minimal
  filesystem paths and syscalls it actually needs.
- **Two console delivery modes**:
  - `exec` — daemon spawns `virsh console <vm>` on demand when a user attaches
  - `qemu_unix` — QEMU dials the daemon at VM boot over a unix socket;
    the hub is live from the first byte, capturing early boot output
- **Glob-based console patterns** — one pattern covers many VMs:
  `/run/vnctlsd/console-{name}.sock` matches all QEMU sockets and extracts
  the VM name automatically
- **ACL resolver** — two-axis access control: console definitions carry
  `rw`/`ro` lists (usernames, group names, or `*`), and users carry group
  memberships with roles. Console ACL takes priority; user map role is the
  fallback.
- **Hot reload** — `SIGHUP` reloads user map and console config without
  restarting. `SIGUSR1` logs active sessions. `SIGUSR2` reloads and
  disconnects sessions whose access has been revoked.
- **Rate limiting** — per-username failed login counter with configurable
  lockout. Constant-time login responses prevent timing-based enumeration.
- **TLS termination by frontend** — the daemon speaks plaintext over a unix
  socket. TLS is handled upstream by ghostunnel, stunnel, or HAProxy.

---

## Architecture

```
                        ┌─────────────────────────────────────┐
                        │           master (root)             │
                        │  startup, socket creation, fork x3  │
                        └──────────────┬──────────────────────┘
                                       │ fork
              ┌────────────────────────┼────────────────────────┐
              │                        │                        │
    ┌─────────▼──────────┐  ┌──────────▼─────────┐  ┌─────────▼──────────┐
    │   monitor (root)   │  │  worker(_vnctlsd)  │  │ watcher(_vnctlsd)  │
    │                    │  │                    │  │                    │
    │ PAM subprocess     │  │ unix socket        │  │ inotify watch dir  │
    │ virsh spawn        │  │ client sessions    │  │ lstat validation   │
    │ management cmds    │  │ ConsoleHub fan-out │  │ glob pattern match │
    │ config reload      │  │ ACL enforcement    │  │                    │
    │ SIGHUP/USR1/USR2   │  │ rate limiting      │  │ landlock: ro only  │
    │                    │  │ landlock + seccomp │  │ seccomp: inotify   │
    └────────┬───────────┘  └──────────┬─────────┘  └─────────┬──────────┘
             │    rpc socketpair        │                       │
             │◄────────────────────────►│                       │
             │    push socketpair       │                       │
             │─────────────────────────►│                       │
             │    ctl socketpair        │    watch socketpair   │
             │◄─────────────────────────────────────────────────►│
             │                          │◄──────────────────────┘
             │                          │  SOCKET_APPEARED/DISAPPEARED
```

### Socketpairs

| Name    | Direction          | Purpose                                     |
|---------|--------------------|---------------------------------------------|
| `rpc`   | worker ↔ monitor   | AUTH_REQ, CMD_REQ, SPAWN_REQ + responses    |
| `push`  | monitor → worker   | SESSION_LIST_REQ, ENFORCE_REQ               |
| `ctl`   | monitor ↔ watcher  | RELOAD_WATCH, WATCHER_READY, WATCHER_ERROR  |
| `watch` | watcher → worker   | SOCKET_APPEARED, SOCKET_DISAPPEARED         |

### Console hub lifecycle

```
user types 'console vm-lab01'
  → worker sends SPAWN_REQ to monitor
    → monitor fork+setuid+exec virsh console vm-lab01
      → monitor sends pty master fd to worker via SCM_RIGHTS
        → worker creates ConsoleHub(vm-lab01, master_fd)
          → hub reader thread broadcasts pty output to all clients
            → read-write client feeds keystrokes back
            → read-only clients receive output only

user types '~.' to detach
  → hub removes client
  → if no clients remain: grace period timer starts (default 30s)
    → if no reconnect within grace: hub tears down, virsh exits
```

For `qemu_unix` consoles the hub is created when QEMU connects at VM boot,
before any user attaches.

---

## Installation

### Requirements

- Linux kernel 5.13+ (for landlock)
- Python 3.11+
- libpam
- libvirt + virsh
- `python-seccomp` (libseccomp bindings)
- PyYAML or tomli (for config files)
- ghostunnel, stunnel, or HAProxy (for TLS termination)

```bash
pip install pyyaml python-seccomp
# or for TOML config:
pip install tomli   # Python < 3.11 only; 3.11+ has tomllib in stdlib
```

### Service account

```bash
# Create worker and watcher account
useradd --system --no-create-home --home-dir /nonexistent \
        --shell /sbin/nologin --comment "vnctlsd worker" _vnctlsd

# Create socket group (used to allow ghostunnel/stunnel to connect)
groupadd --system _vnctlsd
usermod -aG _vnctlsd _vnctlsd

# Add your TLS terminator's user to the group if it runs as non-root
# e.g. for ghostunnel running as 'ghostunnel':
usermod -aG libvirt _vnctlsd   # so worker can run virsh list
```

### Socket directory

```bash
install -d -o root -g _vnctlsd -m 0750 /run/vnctlsd
```

The watcher refuses to watch a world-writable directory — it would allow
any local user to create a fake console socket and capture credentials.
Permissions must be at most `0770` with a trusted group.

### Building the client

```bash
cd vnctl
go mod init vnctl
go get golang.org/x/term
go build -o vnctl vnctl.go

# Windows (cross-compile from Linux)
GOOS=windows GOARCH=amd64 go build -o vnctl.exe vnctl.go

# macOS
GOOS=darwin GOARCH=amd64 go build -o vnctl-macos vnctl.go
```

---

## Configuration

### `vnctlsd.ini`

```ini
[core]
socket_path      = /run/vnctlsd/vnctlsd.sock
socket_mode      = 0660
socket_group     = _vnctlsd
worker_user      = _vnctlsd
watcher_user     = _vnctlsd
pidfile          = /run/vnctlsd/vnctlsd.pid
max_threads      = 64
hub_grace_period = 30       # seconds to keep hub alive after last client leaves
login_timeout    = 30       # seconds to complete login before disconnect
idle_timeout     = 300      # seconds of inactivity at prompt before disconnect

[auth]
max_failures     = 5        # failed logins before lockout
lockout_duration = 60       # seconds locked out after max_failures
failure_window   = 120      # seconds over which failures are counted
```

### `users.yaml`

Users belong to groups. Groups carry roles. A user's effective role is the
highest role across all their groups (`read_write` beats `read_only`).

```yaml
users:
  student01:
    groups: [lab-a]
  student02:
    groups: [lab-b]
  jbelka:
    groups: [mentors, admins]

groups:
  lab-a:
    role: read_write
  lab-b:
    role: read_write
  mentors:
    role: read_only    # can watch consoles, cannot type
  admins:
    role: read_write
```

### `consoles.yaml`

```yaml
# Global socket validation defaults
socket_validation:
  trusted_uid: libvirt-qemu   # QEMU sockets must be owned by this user
  watch_dir: /run/vnctlsd/    # directory to watch for QEMU unix sockets

# Explicit console definitions (highest priority)
consoles:
  special-vm:
    type: exec
    cmd: "virsh -c qemu:///system console special-vm --force"
    run_as: _vnctlsd
    rw: [admins]
    ro: [mentors]
    validation:
      trusted_uid: root        # override per-console

# Pattern-based definitions (matched when no explicit definition applies)
# {name} is a capture group — extracted from the socket filename
console_patterns:
  # QEMU dials in at VM boot — hub is live before any user attaches
  - socket_glob: /run/vnctlsd/console-{name}.sock
    type: qemu_unix
    console_name: "{name}"
    validation:
      trusted_uid: libvirt-qemu
    rw: ["{name}"]             # username matching VM name gets read-write
    ro: [mentors]              # mentors group gets read-only

  # Exec-on-demand: daemon spawns virsh when a user attaches
  - socket_glob: /run/vnctlsd/exec-{name}.sock
    type: exec
    console_name: "{name}"
    cmd: "virsh -c qemu:///system console {name} --force"
    run_as: _vnctlsd
    rw: ["{name}"]
    ro: [mentors]
```

#### ACL resolution order

1. Console definition `rw`/`ro` lists are checked first (most specific)
2. User map group role is the fallback if no console ACL is defined
3. `*` in an ACL list matches all authenticated users
4. Template variables from glob captures are substituted before matching
   (`rw: ["{name}"]` with `name=vm-lab01` → matches username `vm-lab01`)

#### Socket validation

When a socket appears in the watch directory the watcher checks:

1. `lstat` — no symlink following
2. Must be `S_ISSOCK` — not a regular file or pipe
3. Owner uid must match `trusted_uid` (resolved to numeric uid)
4. Must not be world-writable (`S_IWOTH`)
5. Filename must match a console definition or pattern — unknown sockets
   are logged and ignored

The worker independently re-validates every socket event received from the
watcher. A compromised watcher cannot cause the worker to connect to an
untrusted socket.

---

## QEMU console socket setup

Configure each VM to connect to a per-VM unix socket at boot:

```xml
<!-- In the libvirt domain XML, add inside <devices>: -->
<serial type='unix'>
  <source mode='connect' path='/run/vnctlsd/console-vm-lab01.sock'/>
  <protocol type='raw'/>
  <target type='isa-serial' port='0'/>
</serial>
```

Or via `virsh edit vm-lab01`. The daemon listens on the socket; QEMU
connects when the VM starts. The hub is live from the first BIOS byte.

---

## TLS frontend setup

The daemon speaks plaintext over a unix socket. TLS is terminated upstream.

### ghostunnel

```bash
ghostunnel server \
  --listen 0.0.0.0:8443 \
  --target unix:/run/vnctlsd/vnctlsd.sock \
  --cert server.crt \
  --key server.key \
  --cacert ca.crt \
  --disable-authentication   # or use --allow-cn for mutual TLS
```

### stunnel

```ini
[vnctlsd]
accept  = 8443
connect = /run/vnctlsd/vnctlsd.sock
cert    = /etc/vnctlsd/server.crt
key     = /etc/vnctlsd/server.key
CAfile  = /etc/vnctlsd/ca.crt
```

---

## Running

```bash
# Start (must be root)
python3 vnctlsd.py \
  --config /etc/vnctlsd/vnctlsd.ini \
  --users  /etc/vnctlsd/users.yaml \
  --consoles /etc/vnctlsd/consoles.yaml

# Debug mode — verbose logging with PIDs
python3 vnctlsd.py --config ... --debug

# Disable security restrictions for debugging
python3 vnctlsd.py --config ... --no-privsep   # disable landlock + seccomp
python3 vnctlsd.py --config ... --no-seccomp   # disable seccomp only
python3 vnctlsd.py --config ... --no-landlock  # disable landlock only
```

### Signals

Send signals to the **monitor PID** (written to `pidfile`):

```bash
MONITOR=$(cat /run/vnctlsd/vnctlsd.pid)

kill -HUP  $MONITOR   # reload users.yaml + consoles.yaml (non-destructive)
kill -USR1 $MONITOR   # log active sessions and hub state
kill -USR2 $MONITOR   # reload + disconnect sessions with revoked access
```

### systemd unit

```ini
[Unit]
Description=vnctlsd virsh console dispatcher
After=network.target libvirtd.service

[Service]
Type=forking
PIDFile=/run/vnctlsd/vnctlsd.pid
ExecStart=/usr/bin/python3 /usr/local/sbin/vnctlsd.py \
    --config /etc/vnctlsd/vnctlsd.ini \
    --users  /etc/vnctlsd/users.yaml \
    --consoles /etc/vnctlsd/consoles.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RuntimeDirectory=vnctlsd
RuntimeDirectoryMode=0750

[Install]
WantedBy=multi-user.target
```

---

## Client usage

### vnctl (Go binary)

```bash
# Connect (server drives login prompt)
vnctl -server avocado:8443

# Skip TLS certificate verification (development only)
vnctl -server avocado:8443 -insecure

# With CA certificate for server verification
vnctl -server avocado:8443 -ca ca.crt

# With mutual TLS (client certificate)
vnctl -server avocado:8443 -ca ca.crt -cert client.crt -key client.key
```

### socat (Linux/macOS, no binary needed)

```bash
# Basic
socat $(tty),raw,echo=0 OPENSSL:avocado:8443,verify=0

# With CA verification
socat $(tty),raw,echo=0 OPENSSL:avocado:8443,cafile=ca.crt

# With mutual TLS
socat $(tty),raw,echo=0 \
  OPENSSL:avocado:8443,cafile=ca.crt,cert=client.crt,key=client.key
```

### Session example

```
vnctlsd - virsh console dispatcher
Type 'help' for available commands.

Username: student01
Password:

Login successful.

vnctlsd> list
  vm-lab01                       live          1 watcher(s)  [read_write]
  vm-lab02                       idle          0 watcher(s)  [read_write]

vnctlsd> console vm-lab01

[Attached to vm-lab01 (read-write). Escape: ~. to detach  ~~ for literal ~]

Ubuntu 24.04 LTS vm-lab01 ttyS0

vm-lab01 login: _

~.

[Detached from vm-lab01]

vnctlsd> status vm-lab01
running

vnctlsd> quit
Goodbye.
```

### Console escape sequences

While attached to a console:

| Sequence | Action                              |
|----------|-------------------------------------|
| `~.`     | Detach and return to `vnctlsd>` prompt |
| `~~`     | Send a literal `~` to the console   |

---

## Security

### Privilege separation

| Process   | User         | Capabilities                                      |
|-----------|--------------|---------------------------------------------------|
| monitor   | root         | PAM, fork+setuid for virsh, management commands   |
| worker    | `_vnctlsd`   | Unix socket accept, client I/O, no exec/fork      |
| watcher   | `_vnctlsd`   | inotify read, lstat — no network, no write        |

The monitor is the only process that ever runs as root. It has no network
socket access. The worker has network access but cannot fork, exec, or open
arbitrary files (enforced by seccomp and landlock).

### PAM in isolated subprocesses

Each login attempt forks a short-lived child that:
- Sets `PR_SET_NO_NEW_PRIVS`
- Limits itself to 0 further processes (`RLIMIT_NPROC=0`)
- Runs PAM, writes one byte result to a pipe, exits

The password never enters the long-lived monitor's heap. The OS frees the
child's memory immediately on exit.

### Constant-time login responses

All login failure paths (`bad_credentials`, `not_in_usermap`, `no_role`)
return the same message (`Login failed.`) after a minimum of 2 seconds.
This prevents:
- Username enumeration via error message differences
- Timing attacks that distinguish valid from invalid accounts

The real reason is logged server-side only.

### Socket validation (watcher + worker)

Before connecting to any QEMU unix socket:
1. `lstat` — symlinks are never followed
2. Must be `S_ISSOCK`
3. Owner uid must match configured `trusted_uid`
4. Must not be world-writable
5. Filename must match a defined console pattern

The worker re-validates independently after receiving events from the watcher.
A compromised watcher cannot force the worker to connect to an untrusted socket.

### Directory permissions

The watch directory must not be world-writable. If it is, the watcher logs
an error and refuses to watch — a world-writable directory allows any local
user to create a fake console socket and capture credentials typed into it.

### landlock (worker)

The worker's filesystem access is restricted to:
- `/run/vnctlsd/` — unix socket and QEMU console sockets
- `/dev/` — `/dev/null`, `/dev/urandom`, pty devices

The watcher's filesystem access is restricted to:
- Watch directory — read-only

### seccomp

Worker syscall whitelist covers only socket I/O, threading primitives,
and memory management. Notable absences: `fork`, `execve`, `setuid`,
`openat` (blocked by both seccomp and landlock), `inotify_*`.

Watcher syscall whitelist covers only `inotify_*`, `lstat`, `openat` (for
directory scan), and IPC. No network syscalls.

---

## Design decisions

**Why three processes instead of two?**

The watcher needs `inotify_*` and filesystem access to the watch directory.
The worker needs socket accept and network I/O. Combining them would mean
the network-facing process also has inotify and filesystem access — a larger
attack surface. Separating them gives each a minimal, auditable syscall set.

**Why server-driven terminal instead of a line protocol?**

A line protocol requires the client to understand the protocol — token flow,
command dispatch, management menu. That logic must be correct on every
platform including Windows. By moving all logic to the server, the client
becomes a dumb pipe (70 lines of Go) and the server becomes the single
point of correctness. Any TLS raw-socket tool works as a client.

**Why unix sockets instead of TCP for QEMU?**

Unix sockets allow identity validation via `lstat` ownership checks. TCP
connections carry no inherent identity — any process on the host (or network)
could connect. Unix sockets with strict directory permissions restrict
connection to processes running as the configured `trusted_uid`.

**Why glob patterns instead of per-VM config?**

A lab with 30 students and 30 VMs should not require 30 identical config
blocks. A single pattern `/run/vnctlsd/console-{name}.sock` with
`rw: ["{name}"]` covers all of them: the student whose username matches the
VM name gets read-write access, and the mentors group gets read-only.

**Why PAM in a subprocess?**

Python has no `explicit_bzero` equivalent. Passwords stored in Python
strings remain in heap memory until the garbage collector runs — which may
be never for a long-lived daemon. A subprocess whose only job is PAM
authentication has its entire memory freed by the OS on exit, regardless of
GC. This is the same approach used by OpenSSH's privilege separation.

---

## File layout

```
/etc/vnctlsd/
  vnctlsd.ini       daemon configuration
  users.yaml        user → group → role mapping
  consoles.yaml     console definitions and patterns
  server.crt        TLS certificate (for ghostunnel/stunnel)
  server.key        TLS private key
  ca.crt            CA certificate

/run/vnctlsd/       runtime directory (root:_vnctlsd, mode 0750)
  vnctlsd.sock      client-facing unix socket (ghostunnel connects here)
  vnctlsd.pid       monitor PID
  console-*.sock    QEMU serial console sockets (created by QEMU)

/usr/local/sbin/
  vnctlsd.py        daemon

/usr/local/bin/
  vnctl             client binary
```

---

## Limitations

- Linux only (landlock, seccomp, inotify, SCM_RIGHTS, TIOCSCTTY)
- x86_64 only for inotify syscall numbers (constants hardcoded; ARM64 has
  different numbers — trivial to add)
- No VNC/SPICE console support (serial consoles only)
- No multi-host support (single daemon instance)
- No session logging / console output capture (planned)
- LDAP/AD backend for user map not yet implemented (ACLResolver abstraction
  is in place; FileACLResolver is the only current implementation)

---

## License

ISC License — the same license used by OpenBSD.

Copyright (c) 2026 jbelka

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
