# vnctlsd

A privilege-separated KVM/QEMU serial console dispatcher written in Python,
inspired by [Conserver](https://www.conserver.com/) but designed for virtual
machines managed by libvirt.

The daemon drives the terminal server-side. The client is a dumb TLS pipe —
`socat` works on Linux and macOS, and a minimal Go binary (`vnctl`) is
provided for Windows compatibility.

> **Status:** `vnctlsd` is young and experimental. The privilege-separation
> model, configuration format, console backend handling, and operational
> defaults are still evolving. Treat it as a prototype for lab and development
> environments, review the security properties for your deployment, and expect
> incompatible changes before considering it production-ready.

---

## Features

- **Conserver-style server-driven terminal** — login prompt, command menu,
  and console attach/detach all happen on the server. The client sends raw
  keystrokes and displays raw output. No protocol knowledge required.
- **Console fan-out** — multiple users can attach to the same VM console
  simultaneously. Read-write users type; read-only users watch.
- **Privilege separation** — three processes with distinct trust levels:
  - **monitor** (root): PAM authentication, virsh spawning, management
    commands — never touches the network socket
  - **worker** (`_vnctlsd`): network socket, client sessions, console hubs
    — never forks, never execs, never touches arbitrary files
  - **watcher** (`_vnctlsd`): inotify on the socket directory, validates
    QEMU unix sockets as they appear — no network access, read-only fs
- **PAM authentication in isolated subprocesses** — each auth attempt forks
  a short-lived child. Password memory is freed by the OS on exit and never
  persists in the long-lived monitor process.
- **landlock + seccomp** — each process is restricted to the minimal
  filesystem paths and syscalls it actually needs, applied after privilege
  drop and after all library resolution.
- **Two console delivery modes**:
  - `exec` — daemon spawns a command (e.g. `virsh console <vm>`) on demand
    when a user attaches. A `defaults.console` backend applies as a fallback
    for any VM name that has no explicit definition or socket pattern.
  - `qemu_unix` — QEMU creates a unix socket at VM boot (libvirt
    `<source mode='bind'/>`); the daemon's watcher detects it and connects.
    The hub is live from the first byte, capturing early boot output before
    any user attaches. `socket_glob` patterns are only for this mode.
- **Glob-based console patterns** — one pattern covers many VMs:
  `/run/vnctlsd/console-{name}.sock` matches all QEMU sockets and extracts
  the VM name automatically. Template variables are substituted into ACL
  lists too: `rw: ["{name}"]` gives read-write access to the user whose
  username matches the VM name.
- **Config-driven management commands** — commands are defined in
  `consoles.yaml` with format parsing and output filters. The monitor
  validates every command request against its own config before executing;
  the worker never constructs or passes command strings.
- **Output processing pipeline** — each command declares its output format
  (`raw`, `json`, `lines`) and an optional filter that normalizes the output
  into one of four structured types (`string`, `list`, `table`, `status`)
  before rendering to the terminal. ANSI/VT escape sequences are stripped from
  all rendered values before they reach the client.
- **Two-axis ACL** — console definitions carry `rw`/`ro` lists (usernames,
  group names, or `*`). Users carry group memberships with roles. Console ACL
  takes priority; user map role is the fallback. Template variables from glob
  captures are substituted before matching.
- **Hot reload** — `SIGHUP` reloads user map and console config without
  restarting. `SIGUSR1` logs active sessions. `SIGUSR2` reloads and
  disconnects sessions whose access has been revoked.
- **Rate limiting** — per-username failed login counter with configurable
  lockout. Constant-time login responses prevent timing-based user enumeration.
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
    │                    │  │ output pipeline    │  │ seccomp: inotify   │
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

| Name    | Direction          | Purpose                                      |
|---------|--------------------|----------------------------------------------|
| `rpc`   | worker ↔ monitor   | AUTH_REQ, CMD_REQ, SPAWN_REQ + responses     |
| `push`  | monitor → worker   | SESSION_LIST_REQ, ENFORCE_REQ                |
| `ctl`   | monitor ↔ watcher  | RELOAD_WATCH, WATCHER_READY, WATCHER_ERROR   |
| `watch` | watcher → worker   | SOCKET_APPEARED, SOCKET_DISAPPEARED          |

### IPC wire format

```
[1 byte fd_count][4 bytes BE length][JSON payload]
```

File descriptors (pty master fds for virsh console sessions) travel via
`SCM_RIGHTS` in the same `sendmsg` call as the payload. Sequence numbers
in every request/response pair detect stale responses from dead threads and
poison the channel immediately rather than silently corrupting state.

### Management command flow

The worker never constructs or passes command strings to the monitor:

```
user types 'status vm-lab01'
  → worker sends CMD_REQ{action='status', console='vm-lab01'}
    → monitor validates 'status' against consoles.yaml [commands] section
    → monitor validates 'vm-lab01' against VM_NAME_RE
    → monitor builds command: "virsh -c qemu:///system domstate vm-lab01"
    → monitor executes, parses output (format: raw)
    → monitor applies filter → normalized structure
    → monitor renders to terminal string
    → monitor sends CMD_RESP{rendered='running\r\n'}
      → worker forwards rendered string to client
```

A compromised worker sending a crafted `CMD_REQ` with an unknown action
receives `✗ Unknown command` — the monitor only executes what is defined
in its own config.

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
before any user attaches. Early boot output (BIOS, GRUB, kernel) is captured
from the first byte.

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
# Python < 3.11 only (3.11+ has tomllib in stdlib):
pip install tomli
```

### Service accounts

```bash
# Worker and watcher account
useradd --system --no-create-home --home-dir /nonexistent \
        --shell /sbin/nologin --comment "vnctlsd worker" _vnctlsd

# Socket group (allows ghostunnel/stunnel to connect)
groupadd --system _vnctlsd
usermod -aG _vnctlsd _vnctlsd

# Allow worker to run virsh management commands
usermod -aG libvirt _vnctlsd
```

### Socket directory

```bash
install -d -o root -g _vnctlsd -m 0750 /run/vnctlsd
```

The watcher refuses to watch a world-writable directory — it would allow
any local user to create a fake console socket and intercept credentials.
Permissions must be at most `0770` with a trusted group. `0750` is recommended.

### Building the client

```bash
cd vnctl
go mod init vnctl
go get golang.org/x/term
go build -o vnctl vnctl.go

# Cross-compile for Windows
GOOS=windows GOARCH=amd64 go build -o vnctl.exe vnctl.go

# Cross-compile for macOS
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
hub_grace_period = 30       # seconds hub stays alive after last client leaves
login_timeout    = 30       # seconds to complete login before disconnect
idle_timeout     = 300      # seconds idle at prompt before disconnect

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
    groups: [mentors]
  admin:
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
  watch_dir: /run/vnctlsd/    # directory watched for QEMU unix sockets

# ---------------------------------------------------------------------------
# Default console backend
#
# Used when 'console <name>' is typed and no explicit definition or pattern
# matches the name.  {name} is substituted with the name the user typed.
# Remove this section to reject unknown names instead of forwarding to virsh.
# ---------------------------------------------------------------------------
defaults:
  console:
    type: exec
    cmd: "virsh -c qemu:///system console {name} --force"
    run_as: _vnctlsd

# Management commands — config-driven, validated by monitor before execution
# {name} is substituted with the console name (validated against VM_NAME_RE)
#
# format: raw | json | lines
#   raw   — output forwarded as a string
#   json  — output parsed as JSON (dict or list)
#   lines — output split on newlines, empty lines dropped
#
# filter.type: string | list | table | status
#   string — render as a single line
#     value: "{output}"        template over parsed output
#   list   — render as indented bullet list
#     items: "[].fieldname"    extract field from each JSON array element
#   table  — render as key-value table
#     rows:
#       - [Label, "{field}"]   each row: label + template over JSON object
#   status — render as ✓/✗ with message
#     ok_if: "regex"           regex matched against raw output → ok=true
#     message: "{output}"      message template
commands:
  status:
    cmd: "virsh -c qemu:///system domstate {name}"
    format: raw

  start:
    cmd: "virsh -c qemu:///system start {name}"
    format: raw
    filter:
      type: status
      ok_if: "^Domain .* started"
      message: "{output}"

  reset:
    cmd: "virsh -c qemu:///system reboot {name}"
    format: raw
    filter:
      type: status
      ok_if: "^Domain .* is being rebooted"
      message: "{output}"

  force_reset:
    cmd: "virsh -c qemu:///system reset {name}"
    format: raw

  poweroff:
    cmd: "virsh -c qemu:///system destroy {name}"
    format: raw
    filter:
      type: status
      ok_if: "^Domain .* destroyed"
      message: "{output}"

  snapshots:
    cmd: "virsh -c qemu:///system snapshot-list {name} --as-json"
    format: json
    filter:
      type: list
      items: "[].name"

  info:
    cmd: "/usr/local/bin/vm-info {name}"
    format: json
    filter:
      type: table
      rows:
        - [State,   "{state}"]
        - [Memory,  "{memory_mb} MB"]
        - [vCPUs,   "{vcpus}"]

# Explicit console definitions (highest priority — checked first)
# Use for VMs that need per-console ACL overrides or non-default settings.
consoles:
  vm-special:
    type: qemu_unix
    socket: /run/vnctlsd/console-vm-special.sock
    validation:
      trusted_uid: root        # override: this socket is owned by root
    rw: [admin]
    ro: [mentors]

# Pattern-based definitions — matched by socket filename, qemu_unix only.
# socket_glob is for socket-backed transports exclusively.  exec consoles
# that don't watch a socket use the defaults.console fallback above.
# {name} is extracted from the socket path via glob capture.
console_patterns:
  # QEMU creates the socket at VM boot (libvirt mode="bind"); daemon connects.
  # Hub is live before any user attaches, capturing BIOS/GRUB/kernel output.
  - socket_glob: /run/vnctlsd/console-{name}.sock
    type: qemu_unix
    console_name: "{name}"
    validation:
      trusted_uid: libvirt-qemu
    rw: ["{name}"]             # username matching VM name → read-write
    ro: [mentors]              # mentors group → read-only on all VMs
```

### ACL resolution order

1. Console definition `rw`/`ro` lists (most specific — checked first)
2. User map group role (fallback when console has no explicit ACL, including
   when the `defaults.console` backend is used)
3. `*` in an ACL list matches all authenticated users
4. Template variables from glob captures are substituted before matching
   (`rw: ["{name}"]` with `name=vm-lab01` → matches username `vm-lab01`)
5. No match at any level → access denied

### Socket validation

When a socket appears in the watch directory the watcher checks:

1. `lstat` — symlinks are never followed
2. Must be `S_ISSOCK`
3. Owner uid must match `trusted_uid` (global default or per-console override,
   with template variable substitution)
4. Must not be world-writable (`S_IWOTH`) — use filesystem ACLs for group access
5. Filename must match a console definition or pattern — unknown sockets are
   logged and silently ignored

The worker independently re-validates every socket event received from the
watcher before connecting. A compromised watcher cannot cause the worker to
connect to an untrusted socket.

---

## QEMU console socket setup

Configure each VM to bind a per-VM unix socket at boot. QEMU creates and
owns the socket; the daemon's watcher detects it and connects:

```xml
<!-- In the libvirt domain XML, add inside <devices>: -->
<serial type='unix'>
  <source mode='bind' path='/run/vnctlsd/console-vm-lab01.sock'/>
  <protocol type='raw'/>
  <target type='isa-serial' port='0'/>
</serial>
```

QEMU creates the socket file at VM boot and listens on it. The daemon
connects when the socket appears in the watch directory. The hub is live
from the first BIOS byte, capturing all output before any user attaches.

**Socket exclusivity**: once the daemon connects, it is the only consumer of
the QEMU socket. The daemon fans output out to all attached clients itself.
Filesystem permissions on `/run/vnctlsd/` (mode `0750`, group `_vnctlsd`)
must prevent other local processes from connecting to the socket directly,
since a second connect would race with the daemon and could steal console
output.

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
  --disable-authentication   # or --allow-cn for mutual TLS
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
  --config   /etc/vnctlsd/vnctlsd.ini \
  --users    /etc/vnctlsd/users.yaml \
  --consoles /etc/vnctlsd/consoles.yaml

# Debug — verbose logging with PIDs
python3 vnctlsd.py --config ... --debug

# Disable security restrictions for debugging
python3 vnctlsd.py --config ... --no-privsep    # disable landlock + seccomp
python3 vnctlsd.py --config ... --no-seccomp    # disable seccomp only
python3 vnctlsd.py --config ... --no-landlock   # disable landlock only
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
    --config   /etc/vnctlsd/vnctlsd.ini \
    --users    /etc/vnctlsd/users.yaml \
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

# Skip TLS verification (development only)
vnctl -server avocado:8443 -insecure

# With CA certificate
vnctl -server avocado:8443 -ca ca.crt

# With mutual TLS
vnctl -server avocado:8443 -ca ca.crt -cert client.crt -key client.key
```

### socat (Linux/macOS — no binary needed)

```bash
socat $(tty),raw,echo=0 OPENSSL:avocado:8443,verify=0
socat $(tty),raw,echo=0 OPENSSL:avocado:8443,cafile=ca.crt
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
  vm-lab01                       live          1 client(s)  [read_write]
  vm-lab02                       idle          0 client(s)  [read_write]

vnctlsd> status vm-lab01
running

vnctlsd> snapshots vm-lab01
  snap-baseline
  snap-2026-06-13

vnctlsd> info vm-lab01
  State   running
  Memory  2048 MB
  vCPUs   4

vnctlsd> start vm-lab02
✓ Domain vm-lab02 started

vnctlsd> console vm-lab01

[Attached to vm-lab01 (read-write). Escape: ~. to detach  ~~ for literal ~]

Ubuntu 24.04 LTS vm-lab01 ttyS0

vm-lab01 login: _

~.

[Detached from vm-lab01]

vnctlsd> quit
Goodbye.
```

### Console escape sequences

While attached to a console:

| Sequence | Action                                  |
|----------|-----------------------------------------|
| `~.`     | Detach and return to `vnctlsd>` prompt  |
| `~~`     | Send a literal `~` to the console       |

---

## Security

### Privilege separation

| Process   | User         | Capabilities                                       |
|-----------|--------------|----------------------------------------------------|
| monitor   | root         | PAM, fork+setuid for virsh, management commands    |
| worker    | `_vnctlsd`   | Unix socket accept, client I/O, no exec/fork       |
| watcher   | `_vnctlsd`   | inotify read, lstat only — no network, no write    |

The monitor is the only process that ever runs as root and it has no network
socket access. The worker has network access but cannot fork, exec, or open
arbitrary files (enforced by seccomp and landlock).

### PAM in isolated subprocesses

Each login attempt forks a short-lived child that:
- Sets `PR_SET_NO_NEW_PRIVS`
- Limits itself to 0 further processes (`RLIMIT_NPROC=0`)
- Runs PAM, writes one byte result to a pipe, exits immediately

The password never enters the long-lived monitor's heap. The OS frees the
child's memory on exit — no GC delay, no retention.

### Constant-time login responses

All login failure paths (`bad_credentials`, `not_in_usermap`, `no_role`)
return the same message (`Login failed.`) after a minimum of 2 seconds.
This prevents:
- Username enumeration via different error messages
- Timing attacks that distinguish valid from invalid accounts

The real reason is logged server-side only via `log.warning`.

### Command validation in the monitor

The worker sends `{action, console_name}` — never a pre-built command string.
The monitor:
1. Validates `action` against its own `consoles.yaml` commands section
2. Validates `console_name` against `VM_NAME_RE` (`[a-zA-Z0-9_\-.]{1,64}`)
3. Builds the command from its own template, not from the worker's message
4. Processes output through the format+filter pipeline before sending back

A compromised worker cannot cause the monitor to run arbitrary commands as root.

### Output processing pipeline

The monitor passes command output through a format+filter pipeline before
sending it to the worker. The worker sends only the pre-rendered string to
the client. The pipeline steps:

1. Executes the command
2. Parses output according to the declared `format` (`raw`/`json`/`lines`)
3. Applies the `filter` to produce a normalized structure
4. Strips ANSI/VT escape sequences from all string values
5. Renders the structure to a terminal string
6. Sends only the rendered string back to the worker

This sanitises terminal escape sequences from command output and
decouples the client display from command output formats.

### Socket validation (watcher + worker)

Before connecting to any QEMU unix socket:
1. `lstat` — symlinks are never followed
2. Must be `S_ISSOCK`
3. Owner uid must match configured `trusted_uid` (per-console or global)
4. Must not be world-writable — use filesystem ACLs for group access
5. Filename must match a defined console pattern

The worker re-validates independently after receiving events from the watcher.
A compromised watcher cannot force the worker to connect to an untrusted socket.

### Directory permissions

The watch directory must not be world-writable. If it is, the watcher logs
an error and **refuses to watch** — a world-writable directory allows any
local user to create a fake console socket and capture credentials typed
into it by legitimate users.

### landlock

Worker filesystem access restricted to:
- `/run/vnctlsd/` — unix socket and QEMU console sockets (read-write)
- `/dev/` — `/dev/null`, `/dev/urandom`, pty devices (read-write)

Watcher filesystem access restricted to:
- Watch directory — read-only

### seccomp

Worker whitelist covers socket I/O, threading primitives, memory management,
and `connect` (for QEMU unix socket connections). No `fork`, `execve`,
`setuid`, `openat` (blocked by both seccomp and landlock), `inotify_*`.

Watcher whitelist covers `inotify_*`, `lstat`, `openat` (for directory scan),
and IPC. No network syscalls whatsoever.

Restrictions are applied after privilege drop and after all library resolution
(`ctypes.util.find_library` needs `/tmp`; this must complete before landlock
is applied).

---

## Design decisions

**Why three processes instead of two?**

The watcher needs `inotify_*` and filesystem access to the watch directory.
The worker needs socket accept and network I/O. Combining them would mean
the network-facing process also has inotify and filesystem access — a larger
attack surface. Separating them gives each a minimal, auditable syscall set.

**Why server-driven terminal instead of a line protocol?**

A line protocol requires the client to understand commands, token flow, and
management menus — logic that must be correct on every platform including
Windows. By moving all logic to the server, the client becomes a dumb pipe
(74 lines of Go) and any TLS raw-socket tool works. The server is the single
point of correctness.

**Why unix sockets instead of TCP for QEMU console delivery?**

Unix sockets allow identity validation via `lstat` ownership checks. TCP
connections carry no inherent identity — any process on the host or network
could connect. Unix sockets with strict directory permissions restrict
connection to processes running as the configured `trusted_uid`.

**Why glob patterns instead of per-VM config?**

A lab with 30 students and 30 VMs should not require 30 identical config
blocks. A single pattern `/run/vnctlsd/console-{name}.sock` with
`rw: ["{name}"]` covers all of them: the student whose username matches the
VM name gets read-write access automatically.

**Why PAM in a subprocess?**

Python has no `explicit_bzero` equivalent. Passwords in Python strings remain
in heap memory until GC — which may be never for a long-lived daemon. A
subprocess whose only job is PAM has its entire memory freed by the OS on
exit, regardless of GC. This mirrors OpenSSH's privilege separation approach.

**Why does the monitor validate commands instead of trusting the worker?**

The worker is the network-facing process — the most likely target for
exploitation. If the worker is compromised, it should not be able to cause
the root monitor to execute arbitrary commands. By validating `{action,
console_name}` against its own config and building the command itself, the
monitor ensures it only ever runs what was explicitly configured, regardless
of what the worker sends.

**Why a format+filter output pipeline?**

Management commands return different output formats (plain strings, JSON,
multi-line tables). Parsing, normalizing, and ANSI/VT escape stripping in the
monitor keeps command output in a consistently rendered terminal form before
it reaches the client. Adding a new command with structured output requires
only config changes, no code changes.

---

## File layout

```
/etc/vnctlsd/
  vnctlsd.ini       daemon configuration
  users.yaml        user → group → role mapping
  consoles.yaml     console definitions, patterns, commands, socket validation
  server.crt        TLS certificate (for ghostunnel/stunnel)
  server.key        TLS private key
  ca.crt            CA certificate

/run/vnctlsd/       runtime directory (root:_vnctlsd, mode 0750)
  vnctlsd.sock      client-facing unix socket (ghostunnel connects here)
  vnctlsd.pid       monitor PID
  console-*.sock    QEMU serial console sockets (created by QEMU at VM boot)

/usr/local/sbin/
  vnctlsd.py        daemon (~2900 lines, Python 3.11+)

/usr/local/bin/
  vnctl             client binary (~74 lines, Go)
```

---

## Limitations

- Young/experimental daemon: configuration schema, console backend behavior,
  and operational hardening are still evolving.
- Linux only (landlock, seccomp, inotify, SCM_RIGHTS, TIOCSCTTY)
- x86_64 only for raw inotify syscall numbers (hardcoded; ARM64 has different
  numbers — trivial to add as a platform-detected constant)
- No VNC/SPICE console support (serial consoles only)
- No multi-host support (single daemon instance per host)
- No session logging / console output capture to file (planned)
- LDAP/AD backend for user map not yet implemented (the `ACLResolver`
  abstraction is in place; `FileACLResolver` is the only current backend)
- `qemu_unix` console patterns require QEMU to be configured to use unix
  socket serial output (libvirt domain XML change per VM)
- `list` shows explicitly-defined consoles and currently-active hubs only.
  Consoles reachable via `defaults.console` are not enumerated (the daemon
  has no way to discover what VM names exist without an external source).
