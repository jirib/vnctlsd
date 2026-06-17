# vnctlsd

**Virtual/serial coNsole ConTroL Server Daemon** - `vnctlsd`.

`vnctlsd` is a KVM/QEMU serial console dispatcher inspired by
[Conserver](https://www.conserver.com/). It gives users a server-driven
terminal prompt where they can list, inspect, start, and attach to VM serial
consoles.

The client is intentionally simple: it is a raw terminal pipe. The daemon owns
the prompt, commands, access checks, and console fan-out.

> **Status:** experimental. The privilege-separation model, configuration
> format, packaging, and operational defaults are still evolving. Treat this
> as a lab/development daemon until the security model has been reviewed for
> your deployment.

## What It Does

- Provides Conserver-style access to VM serial consoles.
- Lets multiple users watch the same console at once.
- Separates read-write and read-only console access.
- Supports server-side management commands such as status/start/reset.
- Supports QEMU Unix-socket serial consoles for early boot output.
- Supports on-demand exec-style console commands such as `virsh console`.
- Can record console output in asciicast-compatible format.
- Keeps authentication outside the daemon via PAM or SSH bridge helpers.
- Exposes a simple TLS-capable Go client, `vnctl`.

## How Users Connect

With the Go client:

```bash
vnctl -server console.example.com:8443
```

With a trusted CA:

```bash
vnctl -server console.example.com:8443 -ca ca.crt
```

With mutual TLS:

```bash
vnctl -server console.example.com:8443 \
  -ca ca.crt -cert client.crt -key client.key
```

Through SSH:

```bash
vnctl -mode ssh -server console.example.com
```

The server drives the login prompt and command menu after connection.

## Example Session

```text
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

vnctlsd> console vm-lab01

[Attached to vm-lab01 (read-write). Escape: ~. to detach  ~~ for literal ~]

Ubuntu 24.04 LTS vm-lab01 ttyS0

vm-lab01 login:

~.

[Detached from vm-lab01]

vnctlsd> quit
Goodbye.
```

While attached to a console:

| Sequence | Action |
|----------|--------|
| `~.` | Detach and return to the `vnctlsd>` prompt |
| `~~` | Send a literal `~` to the console |

## Configuration Files

Typical configuration lives under `/etc/vnctlsd/`:

| File | Purpose |
|------|---------|
| `vnctlsd.ini` | daemon paths, timeouts, logging, recording |
| `users.yaml` | user to group/role mapping |
| `consoles.yaml` | consoles, patterns, ACLs, management commands |

See the example files in `server/example/`:

- `server/example/vnctlsd.ini`
- `server/example/users.yaml`
- `server/example/consoles.yaml`

Packaged installs should use the systemd unit and files under
`packaging/rpm/`. Development and architecture details are kept out of this
README on purpose.
