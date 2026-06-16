DEFAULT_CONFIG = """
[core]
socket_path      = /run/vnctlsd/vnctlsd.sock
pidfile          = /run/vnctlsd/vnctlsd.pid
max_threads      = 64
hub_grace_period = 30
idle_timeout     = 300
"""

HELP_TEXT = (
    b"Commands:\r\n"
    b"  list                  list accessible consoles and their state\r\n"
    b"  console <name>        attach to a console\r\n"
    b"  status  <name>        show VM power state\r\n"
    b"  start   <name>        start VM\r\n"
    b"  reset   <name>        graceful reboot\r\n"
    b"  force_reset <name>    hard reset\r\n"
    b"  poweroff <name>       hard poweroff\r\n"
    b"  help                  this text\r\n"
    b"  quit / exit           disconnect\r\n"
    b"\r\n"
    b"Console escape sequences (while attached):\r\n"
    b"  ~.    detach and return to prompt\r\n"
    b"  ~~    send a literal ~ to the console\r\n"
    b"\r\n"
)

PROMPT = b"vnctlsd> "
