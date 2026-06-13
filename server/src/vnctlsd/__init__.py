"""vnctlsd — privileged-separated virsh console dispatcher."""

import logging
import sys

__version__ = "0.1.0"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(process)d/%(processName)s/%(threadName)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logging.getLogger().handlers[0].setLevel(logging.NOTSET)
