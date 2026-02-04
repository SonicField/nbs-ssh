"""nbs-ssh: AI-inspectable SSH client library."""

__version__ = "0.1.0"

from nbs_ssh.connection import ExecResult, SSHConnection, SSHConnectionError
from nbs_ssh.events import Event, EventCollector, EventEmitter, EventType

__all__ = [
    "SSHConnection",
    "SSHConnectionError",
    "ExecResult",
    "Event",
    "EventCollector",
    "EventEmitter",
    "EventType",
]
