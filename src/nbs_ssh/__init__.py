"""nbs-ssh: AI-inspectable SSH client library."""

__version__ = "0.1.0"

from nbs_ssh.auth import (
    AuthConfig,
    AuthMethod,
    create_agent_auth,
    create_key_auth,
    create_password_auth,
)
from nbs_ssh.connection import ExecResult, SSHConnection, StreamEvent, StreamExecResult
from nbs_ssh.errors import (
    AgentError,
    AuthenticationError,
    AuthFailed,
    ConnectionRefused,
    ConnectionTimeout,
    DisconnectReason,
    ErrorContext,
    HostKeyMismatch,
    HostUnreachable,
    KeyLoadError,
    NoMutualKex,
    SSHConnectionError,
    SSHError,
)
from nbs_ssh.events import Event, EventCollector, EventEmitter, EventType
from nbs_ssh.keepalive import KeepaliveConfig, ProgressWatchdog

__all__ = [
    # Connection
    "SSHConnection",
    "ExecResult",
    "StreamEvent",
    "StreamExecResult",
    # Auth
    "AuthConfig",
    "AuthMethod",
    "create_password_auth",
    "create_key_auth",
    "create_agent_auth",
    # Errors
    "SSHError",
    "SSHConnectionError",
    "ConnectionRefused",
    "ConnectionTimeout",
    "HostUnreachable",
    "AuthenticationError",
    "AuthFailed",
    "HostKeyMismatch",
    "NoMutualKex",
    "KeyLoadError",
    "AgentError",
    "ErrorContext",
    "DisconnectReason",
    # Keepalive
    "KeepaliveConfig",
    "ProgressWatchdog",
    # Events
    "Event",
    "EventCollector",
    "EventEmitter",
    "EventType",
]
