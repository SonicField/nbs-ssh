"""nbs-ssh: AI-inspectable SSH client library."""

__version__ = "0.1.0"

from nbs_ssh.auth import (
    AuthConfig,
    AuthMethod,
    create_agent_auth,
    create_key_auth,
    create_password_auth,
)
from nbs_ssh.connection import ExecResult, SSHConnection
from nbs_ssh.errors import (
    AgentError,
    AuthenticationError,
    AuthFailed,
    ConnectionRefused,
    ConnectionTimeout,
    ErrorContext,
    HostKeyMismatch,
    HostUnreachable,
    KeyLoadError,
    NoMutualKex,
    SSHConnectionError,
    SSHError,
)
from nbs_ssh.events import Event, EventCollector, EventEmitter, EventType

__all__ = [
    # Connection
    "SSHConnection",
    "ExecResult",
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
    # Events
    "Event",
    "EventCollector",
    "EventEmitter",
    "EventType",
]
