"""nbs-ssh: AI-inspectable SSH client library."""

__version__ = "0.1.0"

from nbs_ssh.auth import (
    AuthConfig,
    AuthMethod,
    check_gssapi_available,
    create_agent_auth,
    create_gssapi_auth,
    create_key_auth,
    create_keyboard_interactive_auth,
    create_password_auth,
)
from nbs_ssh.automation import (
    AutomationEngine,
    ExpectPattern,
    ExpectRespond,
    ExpectResult,
    ExpectTimeout,
    ExpectTimeoutError,
    InteractionType,
    PatternType,
    RespondAction,
    RespondDelay,
    Transcript,
    TranscriptEntry,
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
from nbs_ssh.evidence import (
    AlgorithmInfo,
    EvidenceBundle,
    HostInfo,
    TimingInfo,
    redact_secrets,
    redact_string,
)
from nbs_ssh.forwarding import ForwardHandle, ForwardIntent, ForwardManager, ForwardType
from nbs_ssh.keepalive import KeepaliveConfig, ProgressWatchdog
from nbs_ssh.platform import (
    discover_keys,
    expand_path,
    get_agent_available,
    get_default_key_paths,
    get_known_hosts_path,
    get_openssh_agent_available,
    get_pageant_available,
    get_ssh_dir,
    is_windows,
    validate_path,
)
from nbs_ssh.supervisor import ConnectionState, RetryPolicy, SSHSupervisor

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
    "create_gssapi_auth",
    "create_keyboard_interactive_auth",
    "check_gssapi_available",
    # Automation
    "AutomationEngine",
    "ExpectPattern",
    "ExpectRespond",
    "ExpectResult",
    "ExpectTimeout",
    "ExpectTimeoutError",
    "InteractionType",
    "PatternType",
    "RespondAction",
    "RespondDelay",
    "Transcript",
    "TranscriptEntry",
    # Forwarding
    "ForwardType",
    "ForwardIntent",
    "ForwardHandle",
    "ForwardManager",
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
    # Supervisor
    "ConnectionState",
    "RetryPolicy",
    "SSHSupervisor",
    # Events
    "Event",
    "EventCollector",
    "EventEmitter",
    "EventType",
    # Evidence
    "EvidenceBundle",
    "AlgorithmInfo",
    "HostInfo",
    "TimingInfo",
    "redact_secrets",
    "redact_string",
    # Platform
    "is_windows",
    "get_ssh_dir",
    "get_known_hosts_path",
    "get_default_key_paths",
    "expand_path",
    "validate_path",
    "discover_keys",
    "get_pageant_available",
    "get_openssh_agent_available",
    "get_agent_available",
]
