"""nbs-ssh: AI-inspectable SSH client library."""

__version__ = "0.1.0"

from nbs_ssh.auth import (
    AuthConfig,
    AuthMethod,
    check_gssapi_available,
    check_pkcs11_available,
    check_security_key_available,
    create_agent_auth,
    create_cert_auth,
    create_gssapi_auth,
    create_key_auth,
    create_keyboard_interactive_auth,
    create_password_auth,
    create_pkcs11_auth,
    create_security_key_auth,
    load_pkcs11_keys,
    load_security_key_file,
    load_security_key_keys,
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
from nbs_ssh.config import SSHConfig, SSHHostConfig, get_ssh_config
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
    get_known_hosts_read_paths,
    get_known_hosts_write_path,
    get_openssh_agent_available,
    get_pageant_available,
    get_ssh_dir,
    get_system_known_hosts_path,
    is_windows,
    validate_path,
)
from nbs_ssh.proxy import ProxyCommandError, ProxyCommandProcess
from nbs_ssh.secure_string import SecureString, SecureStringEradicated
from nbs_ssh.supervisor import ConnectionState, RetryPolicy, SSHSupervisor
from nbs_ssh.validation import (
    validate_hostname,
    validate_port,
    validate_username,
)

__all__ = [
    # Connection
    "SSHConnection",
    "ExecResult",
    "StreamEvent",
    "StreamExecResult",
    # Config
    "SSHConfig",
    "SSHHostConfig",
    "get_ssh_config",
    # Auth
    "AuthConfig",
    "AuthMethod",
    "create_password_auth",
    "create_key_auth",
    "create_cert_auth",
    "create_agent_auth",
    "create_gssapi_auth",
    "create_keyboard_interactive_auth",
    "create_pkcs11_auth",
    "create_security_key_auth",
    "check_gssapi_available",
    "check_pkcs11_available",
    "check_security_key_available",
    "load_pkcs11_keys",
    "load_security_key_file",
    "load_security_key_keys",
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
    # Proxy
    "ProxyCommandError",
    "ProxyCommandProcess",
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
    "get_known_hosts_read_paths",
    "get_known_hosts_write_path",
    "get_system_known_hosts_path",
    "get_default_key_paths",
    "expand_path",
    "validate_path",
    "discover_keys",
    "get_pageant_available",
    "get_openssh_agent_available",
    "get_agent_available",
    # SecureString
    "SecureString",
    "SecureStringEradicated",
    # Validation
    "validate_hostname",
    "validate_port",
    "validate_username",
]
