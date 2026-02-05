# API Reference

Complete reference for all public classes and functions in nbs-ssh.

## Table of Contents

- [Core Classes](#core-classes)
- [Authentication](#authentication)
- [Results and Events](#results-and-events)
- [Port Forwarding](#port-forwarding)
- [Automation](#automation)
- [Evidence and Diagnostics](#evidence-and-diagnostics)
- [Errors](#errors)
- [Configuration](#configuration)
- [Utilities](#utilities)

---

## Core Classes

### SSHConnection

Low-level async SSH connection wrapper.

```python
class SSHConnection:
    def __init__(
        self,
        host: str,
        port: int = 22,
        username: str | None = None,
        password: str | None = None,
        client_keys: Sequence[Path | str] | None = None,
        known_hosts: Path | str | None = None,
        event_collector: EventCollector | None = None,
        event_log_path: Path | str | None = None,
        connect_timeout: float = 30.0,
        auth: AuthConfig | Sequence[AuthConfig] | None = None,
        keepalive: KeepaliveConfig | None = None,
    ) -> None
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `host` | `str` | required | SSH server hostname or IP |
| `port` | `int` | `22` | SSH server port |
| `username` | `str \| None` | `None` | Username for authentication |
| `password` | `str \| None` | `None` | Password (legacy, prefer `auth=`) |
| `client_keys` | `Sequence[Path \| str] \| None` | `None` | Key paths (legacy, prefer `auth=`) |
| `known_hosts` | `Path \| str \| None` | `None` | Path to known_hosts, None to disable |
| `event_collector` | `EventCollector \| None` | `None` | In-memory event collector |
| `event_log_path` | `Path \| str \| None` | `None` | JSONL file path for events |
| `connect_timeout` | `float` | `30.0` | Connection timeout in seconds |
| `auth` | `AuthConfig \| Sequence[AuthConfig] \| None` | `None` | Authentication configuration |
| `keepalive` | `KeepaliveConfig \| None` | `None` | Keepalive configuration |

**Methods:**

```python
async def __aenter__(self) -> SSHConnection
    """Establish SSH connection."""

async def __aexit__(self, *args) -> None
    """Close SSH connection."""

async def exec(self, command: str) -> ExecResult
    """Execute command and wait for completion."""

def stream_exec(self, command: str) -> StreamExecResult
    """Execute command with streaming output."""

def get_evidence_bundle(
    self,
    transcript: Transcript | None = None
) -> EvidenceBundle
    """Create diagnostic evidence bundle."""
```

**Example:**

```python
from nbs_ssh import SSHConnection, create_key_auth

auth = create_key_auth("~/.ssh/id_ed25519")

async with SSHConnection(
    "example.com",
    username="alice",
    auth=auth,
) as conn:
    result = await conn.exec("whoami")
    print(result.stdout)
```

---

### SSHSupervisor

High-level supervised connection with auto-reconnection.

```python
class SSHSupervisor:
    def __init__(
        self,
        host: str,
        port: int = 22,
        username: str | None = None,
        password: str | None = None,
        client_keys: Sequence[Path | str] | None = None,
        known_hosts: Path | str | None = None,
        event_collector: EventCollector | None = None,
        event_log_path: Path | str | None = None,
        connect_timeout: float = 30.0,
        auth: AuthConfig | Sequence[AuthConfig] | None = None,
        keepalive: KeepaliveConfig | None = None,
        retry_policy: RetryPolicy | None = None,
    ) -> None
```

**Additional Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `retry_policy` | `RetryPolicy \| None` | `None` | Retry configuration (default: 3 retries) |

**Properties:**

```python
@property
def state(self) -> ConnectionState
    """Current connection state."""

@property
def is_connected(self) -> bool
    """True if currently connected."""

@property
def reconnection_count(self) -> int
    """Number of reconnections since initial connect."""

@property
def forward_manager(self) -> ForwardManager
    """Access to port forward manager."""
```

**Methods:**

```python
async def __aenter__(self) -> SSHSupervisor
async def __aexit__(self, *args) -> None

async def exec(
    self,
    command: str,
    retry_on_disconnect: bool = True
) -> ExecResult
    """Execute with automatic retry on disconnect."""

async def wait_connected(self, timeout: float | None = None) -> bool
    """Wait for CONNECTED state. Returns False on timeout."""

async def close(self) -> None
    """Close connection and cleanup."""

async def forward_local(
    self,
    local_port: int,
    remote_host: str,
    remote_port: int,
    local_host: str = "localhost"
) -> ForwardHandle
    """Create local port forward."""

async def forward_remote(
    self,
    remote_port: int,
    local_host: str,
    local_port: int,
    remote_host: str = ""
) -> ForwardHandle
    """Create remote port forward."""

async def forward_dynamic(
    self,
    local_port: int,
    local_host: str = "localhost"
) -> ForwardHandle
    """Create SOCKS proxy."""

def get_evidence_bundle(
    self,
    transcript: Transcript | None = None
) -> EvidenceBundle
```

**Example:**

```python
from nbs_ssh import SSHSupervisor, create_key_auth, RetryPolicy

auth = create_key_auth("~/.ssh/id_ed25519")
policy = RetryPolicy(max_retries=5, base_delay_sec=2.0)

async with SSHSupervisor(
    "example.com",
    username="alice",
    auth=auth,
    retry_policy=policy,
) as supervisor:
    # Auto-reconnects on transient failures
    result = await supervisor.exec("uptime")
    print(result.stdout)
```

---

### ConnectionState

Supervisor connection states.

```python
class ConnectionState(str, Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    FAILED = "failed"
```

---

## Authentication

### AuthMethod

```python
class AuthMethod(str, Enum):
    PASSWORD = "password"
    PRIVATE_KEY = "private_key"
    SSH_AGENT = "ssh_agent"
```

### AuthConfig

```python
@dataclass
class AuthConfig:
    method: AuthMethod
    password: str | None = None
    key_path: Path | str | None = None
    passphrase: str | None = None
```

### Helper Functions

```python
def create_password_auth(password: str) -> AuthConfig
    """Create password authentication config."""

def create_key_auth(
    key_path: Path | str,
    passphrase: str | None = None
) -> AuthConfig
    """Create private key authentication config."""

def create_agent_auth() -> AuthConfig
    """Create SSH agent authentication config."""

def check_agent_available() -> bool
    """Check if SSH agent is available."""

async def get_agent_keys() -> list[asyncssh.SSHKey]
    """Get keys from SSH agent."""
```

**Example:**

```python
from nbs_ssh import (
    create_password_auth,
    create_key_auth,
    create_agent_auth,
    check_agent_available,
)

# Password
auth = create_password_auth("secret")

# Key with passphrase
auth = create_key_auth("~/.ssh/id_rsa", passphrase="key-secret")

# Agent (check availability first)
if check_agent_available():
    auth = create_agent_auth()

# Multiple methods (fallback chain)
auth_chain = [
    create_agent_auth(),
    create_key_auth("~/.ssh/id_ed25519"),
    create_password_auth("backup"),
]
```

---

## Results and Events

### ExecResult

```python
@dataclass
class ExecResult:
    stdout: str
    stderr: str
    exit_code: int
```

### StreamEvent

```python
@dataclass
class StreamEvent:
    timestamp: float      # Unix milliseconds
    stream: str           # "stdout", "stderr", or "exit"
    data: str = ""
    exit_code: int | None = None  # Only for stream="exit"
```

### StreamExecResult

Async iterator yielding `StreamEvent` objects.

**Example:**

```python
async for event in conn.stream_exec("tail -f /var/log/syslog"):
    if event.stream == "stdout":
        print(event.data, end="")
    elif event.stream == "exit":
        print(f"Exit: {event.exit_code}")
        break
```

### EventType

```python
class EventType(str, Enum):
    CONNECT = "CONNECT"
    AUTH = "AUTH"
    EXEC = "EXEC"
    DISCONNECT = "DISCONNECT"
    ERROR = "ERROR"
    KEEPALIVE_SENT = "KEEPALIVE_SENT"
    KEEPALIVE_RECEIVED = "KEEPALIVE_RECEIVED"
    KEEPALIVE_TIMEOUT = "KEEPALIVE_TIMEOUT"
    PROGRESS_WARNING = "PROGRESS_WARNING"
    STATE_CHANGE = "STATE_CHANGE"
    FORWARD = "FORWARD"
```

### Event

```python
@dataclass
class Event:
    event_type: str
    timestamp: float
    data: dict[str, Any]

    def to_json(self) -> str

    @classmethod
    def from_json(cls, json_str: str) -> Event
```

### EventCollector

```python
class EventCollector:
    def emit(self, event: Event) -> None

    @property
    def events(self) -> list[Event]

    def clear(self) -> None

    def get_by_type(self, event_type: str | EventType) -> list[Event]
```

**Example:**

```python
from nbs_ssh import EventCollector, EventType

collector = EventCollector()

async with SSHConnection(..., event_collector=collector) as conn:
    await conn.exec("whoami")

# All events
for event in collector.events:
    print(f"{event.event_type}: {event.data}")

# Filter by type
auth_events = collector.get_by_type(EventType.AUTH)
```

---

## Port Forwarding

### ForwardType

```python
class ForwardType(str, Enum):
    LOCAL = "local"
    REMOTE = "remote"
    DYNAMIC = "dynamic"
```

### ForwardIntent

```python
@dataclass(frozen=True)
class ForwardIntent:
    forward_type: ForwardType
    local_host: str = "localhost"
    local_port: int = 0
    remote_host: str | None = None
    remote_port: int | None = None
```

### ForwardHandle

```python
class ForwardHandle:
    @property
    def intent(self) -> ForwardIntent

    @property
    def local_port(self) -> int
        """Actual bound port."""

    @property
    def is_active(self) -> bool

    async def close(self) -> None
```

### ForwardManager

```python
class ForwardManager:
    @property
    def intents(self) -> list[ForwardIntent]

    @property
    def active_forwards(self) -> list[ForwardHandle]

    async def forward_local(
        self,
        local_port: int,
        remote_host: str,
        remote_port: int,
        local_host: str = "localhost"
    ) -> ForwardHandle

    async def forward_remote(
        self,
        remote_port: int,
        local_host: str,
        local_port: int,
        remote_host: str = ""
    ) -> ForwardHandle

    async def forward_dynamic(
        self,
        local_port: int,
        local_host: str = "localhost"
    ) -> ForwardHandle

    async def replay_all(self) -> list[ForwardHandle]

    async def close_all(self) -> None
```

**Example:**

```python
async with SSHSupervisor(...) as supervisor:
    # Local forward: localhost:3306 -> db.server:3306
    db = await supervisor.forward_local(3306, "db.server", 3306)

    # Remote forward: remote:8080 -> localhost:8080
    web = await supervisor.forward_remote(8080, "localhost", 8080)

    # SOCKS proxy on localhost:1080
    socks = await supervisor.forward_dynamic(1080)

    print(f"SOCKS on port {socks.local_port}")

    await db.close()
```

---

## Automation

### PatternType

```python
class PatternType(str, Enum):
    LITERAL = "literal"
    REGEX = "regex"
```

### ExpectPattern

```python
@dataclass(frozen=True)
class ExpectPattern:
    pattern: str
    pattern_type: PatternType = PatternType.LITERAL
    name: str | None = None

    def match(self, text: str) -> re.Match[str] | None

    @property
    def compiled(self) -> Pattern[str]
```

### ExpectResult

```python
@dataclass
class ExpectResult:
    matched: bool
    pattern: ExpectPattern
    match_text: str = ""
    groups: tuple[str, ...] = ()
    buffer: str = ""
    duration_ms: float = 0.0
    timed_out: bool = False
```

### RespondAction

```python
@dataclass(frozen=True)
class RespondAction:
    text: str
    add_newline: bool = True
```

### RespondDelay

```python
@dataclass(frozen=True)
class RespondDelay:
    seconds: float = 0.0
```

### ExpectRespond

```python
@dataclass(frozen=True)
class ExpectRespond:
    pattern: ExpectPattern
    response: RespondAction
    delay: RespondDelay = field(default_factory=RespondDelay)
    timeout: ExpectTimeout = field(default_factory=ExpectTimeout)
```

### AutomationEngine

```python
class AutomationEngine:
    def __init__(
        self,
        stream: AsyncIterator,
        stdin_write=None,
    )

    @property
    def transcript(self) -> Transcript

    @property
    def buffer(self) -> str

    async def expect(
        self,
        pattern: ExpectPattern | str,
        timeout: float = 30.0,
    ) -> ExpectResult

    async def send(
        self,
        text: str,
        add_newline: bool = True,
    ) -> None

    async def expect_respond(
        self,
        pattern: ExpectPattern | str,
        response: str,
        timeout: float = 30.0,
        delay: float = 0.0,
    ) -> ExpectResult

    async def run_sequence(
        self,
        sequence: list[ExpectRespond],
    ) -> list[ExpectResult]
```

### Transcript

```python
class Transcript:
    def add_expect(self, result: ExpectResult) -> TranscriptEntry
    def add_send(self, text: str, metadata: dict | None = None) -> TranscriptEntry
    def add_output(self, text: str, stream: str = "stdout") -> TranscriptEntry

    @property
    def entries(self) -> list[TranscriptEntry]

    @property
    def duration_ms(self) -> float

    def to_jsonl(self) -> str
    def to_dict(self) -> dict
    def to_file(self, path: Path | str) -> None

    def __len__(self) -> int
    def __iter__(self)
```

**Example:**

```python
from nbs_ssh import AutomationEngine, ExpectPattern, PatternType

stream = conn.stream_exec("mysql -u root -p")
engine = AutomationEngine(stream)

# Wait for prompt
result = await engine.expect("Enter password: ", timeout=10.0)

if result.matched:
    # Send response
    await engine.send("secret")

    # Wait for mysql prompt with regex
    prompt = ExpectPattern(r"mysql>", pattern_type=PatternType.REGEX)
    await engine.expect(prompt)

    # Execute query
    await engine.send("SELECT VERSION();")

# Get transcript
transcript = engine.transcript
transcript.to_file("session.jsonl")
```

---

## Evidence and Diagnostics

### EvidenceBundle

```python
@dataclass
class EvidenceBundle:
    events: list[Event]
    transcript: Transcript | None
    algorithms: AlgorithmInfo
    disconnect_reason: DisconnectReason
    timing: TimingInfo
    host_info: HostInfo | None
    error_context: dict[str, Any]
    version: str
    created_ms: float

    def to_dict(self, redact: bool = True) -> dict[str, Any]
    def to_jsonl(self, redact: bool = True) -> str
    def to_file(
        self,
        path: Path | str,
        format: str = "json",
        redact: bool = True
    ) -> None

    @classmethod
    def from_file(cls, path: Path | str) -> EvidenceBundle
```

### AlgorithmInfo

```python
@dataclass
class AlgorithmInfo:
    kex: str | None = None
    cipher_cs: str | None = None
    cipher_sc: str | None = None
    mac_cs: str | None = None
    mac_sc: str | None = None
    compression_cs: str | None = None
    compression_sc: str | None = None

    def to_dict(self) -> dict[str, Any]

    @classmethod
    def from_asyncssh_conn(cls, conn) -> AlgorithmInfo
```

### TimingInfo

```python
@dataclass
class TimingInfo:
    connect_start_ms: float | None = None
    connect_end_ms: float | None = None
    auth_start_ms: float | None = None
    auth_end_ms: float | None = None
    disconnect_ms: float | None = None
    bundle_created_ms: float

    @property
    def connect_duration_ms(self) -> float | None

    @property
    def auth_duration_ms(self) -> float | None

    @property
    def total_duration_ms(self) -> float | None

    def to_dict(self) -> dict[str, Any]
```

### HostInfo

```python
@dataclass
class HostInfo:
    host: str
    port: int
    username: str | None = None
    redacted: bool = False

    def to_dict(self, redact: bool = True) -> dict[str, Any]
```

### DisconnectReason

```python
class DisconnectReason(str, Enum):
    NORMAL = "normal"
    KEEPALIVE_TIMEOUT = "keepalive_timeout"
    PROGRESS_TIMEOUT = "progress_timeout"
    NETWORK_ERROR = "network_error"
    AUTH_FAILURE = "auth_failure"
```

**Example:**

```python
from nbs_ssh import EvidenceBundle

# Create bundle on error
try:
    async with SSHConnection(...) as conn:
        await conn.exec("command")
except Exception:
    bundle = conn.get_evidence_bundle()
    bundle.to_file("debug.json", redact=True)

# Load and analyse
bundle = EvidenceBundle.from_file("debug.json")
print(f"KEX: {bundle.algorithms.kex}")
print(f"Auth time: {bundle.timing.auth_duration_ms}ms")
print(f"Reason: {bundle.disconnect_reason}")
```

---

## Errors

### Exception Hierarchy

```
SSHError
├── SSHConnectionError
│   ├── ConnectionRefused
│   ├── ConnectionTimeout
│   └── HostUnreachable
└── AuthenticationError
    ├── AuthFailed
    ├── HostKeyMismatch
    ├── NoMutualKex
    ├── KeyLoadError
    └── AgentError
```

### SSHError

Base class for all SSH errors.

```python
class SSHError(Exception):
    def __init__(
        self,
        message: str,
        context: ErrorContext | None = None
    )

    @property
    def error_type(self) -> str

    def to_dict(self) -> dict[str, Any]
```

### ErrorContext

```python
@dataclass
class ErrorContext:
    host: str | None = None
    port: int | None = None
    username: str | None = None
    auth_method: str | None = None
    key_path: str | None = None
    original_error: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]
```

### Connection Errors

```python
class SSHConnectionError(SSHError):
    """Base for connection errors."""

class ConnectionRefused(SSHConnectionError):
    """Server refused connection."""

class ConnectionTimeout(SSHConnectionError):
    """Connection timed out."""

class HostUnreachable(SSHConnectionError):
    """Host unreachable."""
```

### Authentication Errors

```python
class AuthenticationError(SSHError):
    """Base for auth errors."""

class AuthFailed(AuthenticationError):
    """Credentials rejected."""

class HostKeyMismatch(AuthenticationError):
    """Host key verification failed."""

class NoMutualKex(AuthenticationError):
    """No compatible algorithms."""

class KeyLoadError(AuthenticationError):
    """Cannot load private key."""
    def __init__(
        self,
        message: str,
        key_path: str | None = None,
        reason: str | None = None,
        context: ErrorContext | None = None,
    )

class AgentError(AuthenticationError):
    """SSH agent error."""
    def __init__(
        self,
        message: str,
        reason: str | None = None,
        context: ErrorContext | None = None,
    )
```

**Example:**

```python
from nbs_ssh import (
    ConnectionRefused,
    ConnectionTimeout,
    AuthFailed,
    KeyLoadError,
    SSHError,
)

try:
    async with SSHConnection(...) as conn:
        await conn.exec("command")
except ConnectionRefused:
    print("Server refused connection")
except ConnectionTimeout:
    print("Connection timed out")
except AuthFailed:
    print("Authentication failed")
except KeyLoadError as e:
    print(f"Cannot load key: {e.context.key_path}")
except SSHError as e:
    print(f"{e.error_type}: {e}")
    print(f"Context: {e.context.to_dict()}")
```

---

## Configuration

### RetryPolicy

```python
@dataclass
class RetryPolicy:
    max_retries: int = 3
    base_delay_sec: float = 1.0
    max_delay_sec: float = 60.0
    exponential_base: float = 2.0
    jitter: bool = True

    def calculate_delay(self, attempt: int) -> float
```

### KeepaliveConfig

```python
@dataclass
class KeepaliveConfig:
    interval_sec: float = 30.0
    max_count: int = 3
    progress_timeout_sec: float | None = None

    @property
    def total_timeout_sec(self) -> float

    def to_asyncssh_options(self) -> dict[str, Any]
```

### ProgressWatchdog

```python
class ProgressWatchdog:
    def __init__(
        self,
        timeout_sec: float,
        event_collector: EventCollector | None = None,
        on_timeout: Callable[[], None] | None = None,
        warning_threshold: float = 0.75,
    )

    def start(self) -> None
    def stop(self) -> None
    def progress(self) -> None

    @property
    def is_running(self) -> bool

    @property
    def timed_out(self) -> bool
```

---

## Utilities

### Path Functions

```python
def is_windows() -> bool
    """Check if running on Windows."""

def get_ssh_dir() -> Path
    """Get SSH config directory (~/.ssh or %USERPROFILE%\.ssh)."""

def get_known_hosts_path() -> Path
    """Get default known_hosts path."""

def expand_path(path: str | Path) -> Path
    """Expand ~ and environment variables."""

def validate_path(path: Path) -> tuple[bool, str | None]
    """Validate path exists. Returns (valid, error_message)."""
```

### Key Discovery

```python
def discover_keys() -> list[Path]
    """Find all SSH keys in standard locations."""

def get_default_key_paths() -> list[Path]
    """Get default key paths (id_ed25519, id_rsa, etc.)."""

def get_agent_available() -> bool
    """Check if SSH agent is available."""
```

### Secret Redaction

```python
def redact_secrets(data: Any) -> Any
    """Redact secrets from data structure."""

def redact_string(text: str) -> str
    """Redact secrets from string."""
```

---

## Module Imports

All public classes and functions are available from the main module:

```python
from nbs_ssh import (
    # Core
    SSHConnection,
    SSHSupervisor,
    ConnectionState,

    # Auth
    AuthConfig,
    AuthMethod,
    create_password_auth,
    create_key_auth,
    create_agent_auth,
    check_agent_available,
    get_agent_keys,

    # Results
    ExecResult,
    StreamExecResult,
    StreamEvent,

    # Events
    Event,
    EventType,
    EventCollector,

    # Port Forwarding
    ForwardType,
    ForwardIntent,
    ForwardHandle,
    ForwardManager,

    # Automation
    AutomationEngine,
    ExpectPattern,
    PatternType,
    ExpectResult,
    ExpectRespond,
    RespondAction,
    RespondDelay,
    Transcript,
    TranscriptEntry,

    # Evidence
    EvidenceBundle,
    AlgorithmInfo,
    TimingInfo,
    HostInfo,
    DisconnectReason,

    # Errors
    SSHError,
    SSHConnectionError,
    ConnectionRefused,
    ConnectionTimeout,
    HostUnreachable,
    AuthenticationError,
    AuthFailed,
    HostKeyMismatch,
    NoMutualKex,
    KeyLoadError,
    AgentError,
    ErrorContext,

    # Configuration
    RetryPolicy,
    KeepaliveConfig,
    ProgressWatchdog,

    # Utilities
    is_windows,
    get_ssh_dir,
    get_known_hosts_path,
    expand_path,
    discover_keys,
    get_default_key_paths,
    redact_secrets,
)
```
