# nbs-ssh User Guide

This guide covers all features of the nbs-ssh library in detail.

## Table of Contents

1. [SSHConnection](#sshconnection)
2. [Authentication](#authentication)
3. [SSHSupervisor](#sshsupervisor)
4. [Port Forwarding](#port-forwarding)
5. [Automation (Expect/Respond)](#automation-expectrespond)
6. [Evidence Bundles](#evidence-bundles)
7. [Event System](#event-system)
8. [Error Handling](#error-handling)
9. [Cross-Platform Support](#cross-platform-support)

---

## SSHConnection

`SSHConnection` is the low-level async wrapper for SSH operations. It handles connection establishment, authentication, and command execution.

### Constructor Options

```python
from nbs_ssh import SSHConnection

conn = SSHConnection(
    host="example.com",           # Required: SSH server hostname or IP
    port=22,                      # SSH port (default: 22)
    username="alice",             # Username for authentication
    auth=auth_config,             # AuthConfig or list of AuthConfigs
    known_hosts="~/.ssh/known_hosts",  # Path to known_hosts (None to disable)
    connect_timeout=30.0,         # Connection timeout in seconds
    keepalive=keepalive_config,   # Optional KeepaliveConfig
    event_collector=collector,    # Optional EventCollector for in-memory events
    event_log_path="session.jsonl",  # Optional JSONL file for event persistence
)
```

### exec() - Synchronous Command Execution

Wait for a command to complete and get all output at once:

```python
async with SSHConnection(...) as conn:
    result = await conn.exec("ls -la /var/log")

    print(result.stdout)      # Standard output
    print(result.stderr)      # Standard error
    print(result.exit_code)   # Exit code (0 = success)
```

### stream_exec() - Streaming Command Execution

Get output as it arrives, useful for long-running commands:

```python
async with SSHConnection(...) as conn:
    async for event in conn.stream_exec("tail -f /var/log/syslog"):
        if event.stream == "stdout":
            print(event.data, end="")
        elif event.stream == "stderr":
            print(f"[ERR] {event.data}", end="")
        elif event.stream == "exit":
            print(f"Exit: {event.exit_code}")
```

---

## Authentication

nbs-ssh supports multiple authentication methods with automatic fallback.

### AuthConfig

```python
from nbs_ssh import AuthConfig, AuthMethod

# Password authentication
auth = AuthConfig(method=AuthMethod.PASSWORD, password="secret")

# Private key authentication
auth = AuthConfig(
    method=AuthMethod.PRIVATE_KEY,
    key_path="~/.ssh/id_ed25519",
    passphrase="key-passphrase",  # Optional, for encrypted keys
)

# SSH agent authentication
auth = AuthConfig(method=AuthMethod.SSH_AGENT)
```

### Helper Functions

Convenience functions for common authentication patterns:

```python
from nbs_ssh import (
    create_password_auth,
    create_key_auth,
    create_agent_auth,
    check_agent_available,
)

# Password
auth = create_password_auth("my-password")

# Private key (with optional passphrase)
auth = create_key_auth("~/.ssh/id_rsa", passphrase="secret")

# SSH agent
if check_agent_available():
    auth = create_agent_auth()
```

### Multiple Authentication Methods (Fallback)

Provide a list of AuthConfigs to try in order:

```python
auth_configs = [
    create_agent_auth(),                    # Try agent first
    create_key_auth("~/.ssh/id_ed25519"),   # Then key
    create_password_auth("backup-password"), # Finally password
]

async with SSHConnection("host", username="alice", auth=auth_configs) as conn:
    # Library tries each method until one succeeds
    await conn.exec("whoami")
```

### Legacy Interface

The legacy parameters are still supported for backwards compatibility:

```python
# Password (legacy)
async with SSHConnection("host", username="alice", password="secret") as conn:
    ...

# Key list (legacy)
async with SSHConnection(
    "host",
    username="alice",
    client_keys=["~/.ssh/id_rsa", "~/.ssh/id_ed25519"]
) as conn:
    ...
```

---

## SSHSupervisor

`SSHSupervisor` wraps `SSHConnection` with automatic reconnection, state management, and forward replay.

### When to Use SSHSupervisor

- Long-running scripts that need connection resilience
- Applications with port forwards that must survive reconnection
- Any scenario where transient network issues shouldn't cause failures

### Constructor Options

```python
from nbs_ssh import SSHSupervisor, RetryPolicy

supervisor = SSHSupervisor(
    host="example.com",
    port=22,
    username="alice",
    auth=auth_config,
    known_hosts="~/.ssh/known_hosts",
    connect_timeout=30.0,
    keepalive=keepalive_config,
    event_collector=collector,
    event_log_path="session.jsonl",
    retry_policy=RetryPolicy(       # Reconnection behaviour
        max_retries=5,
        base_delay_sec=2.0,
        max_delay_sec=60.0,
        exponential_base=2.0,
        jitter=True,
    ),
)
```

### Connection States

```python
from nbs_ssh import ConnectionState

# Available states:
# - DISCONNECTED: Not connected
# - CONNECTING: Initial connection in progress
# - CONNECTED: Connected and operational
# - RECONNECTING: Lost connection, attempting to reconnect
# - FAILED: Permanent failure (auth failed or max retries exceeded)

print(supervisor.state)         # Current state
print(supervisor.is_connected)  # True if CONNECTED
print(supervisor.reconnection_count)  # Number of reconnections
```

### Waiting for Connection

```python
async with SSHSupervisor(...) as supervisor:
    # Wait up to 60 seconds for connection
    connected = await supervisor.wait_connected(timeout=60.0)

    if connected:
        result = await supervisor.exec("uptime")
    else:
        print("Could not establish connection")
```

### Retry Policy

Control how reconnection attempts are made:

```python
from nbs_ssh import RetryPolicy

# Aggressive retry (many attempts, short delays)
aggressive = RetryPolicy(
    max_retries=10,
    base_delay_sec=0.5,
    max_delay_sec=30.0,
)

# Conservative retry (fewer attempts, longer delays)
conservative = RetryPolicy(
    max_retries=3,
    base_delay_sec=5.0,
    max_delay_sec=120.0,
)

# No automatic retry
no_retry = RetryPolicy(max_retries=0)
```

The delay formula is: `min(base_delay * (exponential_base ^ attempt), max_delay)`

With jitter enabled, the delay is multiplied by a random factor between 1.0 and 1.25.

### Permanent vs Transient Errors

- **Transient** (auto-retry): `ConnectionRefused`, `ConnectionTimeout`, `HostUnreachable`
- **Permanent** (no retry): `AuthFailed`, `HostKeyMismatch`, `NoMutualKex`

---

## Port Forwarding

nbs-ssh supports all SSH port forwarding types with automatic replay on reconnection.

### Local Port Forward

Forward a local port to a remote destination via SSH:

```python
async with SSHSupervisor(...) as supervisor:
    # Traffic to localhost:3306 goes to database.internal:3306
    handle = await supervisor.forward_local(
        local_port=3306,
        remote_host="database.internal",
        remote_port=3306,
        local_host="localhost",  # Optional, default
    )

    print(f"Forward established on port {handle.local_port}")

    # Use the forward...

    await handle.close()
```

### Remote Port Forward

Expose a local service to the remote server:

```python
async with SSHSupervisor(...) as supervisor:
    # Remote server can access localhost:8080 via its own port 8080
    handle = await supervisor.forward_remote(
        remote_port=8080,
        local_host="localhost",
        local_port=8080,
        remote_host="",  # Bind to all interfaces on remote
    )
```

### Dynamic Port Forward (SOCKS Proxy)

Create a SOCKS proxy for tunnelling arbitrary traffic:

```python
async with SSHSupervisor(...) as supervisor:
    # SOCKS proxy on localhost:1080
    handle = await supervisor.forward_dynamic(
        local_port=1080,
        local_host="localhost",
    )

    # Configure applications to use SOCKS proxy at localhost:1080
```

### Auto-Replay on Reconnection

When using `SSHSupervisor`, all port forwards are automatically re-established after reconnection:

```python
async with SSHSupervisor(...) as supervisor:
    # Establish forwards
    db = await supervisor.forward_local(3306, "db.server", 3306)
    web = await supervisor.forward_local(8080, "web.server", 80)

    # If connection drops and reconnects, forwards are replayed

    # Check active forwards
    active = supervisor.forward_manager.active_forwards
    intents = supervisor.forward_manager.intents
```

### ForwardHandle Properties

```python
handle.intent      # ForwardIntent describing the forward
handle.local_port  # Actual bound port (may differ if 0 was requested)
handle.is_active   # True if forward is currently active
```

---

## Automation (Expect/Respond)

The automation engine enables interaction with interactive command-line programs.

### Basic Expect

Wait for specific output before continuing:

```python
from nbs_ssh import AutomationEngine, ExpectPattern

async with SSHConnection(...) as conn:
    stream = conn.stream_exec("mysql -u root -p")
    engine = AutomationEngine(stream)

    # Wait for password prompt
    result = await engine.expect("Enter password: ", timeout=10.0)

    if result.matched:
        print(f"Found prompt in {result.duration_ms}ms")
    elif result.timed_out:
        print(f"Timeout! Buffer: {result.buffer}")
```

### Send Responses

```python
# Send text followed by newline
await engine.send("my-password")

# Send without newline
await engine.send("partial", add_newline=False)
```

### Expect and Respond

Combine expect and send in one call:

```python
result = await engine.expect_respond(
    pattern="Enter password: ",
    response="secret-password",
    timeout=10.0,
    delay=0.5,  # Wait before sending response
)
```

### Pattern Types

```python
from nbs_ssh import ExpectPattern, PatternType

# Literal match (exact substring)
literal = ExpectPattern("Password: ", pattern_type=PatternType.LITERAL)

# Regex match
regex = ExpectPattern(r"Port (\d+)", pattern_type=PatternType.REGEX)

result = await engine.expect(regex)
if result.matched:
    port = result.groups[0]  # Captured group
```

### Sequences

Run multiple expect/respond pairs:

```python
from nbs_ssh import ExpectRespond, RespondAction, RespondDelay

sequence = [
    ExpectRespond(
        pattern=ExpectPattern("Username: "),
        response=RespondAction("alice"),
    ),
    ExpectRespond(
        pattern=ExpectPattern("Password: "),
        response=RespondAction("secret"),
        delay=RespondDelay(0.5),
    ),
    ExpectRespond(
        pattern=ExpectPattern(r".*\$", pattern_type=PatternType.REGEX),
        response=RespondAction(""),  # No response needed
    ),
]

results = await engine.run_sequence(sequence)

for result in results:
    print(f"Matched: {result.pattern.pattern}")
```

### Transcripts

The automation engine maintains a complete transcript of all interactions:

```python
transcript = engine.transcript

# Iterate entries
for entry in transcript.entries:
    print(f"{entry.interaction_type}: {entry.content[:50]}")

# Export to JSONL
transcript.to_file("interaction.jsonl")

# Get as dict
data = transcript.to_dict()
```

---

## Evidence Bundles

Evidence bundles are diagnostic packages containing everything needed to debug SSH issues.

### Capturing Evidence

```python
from nbs_ssh import SSHConnection, EventCollector

collector = EventCollector()

try:
    async with SSHConnection(
        "example.com",
        username="alice",
        auth=auth,
        event_collector=collector,
    ) as conn:
        await conn.exec("command")
except Exception as e:
    # Capture evidence on failure
    bundle = conn.get_evidence_bundle()
    bundle.to_file("debug.json")
```

### Bundle Contents

An evidence bundle includes:

- **events**: All JSONL events from the session
- **transcript**: Automation transcript (if provided)
- **algorithms**: Negotiated SSH algorithms (KEX, ciphers, MACs)
- **timing**: Connection and authentication timing
- **host_info**: Target host details
- **disconnect_reason**: Why the connection ended
- **error_context**: Additional error details

### Export Formats

```python
# JSON (single file, complete bundle)
bundle.to_file("session.json", format="json")

# JSONL (streaming format, one JSON object per line)
bundle.to_file("session.jsonl", format="jsonl")
```

### Secret Redaction

By default, bundles redact sensitive information:

```python
# Redacted (safe for sharing)
bundle.to_file("debug.json", redact=True)

# Unredacted (for internal debugging only)
bundle.to_file("debug_raw.json", redact=False)
```

Redacted items include:
- Passwords and passphrases
- Private key contents
- Long base64 strings
- IP addresses (partially)

### Loading Bundles

```python
from nbs_ssh import EvidenceBundle

bundle = EvidenceBundle.from_file("session.json")

print(f"Disconnect reason: {bundle.disconnect_reason}")
print(f"Connection took: {bundle.timing.connect_duration_ms}ms")
print(f"KEX algorithm: {bundle.algorithms.kex}")

for event in bundle.events:
    print(f"{event.event_type}: {event.data}")
```

---

## Event System

nbs-ssh uses structured JSONL events for AI-inspectable logging.

### Event Types

```python
from nbs_ssh import EventType

# Available event types:
EventType.CONNECT          # Connection initiated/established
EventType.AUTH             # Authentication attempt/result
EventType.EXEC             # Command execution
EventType.DISCONNECT       # Connection closed
EventType.ERROR            # Error occurred
EventType.KEEPALIVE_SENT   # Keepalive sent
EventType.KEEPALIVE_RECEIVED  # Keepalive response
EventType.KEEPALIVE_TIMEOUT   # Keepalive failed
EventType.PROGRESS_WARNING    # Application progress warning
EventType.STATE_CHANGE     # Supervisor state change
EventType.FORWARD          # Port forward event
```

### In-Memory Collection

```python
from nbs_ssh import EventCollector

collector = EventCollector()

async with SSHConnection(..., event_collector=collector) as conn:
    await conn.exec("whoami")

# Access collected events
for event in collector.events:
    print(f"{event.event_type}: {event.data}")

# Filter by type
auth_events = collector.get_by_type(EventType.AUTH)
```

### JSONL File Logging

```python
async with SSHConnection(
    ...,
    event_log_path="session.jsonl"
) as conn:
    await conn.exec("whoami")

# session.jsonl contains one JSON event per line
```

### Event Structure

Each event contains:

```json
{
  "event_type": "EXEC",
  "timestamp": 1234567890.123,
  "data": {
    "command": "ls -la",
    "streaming": false,
    "duration_ms": 123.4,
    "exit_code": 0,
    "stdout_len": 1024,
    "stderr_len": 0
  }
}
```

---

## Error Handling

nbs-ssh provides a structured exception hierarchy for programmatic error handling.

### Exception Hierarchy

```
SSHError (base)
├── SSHConnectionError
│   ├── ConnectionRefused    # Server refused connection
│   ├── ConnectionTimeout    # Connection timed out
│   └── HostUnreachable      # Network unreachable
└── AuthenticationError
    ├── AuthFailed           # Credentials rejected
    ├── HostKeyMismatch      # Host key verification failed
    ├── NoMutualKex          # No compatible algorithms
    ├── KeyLoadError         # Cannot load private key
    └── AgentError           # SSH agent error
```

### Handling Specific Errors

```python
from nbs_ssh import (
    ConnectionRefused,
    ConnectionTimeout,
    AuthFailed,
    HostKeyMismatch,
    KeyLoadError,
    SSHError,
)

try:
    async with SSHConnection(...) as conn:
        await conn.exec("command")
except ConnectionRefused:
    print("Server refused connection - check host/port")
except ConnectionTimeout:
    print("Connection timed out - check network")
except AuthFailed:
    print("Authentication failed - check credentials")
except HostKeyMismatch:
    print("Host key mismatch - potential security issue!")
except KeyLoadError as e:
    print(f"Cannot load key: {e}")
except SSHError as e:
    print(f"SSH error ({e.error_type}): {e}")
```

### Error Context

All errors carry contextual information:

```python
try:
    async with SSHConnection(...) as conn:
        ...
except SSHError as e:
    ctx = e.context
    print(f"Host: {ctx.host}:{ctx.port}")
    print(f"Username: {ctx.username}")
    print(f"Original error: {ctx.original_error}")
```

---

## Cross-Platform Support

nbs-ssh handles platform differences automatically.

### Key Discovery

```python
from nbs_ssh import discover_keys, get_default_key_paths

# Find all available SSH keys
keys = discover_keys()

# Get default key paths (~/.ssh/id_ed25519, etc.)
defaults = get_default_key_paths()
```

### SSH Agent Detection

```python
from nbs_ssh import check_agent_available, get_agent_keys

if check_agent_available():
    keys = await get_agent_keys()
    print(f"Agent has {len(keys)} keys")
```

### Path Utilities

```python
from nbs_ssh import (
    is_windows,
    get_ssh_dir,
    get_known_hosts_path,
    expand_path,
)

# ~/.ssh on Unix, %USERPROFILE%\.ssh on Windows
ssh_dir = get_ssh_dir()

# Expand ~ and environment variables
expanded = expand_path("~/.ssh/id_rsa")

# Check platform
if is_windows():
    # Handle Windows-specific paths
    ...
```

---

## Keep-Alive Configuration

Configure SSH-level keepalive for connection health monitoring:

```python
from nbs_ssh import SSHConnection, KeepaliveConfig

keepalive = KeepaliveConfig(
    interval_sec=30.0,    # Send keepalive every 30 seconds
    max_count=3,          # Disconnect after 3 missed responses
    progress_timeout_sec=60.0,  # App-level timeout (no output for 60s)
)

async with SSHConnection(..., keepalive=keepalive) as conn:
    # Connection will be monitored for health
    ...
```

### Progress Watchdog

For application-level freeze detection:

```python
from nbs_ssh import ProgressWatchdog

watchdog = ProgressWatchdog(
    timeout_sec=60.0,
    on_timeout=lambda: print("Application appears frozen!"),
)

watchdog.start()
try:
    async for event in conn.stream_exec("long_command"):
        watchdog.progress()  # Reset timer on each output
        process(event.data)
finally:
    watchdog.stop()
```
