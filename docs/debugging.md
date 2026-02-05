# Debugging Guide

This guide explains how to diagnose issues when using nbs-ssh.

## Enabling JSONL Event Logging

nbs-ssh uses structured JSONL (JSON Lines) event logging. Each line in the log is a complete JSON object representing a single event.

### Enable Logging via Code

```python
from nbs_ssh import SSHConnection, EventCollector

# Option 1: Log to file
async with SSHConnection(
    "example.com",
    username="alice",
    auth=auth,
    event_log_path="session.jsonl",  # Events written here
) as conn:
    await conn.exec("command")

# Option 2: In-memory collection
collector = EventCollector()
async with SSHConnection(
    "example.com",
    username="alice",
    auth=auth,
    event_collector=collector,
) as conn:
    await conn.exec("command")

# Access events
for event in collector.events:
    print(event.to_json())

# Option 3: Both (file + in-memory)
collector = EventCollector()
async with SSHConnection(
    "example.com",
    username="alice",
    auth=auth,
    event_collector=collector,
    event_log_path="session.jsonl",
) as conn:
    await conn.exec("command")
```

### Enable Logging via CLI

```bash
# Log events to stderr (redirect to file)
python -m nbs_ssh --events alice@example.com "ls" 2>session.jsonl

# View events in real-time
python -m nbs_ssh --events alice@example.com "ls"
```

---

## Reading Event Logs

### JSONL Format

Each line is a standalone JSON object:

```json
{"event_type": "CONNECT", "timestamp": 1234567890.123, "data": {"status": "initiating", "host": "example.com", "port": 22}}
{"event_type": "AUTH", "timestamp": 1234567890.234, "data": {"status": "success", "method": "private_key", "duration_ms": 45.2}}
{"event_type": "EXEC", "timestamp": 1234567890.345, "data": {"command": "ls", "exit_code": 0, "duration_ms": 12.3}}
{"event_type": "DISCONNECT", "timestamp": 1234567890.456, "data": {"reason": "normal"}}
```

### Quick Analysis with jq

```bash
# Pretty-print all events
cat session.jsonl | jq .

# Filter by event type
cat session.jsonl | jq 'select(.event_type == "ERROR")'

# Extract connection timing
cat session.jsonl | jq 'select(.event_type == "AUTH") | .data.duration_ms'

# Find failed operations
cat session.jsonl | jq 'select(.data.status == "failed")'
```

### Programmatic Analysis

```python
import json

def read_events(path):
    with open(path) as f:
        for line in f:
            yield json.loads(line)

# Find errors
for event in read_events("session.jsonl"):
    if event["event_type"] == "ERROR":
        print(f"Error: {event['data']['message']}")
    elif event.get("data", {}).get("status") == "failed":
        print(f"Failed: {event}")
```

---

## Event Types Reference

### CONNECT

Connection initiation and establishment:

```json
{
  "event_type": "CONNECT",
  "timestamp": 1234567890.123,
  "data": {
    "status": "initiating",  // or "connected"
    "host": "example.com",
    "port": 22,
    "username": "alice",
    "auth_method": "private_key"  // Only on success
  }
}
```

### AUTH

Authentication attempts and results:

```json
{
  "event_type": "AUTH",
  "timestamp": 1234567890.234,
  "data": {
    "status": "success",  // or "failed"
    "method": "password",  // "private_key", "ssh_agent"
    "username": "alice",
    "duration_ms": 45.2,
    "error_type": "PermissionDenied",  // On failure
    "error_message": "..."
  }
}
```

### EXEC

Command execution:

```json
{
  "event_type": "EXEC",
  "timestamp": 1234567890.345,
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

### ERROR

Any error during operation:

```json
{
  "event_type": "ERROR",
  "timestamp": 1234567890.456,
  "data": {
    "error_type": "ConnectionTimeout",
    "message": "Connection timed out after 30.0 seconds",
    "host": "example.com",
    "port": 22
  }
}
```

### STATE_CHANGE (Supervisor only)

Supervisor state transitions:

```json
{
  "event_type": "STATE_CHANGE",
  "timestamp": 1234567890.567,
  "data": {
    "from_state": "connecting",
    "to_state": "connected",
    "reconnection_count": 0
  }
}
```

### FORWARD

Port forwarding events:

```json
{
  "event_type": "FORWARD",
  "timestamp": 1234567890.678,
  "data": {
    "status": "established",  // "establishing", "closed", "failed"
    "forward_type": "local",
    "local_host": "localhost",
    "local_port": 3306,
    "remote_host": "db.server",
    "remote_port": 3306
  }
}
```

---

## Evidence Bundle Analysis

Evidence bundles are comprehensive diagnostic packages created when issues occur.

### Generating a Bundle

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
    # Create bundle with all diagnostic info
    bundle = conn.get_evidence_bundle()

    # Save with secrets redacted (safe for sharing)
    bundle.to_file("debug.json", redact=True)

    # Save unredacted (internal debugging only)
    bundle.to_file("debug_raw.json", redact=False)
```

### Bundle Contents

```python
from nbs_ssh import EvidenceBundle

bundle = EvidenceBundle.from_file("debug.json")

# Timing information
print(f"Connect time: {bundle.timing.connect_duration_ms}ms")
print(f"Auth time: {bundle.timing.auth_duration_ms}ms")
print(f"Total time: {bundle.timing.total_duration_ms}ms")

# Negotiated algorithms
print(f"KEX: {bundle.algorithms.kex}")
print(f"Cipher: {bundle.algorithms.cipher_cs}")
print(f"MAC: {bundle.algorithms.mac_cs}")

# Why did connection end?
print(f"Disconnect reason: {bundle.disconnect_reason}")

# Error details
print(f"Error context: {bundle.error_context}")

# All events in the session
for event in bundle.events:
    print(f"{event.event_type}: {event.data}")
```

### Bundle Fields

| Field | Description |
|-------|-------------|
| `events` | List of all JSONL events from the session |
| `transcript` | Automation transcript (if expect/respond was used) |
| `algorithms` | Negotiated SSH algorithms (KEX, ciphers, MACs, compression) |
| `timing` | Connection, auth, and session timing |
| `host_info` | Target host, port, username |
| `disconnect_reason` | Why the connection ended (normal, keepalive_timeout, etc.) |
| `error_context` | Additional error details |
| `version` | Bundle format version |
| `created_ms` | When the bundle was created |

---

## Common Issues and Solutions

### Connection Refused

**Symptom**: `ConnectionRefused` exception

**Causes**:
- SSH server not running on target host
- Wrong port number
- Firewall blocking the connection

**Diagnosis**:
```bash
# Check if port is open
nc -zv example.com 22

# Check from the same network as your application
ssh -v -p 22 alice@example.com
```

### Connection Timeout

**Symptom**: `ConnectionTimeout` exception

**Causes**:
- Host unreachable (network issue)
- Firewall dropping packets silently
- Very slow network

**Diagnosis**:
```bash
# Check network connectivity
ping example.com

# Check routing
traceroute example.com

# Try with longer timeout
async with SSHConnection(..., connect_timeout=60.0) as conn:
    ...
```

### Authentication Failed

**Symptom**: `AuthFailed` exception

**Causes**:
- Wrong password
- Wrong username
- Key not accepted by server
- Key not in authorized_keys

**Diagnosis**:
```python
# Check which method was tried
for event in collector.get_by_type("AUTH"):
    print(f"Method: {event.data['method']}, Status: {event.data['status']}")
```

```bash
# Verify key is correct
ssh-keygen -lf ~/.ssh/id_ed25519.pub

# Check server logs (on server)
tail -f /var/log/auth.log
```

### Key Load Error

**Symptom**: `KeyLoadError` exception

**Causes**:
- Key file not found
- Wrong permissions on key file
- Wrong passphrase for encrypted key
- Corrupted key file

**Diagnosis**:
```python
try:
    async with SSHConnection(...) as conn:
        ...
except KeyLoadError as e:
    print(f"Key path: {e.context.key_path}")
    print(f"Reason: {e.context.extra.get('reason')}")
```

```bash
# Check key file exists and permissions
ls -la ~/.ssh/id_ed25519
# Should be -rw------- (600)

# Verify key is valid
ssh-keygen -yf ~/.ssh/id_ed25519
```

### Host Key Mismatch

**Symptom**: `HostKeyMismatch` exception

**Causes**:
- Server was reinstalled/reconfigured
- Potential man-in-the-middle attack
- Connecting to wrong server

**Resolution**:
```bash
# If server legitimately changed, remove old key
ssh-keygen -R example.com

# Then reconnect to accept new key
ssh alice@example.com
```

**Warning**: Only do this if you're certain the server legitimately changed!

### No Mutual KEX

**Symptom**: `NoMutualKex` exception

**Causes**:
- Server and client have no compatible encryption algorithms
- Very old or very new server with different algorithm support

**Diagnosis**:
```bash
# Check what algorithms server supports
ssh -Q kex
nmap --script ssh2-enum-algos example.com
```

### SSH Agent Not Available

**Symptom**: `AgentError` exception

**Causes**:
- SSH agent not running
- SSH_AUTH_SOCK not set
- Agent socket not accessible

**Diagnosis**:
```python
from nbs_ssh import check_agent_available

if not check_agent_available():
    print("SSH agent not available")
```

```bash
# Check agent is running
echo $SSH_AUTH_SOCK
ssh-add -l
```

### Connection Drops During Operation

**Symptom**: Commands fail mid-execution

**Causes**:
- Network instability
- Server timeout
- Keepalive not configured

**Solution**: Use SSHSupervisor with keepalive:

```python
from nbs_ssh import SSHSupervisor, KeepaliveConfig, RetryPolicy

keepalive = KeepaliveConfig(
    interval_sec=15.0,
    max_count=3,
)

retry = RetryPolicy(
    max_retries=5,
    base_delay_sec=2.0,
)

async with SSHSupervisor(
    ...,
    keepalive=keepalive,
    retry_policy=retry,
) as supervisor:
    # Auto-reconnects on transient failures
    await supervisor.exec("command")
```

---

## How to Report Bugs

When reporting issues, include the following information:

### 1. Evidence Bundle

```python
try:
    async with SSHConnection(..., event_collector=collector) as conn:
        await conn.exec("command")
except Exception as e:
    bundle = conn.get_evidence_bundle()
    bundle.to_file("bug_report.json", redact=True)  # Safe for sharing
```

### 2. Environment Information

```bash
python --version
pip show nbs-ssh asyncssh
uname -a  # or systeminfo on Windows
```

### 3. Minimal Reproduction

Provide the smallest code that reproduces the issue:

```python
import asyncio
from nbs_ssh import SSHConnection, create_password_auth

async def main():
    auth = create_password_auth("password")
    async with SSHConnection(
        "example.com",
        username="alice",
        auth=auth,
    ) as conn:
        result = await conn.exec("whoami")
        print(result.stdout)

asyncio.run(main())
```

### 4. What You Expected vs What Happened

- Expected behaviour: "Command should execute and print username"
- Actual behaviour: "ConnectionTimeout after 30 seconds"

### 5. Relevant Logs

Include the JSONL event log (with secrets redacted) or relevant portions of it.

---

## Debug Checklist

When troubleshooting, work through this checklist:

- [ ] Can you SSH to the target manually? (`ssh user@host`)
- [ ] Is the port correct? (default is 22)
- [ ] Is the username correct?
- [ ] For key auth: Does the key file exist and have correct permissions (600)?
- [ ] For key auth: Is the public key in server's authorized_keys?
- [ ] For password auth: Is password authentication enabled on server?
- [ ] Are there firewall rules blocking the connection?
- [ ] Is known_hosts configured correctly (or disabled for testing)?
- [ ] Check the JSONL event log for specific error messages
- [ ] Generate an evidence bundle for detailed diagnostics
