# Testing Guide

This document explains the testing philosophy and approach used in nbs-ssh.

## Philosophy: Falsifiability Over Coverage

The goal is not "100% coverage" but **falsifiable tests** - tests that could fail if the code is wrong, and whose failure would tell us something specific.

A test that cannot fail is not useful. A test that can fail but doesn't tell us what's wrong is barely useful. A good test:

1. Has a clear hypothesis ("this function returns X when given Y")
2. Could be falsified (there exists an input that would make it fail)
3. Fails informatively (the error message tells us what went wrong)

## No Docker Required

All tests run against `MockSSHServer` - a pure-Python SSH server built on AsyncSSH. This provides:

- **Fast startup**: No container spin-up time
- **Parallel execution**: Each test binds to port 0 (OS assigns a free port)
- **Deterministic behaviour**: No network variability
- **Works everywhere**: Linux, macOS, Windows - no Docker needed

## MockSSHServer

The mock server is a real SSH server, not a fake. It:

- Accepts SSH connections with configurable authentication
- Executes commands (mock responses or real shell execution)
- Supports PTY for interactive shell tests
- Emits JSONL events for debugging
- Can simulate failures (delays, disconnects, malformed responses)

### Basic Usage

```python
import pytest
from nbs_ssh import SSHConnection
from nbs_ssh.testing.mock_server import MockServerConfig, MockSSHServer

@pytest.mark.asyncio
async def test_exec_command():
    config = MockServerConfig(
        username="test",
        password="test",
    )

    async with MockSSHServer(config) as server:
        async with SSHConnection(
            host="localhost",
            port=server.port,
            username="test",
            password="test",
            known_hosts=None,
        ) as conn:
            result = await conn.exec("echo hello")
            assert result.exit_code == 0
            assert "hello" in result.stdout
```

### Configuring Mock Responses

```python
config = MockServerConfig(
    username="test",
    password="test",
    command_outputs={
        "echo hello": "hello\n",
        "whoami": "testuser\n",
    },
    command_exit_codes={
        "exit 42": 42,
    },
)
```

### Real Command Execution

For tests that need actual shell behaviour:

```python
config = MockServerConfig(
    username="test",
    password="test",
    execute_commands=True,  # Run real commands via subprocess
)
```

### Key-Based Authentication

```python
import asyncssh

# Generate a test keypair
private_key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
public_key = private_key.export_public_key().decode("utf-8")

config = MockServerConfig(
    username="test",
    password="test",
    authorized_keys=[public_key],
)

# Write private key to temp file for client
key_path = tmp_path / "test_key"
key_path.write_bytes(private_key.export_private_key())
key_path.chmod(0o600)

# Connect with key
async with SSHConnection(
    host="localhost",
    port=server.port,
    username="test",
    client_keys=[key_path],
    known_hosts=None,
) as conn:
    ...
```

## Test Categories

### Unit Tests

Test individual functions and classes in isolation.

```python
def test_auth_config_creation():
    from nbs_ssh import create_password_auth

    config = create_password_auth("secret")
    assert config.method == AuthMethod.PASSWORD
    assert config.password == "secret"
```

### Integration Tests

Test components working together against MockSSHServer.

```python
@pytest.mark.asyncio
async def test_streaming_exec(mock_ssh_server):
    async with SSHConnection(...) as conn:
        events = []
        async for event in await conn.stream_exec("echo hello"):
            events.append(event)

        assert any(e.stream == "stdout" for e in events)
        assert any(e.stream == "exit" for e in events)
```

### Security Tests (Falsification Pattern)

Security tests follow a specific pattern: **attempt the attack, verify it fails**.

```python
@pytest.mark.asyncio
async def test_weak_cipher_rejected():
    """
    Hypothesis: Client rejects connections using weak ciphers.
    Falsification: If connection succeeds with weak cipher, test fails.
    """
    config = MockServerConfig(
        username="test",
        password="test",
        encryption_algs=["3des-cbc"],  # Weak cipher
    )

    async with MockSSHServer(config) as server:
        with pytest.raises(NoMutualKexError):
            async with SSHConnection(
                host="localhost",
                port=server.port,
                username="test",
                password="test",
                known_hosts=None,
                # Client uses strong ciphers only
            ) as conn:
                pass  # Should not reach here
```

### Chaos Tests

Test behaviour under adverse conditions.

```python
@pytest.mark.asyncio
async def test_connection_drops_mid_command():
    """Test graceful handling when server disconnects during command."""
    ...
```

## Fixtures

Common fixtures are defined in `tests/conftest.py`:

```python
@pytest.fixture
async def mock_ssh_server():
    """Basic mock server with password auth."""
    config = MockServerConfig(username="test", password="test")
    async with MockSSHServer(config) as server:
        yield server

@pytest.fixture
async def streaming_ssh_server():
    """Mock server with real command execution for streaming tests."""
    config = MockServerConfig(
        username="test",
        password="test",
        execute_commands=True,
    )
    async with MockSSHServer(config) as server:
        yield server

@pytest.fixture
def event_collector():
    """Collector for capturing events during tests."""
    from nbs_ssh.events import EventCollector
    return EventCollector()
```

## Running Tests

```bash
# All tests
PYTHONPATH=src pytest tests/ -v

# Specific file
PYTHONPATH=src pytest tests/test_connection.py -v

# Specific test
PYTHONPATH=src pytest tests/test_connection.py::test_exec_command -v

# With coverage
PYTHONPATH=src pytest tests/ --cov=nbs_ssh --cov-report=html

# Stop on first failure
PYTHONPATH=src pytest tests/ -x

# Run in parallel (requires pytest-xdist)
PYTHONPATH=src pytest tests/ -n auto
```

## Writing New Tests

1. **State the hypothesis**: What are you testing?
2. **Define falsification**: What would prove the code wrong?
3. **Write the test**: Arrange, Act, Assert
4. **Verify it can fail**: Temporarily break the code and confirm the test catches it

Example template:

```python
@pytest.mark.asyncio
async def test_feature_x():
    """
    Hypothesis: [What you expect to be true]
    Falsification: [What would prove it wrong]
    """
    # Arrange
    config = MockServerConfig(...)
    async with MockSSHServer(config) as server:
        async with SSHConnection(...) as conn:

            # Act
            result = await conn.some_method()

            # Assert
            assert result.expected_property == expected_value
```

## Test Organisation

```
tests/
├── conftest.py           # Shared fixtures
├── test_auth.py          # Authentication tests
├── test_automation.py    # Expect/respond automation
├── test_cli.py           # CLI interface tests
├── test_connection.py    # Core connection tests
├── test_events.py        # Event system tests
├── test_forwarding.py    # Port forwarding tests
├── test_hello_ssh.py     # Basic connectivity tests
├── test_keepalive.py     # Keepalive and freeze detection
├── test_platform.py      # Platform-specific utilities
├── test_security.py      # Security tests (cipher rejection, etc.)
├── test_shell.py         # Interactive shell tests
├── test_streaming.py     # Streaming exec tests
└── test_supervisor.py    # Supervisor FSM tests
```

## Debugging Test Failures

1. **Run with `-v`** for verbose output
2. **Run with `-s`** to see print statements
3. **Run with `--tb=long`** for full tracebacks
4. **Check MockSSHServer events**: Enable `emit_events=True` in config
5. **Use `event_collector` fixture** to capture and inspect events

```python
@pytest.mark.asyncio
async def test_with_events(mock_ssh_server, event_collector):
    async with SSHConnection(
        ...,
        event_collector=event_collector,
    ) as conn:
        await conn.exec("echo hello")

    # Inspect events
    for event in event_collector.events:
        print(f"{event.event_type}: {event.data}")
```
