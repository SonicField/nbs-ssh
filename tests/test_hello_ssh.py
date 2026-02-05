"""
Hello SSH integration test.

Tests basic SSH connection, command execution, and JSONL event logging.
This is the first integration test for nbs-ssh, validating:
- MockSSHServer connectivity
- Basic command execution (echo hello)
- Event sequence: CONNECT -> AUTH -> EXEC -> DISCONNECT
- JSONL event serialisation with timestamps
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from conftest import SSHServerInfo


@pytest.mark.asyncio
async def test_connect_and_echo(
    ssh_server: "SSHServerInfo",
    event_collector,
    temp_jsonl_path: Path,
) -> None:
    """
    Connect to SSH server, run 'echo hello', verify output and events.

    Success criteria:
    1. Command output is 'hello'
    2. Events contain CONNECT -> AUTH -> EXEC -> DISCONNECT sequence
    3. All events have timestamps
    """
    from nbs_ssh.connection import SSHConnection

    # Precondition: SSH server is available
    assert ssh_server is not None, "SSH server fixture should provide connection info"

    async with SSHConnection(
        host=ssh_server.host,
        port=ssh_server.port,
        username=ssh_server.username,
        password=ssh_server.password,
        known_hosts=ssh_server.known_hosts_path,  # May be None for mock server
        event_collector=event_collector,
        event_log_path=temp_jsonl_path,
    ) as conn:
        # Execute command
        result = await conn.exec("echo hello")

        # Postcondition: Command succeeded with expected output
        assert result.exit_code == 0, f"Command failed with exit code {result.exit_code}"
        assert result.stdout.strip() == "hello", f"Expected 'hello', got '{result.stdout.strip()}'"
        assert result.stderr == "", f"Unexpected stderr: {result.stderr}"

    # Verify event sequence
    events = event_collector.events
    assert len(events) >= 4, f"Expected at least 4 events, got {len(events)}"

    event_types = [e.event_type for e in events]
    assert "CONNECT" in event_types, "Missing CONNECT event"
    assert "AUTH" in event_types, "Missing AUTH event"
    assert "EXEC" in event_types, "Missing EXEC event"
    assert "DISCONNECT" in event_types, "Missing DISCONNECT event"

    # Verify sequence order
    connect_idx = event_types.index("CONNECT")
    auth_idx = event_types.index("AUTH")
    exec_idx = event_types.index("EXEC")
    disconnect_idx = event_types.index("DISCONNECT")

    assert connect_idx < auth_idx, "CONNECT must precede AUTH"
    assert auth_idx < exec_idx, "AUTH must precede EXEC"
    assert exec_idx < disconnect_idx, "EXEC must precede DISCONNECT"

    # Verify all events have timestamps
    for event in events:
        assert event.timestamp is not None, f"Event {event.event_type} missing timestamp"
        assert event.timestamp > 0, f"Event {event.event_type} has invalid timestamp"

    # Verify JSONL output
    assert temp_jsonl_path.exists(), "JSONL log file should exist"
    lines = temp_jsonl_path.read_text().strip().split("\n")
    assert len(lines) >= 4, f"Expected at least 4 JSONL lines, got {len(lines)}"

    # Verify each line is valid JSON with required fields
    for line in lines:
        data = json.loads(line)
        assert "event_type" in data, f"JSONL line missing event_type: {line}"
        assert "timestamp" in data, f"JSONL line missing timestamp: {line}"


@pytest.mark.asyncio
async def test_connect_with_key(event_collector, tmp_path) -> None:
    """
    Connect using SSH key authentication.

    Validates key-based auth works with MockSSHServer.
    """
    import asyncssh

    from nbs_ssh.connection import SSHConnection
    from nbs_ssh.testing.mock_server import MockServerConfig, MockSSHServer

    # Generate a test keypair
    private_key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
    public_key = private_key.export_public_key().decode("utf-8")

    # Write private key to temp file for SSHConnection to load
    key_path = tmp_path / "test_key"
    key_path.write_bytes(private_key.export_private_key())
    key_path.chmod(0o600)  # SSH requires restricted permissions

    # Configure mock server with the public key
    config = MockServerConfig(
        username="test",
        password="test",  # Password still set but won't be used
        authorized_keys=[public_key],
    )

    async with MockSSHServer(config) as server:
        async with SSHConnection(
            host="localhost",
            port=server.port,
            username="test",
            client_keys=[key_path],
            known_hosts=None,
            event_collector=event_collector,
        ) as conn:
            result = await conn.exec("echo hello")

            # Postcondition: Command succeeded
            assert result.exit_code == 0, f"Command failed: {result.stderr}"
            assert result.stdout.strip() == "hello"

    # Verify AUTH event shows success
    auth_events = [e for e in event_collector.events if e.event_type == "AUTH"]
    assert len(auth_events) >= 1, "Should have AUTH event"
    # Check we have a successful auth
    assert any(e.data.get("status") == "success" for e in auth_events), "Auth should succeed"
    # Verify key auth method was used
    assert any(e.data.get("method") == "private_key" for e in auth_events), \
        "Should use private_key auth method"


@pytest.mark.asyncio
async def test_exec_failure_event(
    ssh_server: "SSHServerInfo",
    event_collector,
) -> None:
    """
    Verify EXEC event captures command exit code.

    Note: With MockSSHServer, we configure specific exit codes.
    """
    from nbs_ssh.connection import SSHConnection
    from nbs_ssh.testing.mock_server import MockServerConfig, MockSSHServer

    # Use a mock server with custom exit code
    config = MockServerConfig(
        username="test",
        password="test",
        command_exit_codes={"exit 42": 42},
    )

    async with MockSSHServer(config) as server:
        async with SSHConnection(
            host="localhost",
            port=server.port,
            username="test",
            password="test",
            known_hosts=None,
            event_collector=event_collector,
        ) as conn:
            result = await conn.exec("exit 42")

            # Command should complete with configured exit code
            assert result.exit_code == 42

        # Verify EXEC event captured the exit code
        exec_events = [e for e in event_collector.events if e.event_type == "EXEC"]
        assert len(exec_events) == 1
        assert exec_events[0].data.get("exit_code") == 42


@pytest.mark.asyncio
async def test_event_context_timing(
    ssh_server: "SSHServerInfo",
    event_collector,
) -> None:
    """
    Verify event timing is captured correctly.

    Note: MockSSHServer returns instantly, so we use slow_output to create delay.
    """
    from nbs_ssh.connection import SSHConnection
    from nbs_ssh.testing.mock_server import MockServerConfig, MockSSHServer

    # Use a mock server with slow output
    config = MockServerConfig(
        username="test",
        password="test",
        slow_output_bytes_per_sec=50,
        command_outputs={"slow_cmd": ("x" * 20 + "\n", "")},
    )

    async with MockSSHServer(config) as server:
        async with SSHConnection(
            host="localhost",
            port=server.port,
            username="test",
            password="test",
            known_hosts=None,
            event_collector=event_collector,
        ) as conn:
            # Run a command with slow output
            result = await conn.exec("slow_cmd")
            assert result.exit_code == 0

        # Find EXEC event and verify duration
        exec_events = [e for e in event_collector.events if e.event_type == "EXEC"]
        assert len(exec_events) == 1

        exec_event = exec_events[0]
        duration = exec_event.data.get("duration_ms")
        assert duration is not None, "EXEC event should have duration_ms"
        # Slow output takes ~0.4s for 20 bytes at 50 bytes/sec
        assert duration >= 100, f"Duration should be >= 100ms, got {duration}ms"


@pytest.mark.asyncio
async def test_connection_refused_error(event_collector) -> None:
    """
    Verify ERROR event when connection is refused.
    """
    from nbs_ssh.connection import SSHConnection
    from nbs_ssh.errors import SSHConnectionError

    with pytest.raises(SSHConnectionError):
        async with SSHConnection(
            host="localhost",
            port=29999,  # Unlikely to be in use
            username="nobody",
            password="nopass",
            known_hosts=None,  # Don't check
            event_collector=event_collector,
            connect_timeout=2.0,
        ):
            pass

    # Verify error event
    error_events = [e for e in event_collector.events if e.event_type == "ERROR"]
    assert len(error_events) >= 1, "Should have ERROR event for connection failure"


@pytest.mark.asyncio
async def test_whoami_command(ssh_server: "SSHServerInfo", event_collector) -> None:
    """
    Verify whoami command returns the expected username.
    """
    from nbs_ssh.connection import SSHConnection

    async with SSHConnection(
        host=ssh_server.host,
        port=ssh_server.port,
        username=ssh_server.username,
        password=ssh_server.password,
        known_hosts=ssh_server.known_hosts_path,
        event_collector=event_collector,
    ) as conn:
        result = await conn.exec("whoami")

        assert result.exit_code == 0
        assert result.stdout.strip() == ssh_server.username
