"""
Hello SSH integration test.

Tests basic SSH connection, command execution, and JSONL event logging.
This is the first integration test for nbs-ssh, validating:
- Docker SSH server connectivity
- Basic command execution (echo hello)
- Event sequence: CONNECT → AUTH → EXEC → DISCONNECT
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
    ssh_server: SSHServerInfo,
    event_collector,
    temp_jsonl_path: Path,
) -> None:
    """
    Connect to SSH server, run 'echo hello', verify output and events.

    Success criteria:
    1. Command output is 'hello'
    2. Events contain CONNECT → AUTH → EXEC → DISCONNECT sequence
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
        known_hosts=ssh_server.known_hosts_path,
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
async def test_connect_with_key(
    ssh_server: SSHServerInfo,
    event_collector,
) -> None:
    """
    Connect using SSH key authentication.

    Validates key-based auth works alongside password auth.
    """
    from nbs_ssh.connection import SSHConnection

    assert ssh_server is not None, "SSH server fixture should provide connection info"

    async with SSHConnection(
        host=ssh_server.host,
        port=ssh_server.port,
        username=ssh_server.username,
        client_keys=[ssh_server.key_path],
        known_hosts=ssh_server.known_hosts_path,
        event_collector=event_collector,
    ) as conn:
        result = await conn.exec("whoami")

        assert result.exit_code == 0, f"Command failed: {result.stderr}"
        assert result.stdout.strip() == ssh_server.username


@pytest.mark.asyncio
async def test_exec_failure_event(
    ssh_server: SSHServerInfo,
    event_collector,
) -> None:
    """
    Verify ERROR event is emitted when command fails.
    """
    from nbs_ssh.connection import SSHConnection

    assert ssh_server is not None

    async with SSHConnection(
        host=ssh_server.host,
        port=ssh_server.port,
        username=ssh_server.username,
        password=ssh_server.password,
        known_hosts=ssh_server.known_hosts_path,
        event_collector=event_collector,
    ) as conn:
        result = await conn.exec("exit 42")

        # Command should complete but with non-zero exit code
        assert result.exit_code == 42

    # Verify EXEC event captured the failure
    exec_events = [e for e in event_collector.events if e.event_type == "EXEC"]
    assert len(exec_events) == 1
    assert exec_events[0].data.get("exit_code") == 42


@pytest.mark.asyncio
async def test_event_context_timing(
    ssh_server: SSHServerInfo,
    event_collector,
) -> None:
    """
    Verify event timing is captured correctly.
    """
    from nbs_ssh.connection import SSHConnection

    assert ssh_server is not None

    async with SSHConnection(
        host=ssh_server.host,
        port=ssh_server.port,
        username=ssh_server.username,
        password=ssh_server.password,
        known_hosts=ssh_server.known_hosts_path,
        event_collector=event_collector,
    ) as conn:
        # Run a command that takes measurable time
        result = await conn.exec("sleep 0.1 && echo done")
        assert result.exit_code == 0

    # Find EXEC event and verify duration
    exec_events = [e for e in event_collector.events if e.event_type == "EXEC"]
    assert len(exec_events) == 1

    exec_event = exec_events[0]
    duration = exec_event.data.get("duration_ms")
    assert duration is not None, "EXEC event should have duration_ms"
    assert duration >= 100, f"Duration should be >= 100ms, got {duration}ms"


@pytest.mark.asyncio
async def test_connection_refused_error(event_collector) -> None:
    """
    Verify ERROR event when connection is refused.
    """
    from nbs_ssh.connection import SSHConnection, SSHConnectionError

    with pytest.raises(SSHConnectionError) as exc_info:
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
