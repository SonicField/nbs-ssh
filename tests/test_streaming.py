"""
Streaming exec integration tests.

Tests for stream_exec() which yields structured output events as they arrive,
with support for cancellation.

Success criteria:
1. Can `async for event in conn.stream_exec("command")` and receive events as they arrive?
2. Can cancel a running stream_exec and have it terminate gracefully?
3. Do EXEC events distinguish between exec() and stream_exec()?
"""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock

import pytest

if TYPE_CHECKING:
    from conftest import SSHServerInfo


# =============================================================================
# Unit Tests (no Docker required)
# =============================================================================


class TestStreamEvent:
    """Unit tests for StreamEvent dataclass."""

    def test_stream_event_stdout(self) -> None:
        """StreamEvent can be created for stdout."""
        from nbs_ssh.connection import StreamEvent

        event = StreamEvent(timestamp=1000.0, stream="stdout", data="hello")
        assert event.stream == "stdout"
        assert event.data == "hello"
        assert event.exit_code is None
        assert event.timestamp == 1000.0

    def test_stream_event_stderr(self) -> None:
        """StreamEvent can be created for stderr."""
        from nbs_ssh.connection import StreamEvent

        event = StreamEvent(timestamp=1000.0, stream="stderr", data="error msg")
        assert event.stream == "stderr"
        assert event.data == "error msg"

    def test_stream_event_exit(self) -> None:
        """StreamEvent can be created for exit with exit code."""
        from nbs_ssh.connection import StreamEvent

        event = StreamEvent(timestamp=1000.0, stream="exit", exit_code=42)
        assert event.stream == "exit"
        assert event.exit_code == 42
        assert event.data == ""

    def test_stream_event_invalid_stream_raises(self) -> None:
        """StreamEvent raises on invalid stream type."""
        from nbs_ssh.connection import StreamEvent

        with pytest.raises(AssertionError, match="stream must be"):
            StreamEvent(timestamp=1000.0, stream="invalid", data="test")

    def test_stream_event_invalid_timestamp_raises(self) -> None:
        """StreamEvent raises on non-positive timestamp."""
        from nbs_ssh.connection import StreamEvent

        with pytest.raises(AssertionError, match="timestamp must be positive"):
            StreamEvent(timestamp=-1.0, stream="stdout", data="test")


class TestStreamExecResultUnit:
    """Unit tests for StreamExecResult using mocks."""

    @pytest.mark.asyncio
    async def test_stream_exec_result_emits_exec_event_on_completion(self) -> None:
        """StreamExecResult emits EXEC event when iteration completes."""
        from nbs_ssh.connection import StreamExecResult
        from nbs_ssh.events import EventCollector, EventEmitter

        # Create mock process
        mock_process = MagicMock()
        mock_process.exit_status = 0
        mock_process.wait = AsyncMock(return_value=None)

        # Mock stdout - return empty to signal EOF immediately
        mock_stdout = AsyncMock()
        mock_stdout.read = AsyncMock(return_value="")
        mock_process.stdout = mock_stdout

        # Mock stderr
        mock_stderr = AsyncMock()
        mock_stderr.read = AsyncMock(return_value="")
        mock_process.stderr = mock_stderr

        # Create event collector
        collector = EventCollector()
        emitter = EventEmitter(collector=collector)

        stream = StreamExecResult(mock_process, emitter, "test command")

        # Iterate to completion
        events = []
        async for event in stream:
            events.append(event)

        # Should have emitted EXEC event
        exec_events = collector.get_by_type("EXEC")
        assert len(exec_events) == 1

        exec_event = exec_events[0]
        assert exec_event.data["streaming"] is True
        assert exec_event.data["command"] == "test command"
        assert exec_event.data["cancelled"] is False

    @pytest.mark.asyncio
    async def test_stream_exec_result_cancel_sets_flag(self) -> None:
        """Calling cancel() sets the cancelled flag."""
        from nbs_ssh.connection import StreamExecResult
        from nbs_ssh.events import EventCollector, EventEmitter

        # Create mock process
        mock_process = MagicMock()
        mock_process.exit_status = None
        mock_process.terminate = MagicMock()
        mock_process.kill = MagicMock()
        mock_process.wait = AsyncMock(return_value=None)

        collector = EventCollector()
        emitter = EventEmitter(collector=collector)

        stream = StreamExecResult(mock_process, emitter, "test")

        # Cancel the stream
        await stream.cancel()

        # Verify cancelled flag is set
        assert stream._cancelled is True
        mock_process.terminate.assert_called_once()


# =============================================================================
# Integration Tests (require Docker)
# =============================================================================


@pytest.mark.asyncio
async def test_stream_exec_yields_events_in_order(
    ssh_server: "SSHServerInfo",
    event_collector,
) -> None:
    """
    stream_exec should yield StreamEvents in the order they arrive.

    Validates:
    - Events are yielded as they arrive (not buffered)
    - Each event has timestamp, stream type, data
    - Final event is EOF
    """
    from nbs_ssh.connection import SSHConnection, StreamEvent

    assert ssh_server is not None, "SSH server fixture should provide connection info"

    async with SSHConnection(
        host=ssh_server.host,
        port=ssh_server.port,
        username=ssh_server.username,
        password=ssh_server.password,
        known_hosts=ssh_server.known_hosts_path,
        event_collector=event_collector,
    ) as conn:
        events: list[StreamEvent] = []

        async for event in conn.stream_exec("echo line1 && echo line2"):
            events.append(event)

    # Postconditions
    assert len(events) >= 1, "Should receive at least one event"

    # All events should have required fields
    for event in events:
        assert event.timestamp > 0, "Event must have positive timestamp"
        assert event.stream in ("stdout", "stderr", "exit"), f"Invalid stream: {event.stream}"

    # Check we got stdout events with content
    stdout_events = [e for e in events if e.stream == "stdout"]
    assert len(stdout_events) >= 1, "Should have stdout events"

    # Check combined stdout contains expected output
    stdout_data = "".join(e.data for e in stdout_events)
    assert "line1" in stdout_data, f"Expected 'line1' in stdout, got: {stdout_data}"
    assert "line2" in stdout_data, f"Expected 'line2' in stdout, got: {stdout_data}"

    # Should have an exit event with exit code
    exit_events = [e for e in events if e.stream == "exit"]
    assert len(exit_events) == 1, "Should have exactly one exit event"
    assert exit_events[0].exit_code == 0, "Exit code should be 0"


@pytest.mark.asyncio
async def test_stream_exec_cancellation_stops_stream(
    ssh_server: "SSHServerInfo",
    event_collector,
) -> None:
    """
    Cancelling a stream_exec should terminate gracefully.

    Validates:
    - cancel() method stops the stream
    - No zombie processes are left running
    - EXEC event includes cancelled=True
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
        # Start a long-running command
        stream = conn.stream_exec("sleep 10 && echo done")
        events_received = 0

        # Cancel after brief delay
        async def cancel_after_delay():
            await asyncio.sleep(0.5)
            await stream.cancel()

        cancel_task = asyncio.create_task(cancel_after_delay())

        try:
            async for _ in stream:
                events_received += 1
        except asyncio.CancelledError:
            pass  # Expected when cancelled

        await cancel_task

    # Verify EXEC event shows cancelled
    exec_events = [e for e in event_collector.events if e.event_type == "EXEC"]
    assert len(exec_events) == 1, "Should have one EXEC event"
    assert exec_events[0].data.get("cancelled") is True, "EXEC event should show cancelled=True"
    assert exec_events[0].data.get("streaming") is True, "EXEC event should show streaming=True"


@pytest.mark.asyncio
async def test_stream_exec_events_include_streaming_metadata(
    ssh_server: "SSHServerInfo",
    event_collector,
) -> None:
    """
    EXEC events from stream_exec should include streaming-specific metadata.

    Validates:
    - streaming: True
    - bytes_stdout: total bytes received on stdout
    - bytes_stderr: total bytes received on stderr
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
        async for _ in conn.stream_exec("echo hello && echo error >&2"):
            pass

    # Verify EXEC event metadata
    exec_events = [e for e in event_collector.events if e.event_type == "EXEC"]
    assert len(exec_events) == 1, "Should have one EXEC event"

    exec_event = exec_events[0]
    assert exec_event.data.get("streaming") is True, "EXEC should have streaming=True"
    assert "bytes_stdout" in exec_event.data, "EXEC should have bytes_stdout"
    assert "bytes_stderr" in exec_event.data, "EXEC should have bytes_stderr"
    assert exec_event.data["bytes_stdout"] > 0, "Should have stdout bytes"
    assert exec_event.data["bytes_stderr"] > 0, "Should have stderr bytes"


@pytest.mark.asyncio
async def test_stream_exec_stdout_stderr_interleaving(
    ssh_server: "SSHServerInfo",
    event_collector,
) -> None:
    """
    stdout and stderr events should preserve their interleaving order.

    Uses a command that alternates stdout/stderr output.
    """
    from nbs_ssh.connection import SSHConnection, StreamEvent

    assert ssh_server is not None

    async with SSHConnection(
        host=ssh_server.host,
        port=ssh_server.port,
        username=ssh_server.username,
        password=ssh_server.password,
        known_hosts=ssh_server.known_hosts_path,
        event_collector=event_collector,
    ) as conn:
        events: list[StreamEvent] = []

        # Command that outputs to both stdout and stderr
        cmd = "echo out1 && echo err1 >&2 && echo out2 && echo err2 >&2"
        async for event in conn.stream_exec(cmd):
            events.append(event)

    # Filter to just stdout/stderr events
    output_events = [e for e in events if e.stream in ("stdout", "stderr")]

    # Verify we got both stdout and stderr
    stdout_data = "".join(e.data for e in output_events if e.stream == "stdout")
    stderr_data = "".join(e.data for e in output_events if e.stream == "stderr")

    assert "out1" in stdout_data and "out2" in stdout_data, f"Missing stdout content: {stdout_data}"
    assert "err1" in stderr_data and "err2" in stderr_data, f"Missing stderr content: {stderr_data}"


@pytest.mark.asyncio
async def test_stream_exec_vs_exec_events_differ(
    ssh_server: "SSHServerInfo",
    event_collector,
) -> None:
    """
    EXEC events should distinguish between exec() and stream_exec().

    exec() should have streaming=False (or no streaming key).
    stream_exec() should have streaming=True.
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
        # Run a regular exec
        await conn.exec("echo regular")

        # Run a streaming exec
        async for _ in conn.stream_exec("echo streaming"):
            pass

    # Find the EXEC events
    exec_events = [e for e in event_collector.events if e.event_type == "EXEC"]
    assert len(exec_events) == 2, f"Expected 2 EXEC events, got {len(exec_events)}"

    # First event (regular exec) should not have streaming=True
    regular_event = exec_events[0]
    assert regular_event.data.get("streaming") is not True, "Regular exec should not have streaming=True"

    # Second event (stream_exec) should have streaming=True
    stream_event = exec_events[1]
    assert stream_event.data.get("streaming") is True, "stream_exec should have streaming=True"


@pytest.mark.asyncio
async def test_stream_exec_with_exit_code(
    ssh_server: "SSHServerInfo",
    event_collector,
) -> None:
    """
    stream_exec should capture non-zero exit codes.
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
        events = []
        async for event in conn.stream_exec("exit 42"):
            events.append(event)

    # Should have exit event with code 42
    exit_events = [e for e in events if e.stream == "exit"]
    assert len(exit_events) == 1, "Should have one exit event"
    assert exit_events[0].exit_code == 42, f"Exit code should be 42, got {exit_events[0].exit_code}"

    # EXEC event should also have exit code
    exec_events = [e for e in event_collector.events if e.event_type == "EXEC"]
    assert len(exec_events) == 1
    assert exec_events[0].data.get("exit_code") == 42
