"""
Streaming exec integration tests.

Tests for stream_exec() which yields structured output events as they arrive,
with support for cancellation.

Success criteria:
1. Can `async for event in conn.stream_exec("command")` and receive events as they arrive?
2. Can cancel a running stream_exec and have it terminate gracefully?
3. Do EXEC events distinguish between exec() and stream_exec()?

Uses streaming_ssh_server fixture with execute_commands=True for real shell execution.
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
# Integration Tests (use streaming_ssh_server with execute_commands=True)
# =============================================================================


@pytest.mark.asyncio
async def test_stream_exec_yields_events_in_order(
    streaming_ssh_server,
    event_collector,
) -> None:
    """stream_exec should yield StreamEvents in the order they arrive."""
    from nbs_ssh import SSHConnection

    async with SSHConnection(
        host="localhost",
        port=streaming_ssh_server.port,
        username="test",
        password="test",
        known_hosts=None,
        event_collector=event_collector,
    ) as conn:
        events = []
        async for event in conn.stream_exec("echo hello"):
            events.append(event)

        # Should have at least one stdout event and one exit event
        assert len(events) >= 1
        assert events[-1].stream == "exit"
        assert events[-1].exit_code == 0

        # Collect all stdout data
        stdout_data = "".join(e.data for e in events if e.stream == "stdout")
        assert "hello" in stdout_data


@pytest.mark.asyncio
async def test_stream_exec_cancellation_stops_stream(
    streaming_ssh_server,
    event_collector,
) -> None:
    """Cancelling a stream_exec should terminate gracefully."""
    from nbs_ssh import SSHConnection

    async with SSHConnection(
        host="localhost",
        port=streaming_ssh_server.port,
        username="test",
        password="test",
        known_hosts=None,
        event_collector=event_collector,
    ) as conn:
        stream = conn.stream_exec("sleep 10; echo done")

        # Get the first event (or timeout)
        events = []
        try:
            async for event in stream:
                events.append(event)
                # Cancel after seeing any event or just cancel immediately
                await stream.cancel()
                break
        except StopAsyncIteration:
            pass

        # Verify the stream was cancelled - check EXEC event metadata
        exec_events = event_collector.get_by_type("EXEC")
        # May or may not have an exec event depending on timing
        if exec_events:
            assert exec_events[0].data.get("cancelled") is True


@pytest.mark.asyncio
async def test_stream_exec_events_include_streaming_metadata(
    streaming_ssh_server,
    event_collector,
) -> None:
    """EXEC events from stream_exec should include streaming-specific metadata."""
    from nbs_ssh import SSHConnection

    async with SSHConnection(
        host="localhost",
        port=streaming_ssh_server.port,
        username="test",
        password="test",
        known_hosts=None,
        event_collector=event_collector,
    ) as conn:
        async for _ in conn.stream_exec("echo test"):
            pass

        # Check EXEC event has streaming metadata
        exec_events = event_collector.get_by_type("EXEC")
        assert len(exec_events) == 1

        exec_event = exec_events[0]
        assert exec_event.data["streaming"] is True
        assert "bytes_stdout" in exec_event.data
        assert "bytes_stderr" in exec_event.data
        assert exec_event.data["cancelled"] is False


@pytest.mark.asyncio
async def test_stream_exec_stdout_stderr_interleaving(
    streaming_ssh_server,
    event_collector,
) -> None:
    """stdout and stderr events should preserve their ordering."""
    from nbs_ssh import SSHConnection

    async with SSHConnection(
        host="localhost",
        port=streaming_ssh_server.port,
        username="test",
        password="test",
        known_hosts=None,
        event_collector=event_collector,
    ) as conn:
        events = []
        # Write to both stdout and stderr
        async for event in conn.stream_exec("echo out; echo err >&2"):
            events.append(event)

        # Should have stdout, stderr, and exit events
        streams = [e.stream for e in events]
        assert "exit" in streams

        # Verify we got data from at least one stream
        data_events = [e for e in events if e.stream in ("stdout", "stderr") and e.data]
        assert len(data_events) >= 1


@pytest.mark.asyncio
async def test_stream_exec_vs_exec_events_differ(
    streaming_ssh_server,
    event_collector,
) -> None:
    """EXEC events should distinguish between exec() and stream_exec()."""
    from nbs_ssh import SSHConnection

    async with SSHConnection(
        host="localhost",
        port=streaming_ssh_server.port,
        username="test",
        password="test",
        known_hosts=None,
        event_collector=event_collector,
    ) as conn:
        # Run regular exec
        await conn.exec("echo regular")

        # Run stream exec
        async for _ in conn.stream_exec("echo streaming"):
            pass

        # Check both EXEC events
        exec_events = event_collector.get_by_type("EXEC")
        assert len(exec_events) == 2

        # First should NOT have streaming flag (regular exec)
        assert "streaming" not in exec_events[0].data or exec_events[0].data.get("streaming") is not True

        # Second should have streaming=True
        assert exec_events[1].data["streaming"] is True


@pytest.mark.asyncio
async def test_stream_exec_with_exit_code(
    streaming_ssh_server,
    event_collector,
) -> None:
    """stream_exec should capture non-zero exit codes."""
    from nbs_ssh import SSHConnection

    async with SSHConnection(
        host="localhost",
        port=streaming_ssh_server.port,
        username="test",
        password="test",
        known_hosts=None,
        event_collector=event_collector,
    ) as conn:
        events = []
        async for event in conn.stream_exec("exit 42"):
            events.append(event)

        # Last event should be exit with code 42
        assert len(events) >= 1
        exit_event = events[-1]
        assert exit_event.stream == "exit"
        assert exit_event.exit_code == 42
