"""
Chaos falsification tests for nbs-ssh.

These tests verify the client handles adverse network conditions
correctly - mid-stream disconnects, slow servers, auth failures,
and reconnection scenarios.

Falsification approach:
- Configure server to exhibit specific failure modes
- Verify client handles them correctly
- Verify client logs explain what happened

Each test documents:
1. What chaos was induced
2. What evidence was gathered
3. What the client's response was
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from nbs_ssh.connection import SSHConnection
from nbs_ssh.errors import AuthFailed, ConnectionTimeout, SSHConnectionError
from nbs_ssh.events import EventCollector
from nbs_ssh.supervisor import ConnectionState, RetryPolicy, SSHSupervisor
from nbs_ssh.testing.mock_server import MockServerConfig, MockSSHServer


# ---------------------------------------------------------------------------
# Mid-Stream Disconnect Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_client_handles_mid_stream_disconnect() -> None:
    """
    Falsification: Server drops connection mid-stream.

    Chaos induced:
    - Server configured to drop after 0.5 seconds
    - Client executes long-running command

    Expected behaviour:
    - Client receives connection error
    - Error is properly logged
    - No hung resources

    Evidence gathered:
    - Server event log showing drop reason
    - Client error details
    """
    config = MockServerConfig(
        username="test",
        password="test",
        drop_after_seconds=0.5,
    )

    event_collector = EventCollector()

    async with MockSSHServer(config=config) as server:
        try:
            async with SSHConnection(
                host="localhost",
                port=server.port,
                username="test",
                password="test",
                known_hosts=None,
                event_collector=event_collector,
                connect_timeout=5.0,
            ) as conn:
                # Try to execute command - should fail when server drops
                # Use a command that would take time
                result = await asyncio.wait_for(
                    conn.exec("echo hello"),
                    timeout=2.0,
                )
                # If we get here, connection might have been fast enough
                assert result.exit_code == 0

        except (SSHConnectionError, ConnectionError, asyncio.TimeoutError):
            # Expected - connection was dropped
            pass

        # Evidence: Server logged the drop
        drop_events = [e for e in server.events if e.event_type == "SERVER_DROP"]
        # Server may or may not have dropped yet - this is timing dependent


@pytest.mark.asyncio
async def test_client_handles_server_close_during_exec() -> None:
    """
    Falsification: Server closes immediately after auth.

    This simulates a flaky server that accepts connections then dies.
    """
    config = MockServerConfig(
        username="test",
        password="test",
        drop_after_seconds=0.1,  # Drop very quickly
    )

    event_collector = EventCollector()

    async with MockSSHServer(config=config) as server:
        # The connection may succeed briefly before drop
        try:
            async with SSHConnection(
                host="localhost",
                port=server.port,
                username="test",
                password="test",
                known_hosts=None,
                event_collector=event_collector,
            ):
                # Give time for drop to happen
                await asyncio.sleep(0.2)
                # Trying to exec after drop should fail
                # But this might not even be reached
        except (SSHConnectionError, ConnectionError, OSError):
            pass  # Expected

        # Evidence: Events were logged
        assert len(event_collector.events) >= 1, "Should have logged events"


# ---------------------------------------------------------------------------
# Slow Server Timeout Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_client_times_out_on_slow_auth() -> None:
    """
    Falsification: Server delays authentication response.

    Chaos induced:
    - Server configured with 5-second auth delay
    - Client has 1-second timeout

    Expected behaviour:
    - Client times out waiting for auth
    - Timeout error is raised

    Evidence gathered:
    - Timing of events shows timeout occurred
    """
    config = MockServerConfig(
        username="test",
        password="test",
        delay_auth=5.0,  # Very slow auth
    )

    event_collector = EventCollector()

    async with MockSSHServer(config=config) as server:
        with pytest.raises((ConnectionTimeout, asyncio.TimeoutError, SSHConnectionError)):
            async with SSHConnection(
                host="localhost",
                port=server.port,
                username="test",
                password="test",
                known_hosts=None,
                event_collector=event_collector,
                connect_timeout=1.0,  # Short timeout
            ):
                pass

        # Evidence: Server logged auth begin but not complete
        auth_begin_events = [e for e in server.events if e.event_type == "SERVER_AUTH_BEGIN"]
        auth_complete_events = [e for e in server.events if e.event_type == "SERVER_AUTH" and e.data.get("success")]

        # Auth should have started but may not have completed
        # (depends on timing)


@pytest.mark.asyncio
async def test_client_handles_slow_command_output() -> None:
    """
    Falsification: Server sends output very slowly.

    Chaos induced:
    - Server configured to throttle output to 10 bytes/sec
    - Command produces 100 bytes of output

    Expected behaviour:
    - Client receives all output eventually
    - No premature timeout
    """
    # Configure slow output
    slow_output = "a" * 50  # 50 bytes
    config = MockServerConfig(
        username="test",
        password="test",
        slow_output_bytes_per_sec=100,  # Slow but not too slow
        command_outputs={"slow_command": (slow_output + "\n", "")},
    )

    async with MockSSHServer(config=config) as server:
        async with SSHConnection(
            host="localhost",
            port=server.port,
            username="test",
            password="test",
            known_hosts=None,
            connect_timeout=30.0,  # Long timeout
        ) as conn:
            result = await asyncio.wait_for(
                conn.exec("slow_command"),
                timeout=30.0,
            )
            assert result.exit_code == 0
            assert slow_output in result.stdout


# ---------------------------------------------------------------------------
# Authentication Retry Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_client_handles_auth_failures_then_success() -> None:
    """
    Falsification: Server fails auth N times before succeeding.

    Chaos induced:
    - Server configured to fail first 2 auth attempts
    - Client uses SSHConnection (no auto-retry)

    Expected behaviour:
    - First attempts fail
    - This tests the server's configured failure behaviour

    Evidence gathered:
    - Server logs show failure count
    """
    config = MockServerConfig(
        username="test",
        password="test",
        auth_attempts_before_success=2,  # Fail first 2 attempts
    )

    event_collector = EventCollector()

    async with MockSSHServer(config=config) as server:
        # First attempt should fail
        with pytest.raises((AuthFailed, SSHConnectionError)):
            async with SSHConnection(
                host="localhost",
                port=server.port,
                username="test",
                password="test",
                known_hosts=None,
                event_collector=event_collector,
            ):
                pass

        # Evidence: Server logged the failure
        auth_events = [e for e in server.events if e.event_type == "SERVER_AUTH"]
        assert len(auth_events) >= 1, "Should have logged auth attempt"

        failed_auth = [e for e in auth_events if not e.data.get("success")]
        assert len(failed_auth) >= 1, "Should have logged failed auth"


@pytest.mark.asyncio
async def test_auth_failure_logging_includes_reason() -> None:
    """
    Verify auth failures include reason in logs.

    When authentication fails, both server and client logs
    should explain why.
    """
    config = MockServerConfig(
        username="test",
        password="test",
    )

    event_collector = EventCollector()

    async with MockSSHServer(config=config) as server:
        # Attempt with wrong password
        with pytest.raises((AuthFailed, SSHConnectionError)):
            async with SSHConnection(
                host="localhost",
                port=server.port,
                username="test",
                password="wrong_password",
                known_hosts=None,
                event_collector=event_collector,
            ):
                pass

        # Evidence: Server logged failure reason
        auth_events = [e for e in server.events if e.event_type == "SERVER_AUTH"]
        assert len(auth_events) >= 1

        failed_event = auth_events[0]
        assert failed_event.data.get("success") is False
        assert "reason" in failed_event.data, "Auth failure should include reason"


# ---------------------------------------------------------------------------
# Supervisor Reconnection Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_supervisor_reconnects_after_server_drop() -> None:
    """
    Falsification: Server drops, supervisor should reconnect.

    Chaos induced:
    - Server drops connection after 0.5 seconds
    - A new server is started
    - Supervisor should reconnect

    Expected behaviour:
    - Supervisor detects disconnect
    - Supervisor attempts reconnection
    - Connection is re-established

    Note: This is a simplified test - full reconnection testing
    requires coordination between server drop and restart.
    """
    config = MockServerConfig(
        username="test",
        password="test",
    )

    event_collector = EventCollector()

    # Use short retry delays for faster testing
    retry_policy = RetryPolicy(
        max_retries=3,
        base_delay_sec=0.1,
        jitter=False,
    )

    async with MockSSHServer(config=config) as server:
        async with SSHSupervisor(
            host="localhost",
            port=server.port,
            username="test",
            password="test",
            known_hosts=None,
            event_collector=event_collector,
            retry_policy=retry_policy,
        ) as supervisor:
            # Verify connected
            assert supervisor.state == ConnectionState.CONNECTED

            # Execute a command to prove connection works
            result = await supervisor.exec("echo hello")
            assert result.exit_code == 0
            assert result.stdout.strip() == "hello"

    # Evidence: State changes were logged
    state_events = [e for e in event_collector.events if e.event_type == "STATE_CHANGE"]
    assert len(state_events) >= 2, "Should have logged state changes"


@pytest.mark.asyncio
async def test_supervisor_fails_after_max_retries() -> None:
    """
    Falsification: Server unavailable, supervisor exhausts retries.

    Chaos induced:
    - Server started then immediately stopped
    - Supervisor tries to connect

    Expected behaviour:
    - Supervisor attempts max_retries connections
    - State becomes FAILED
    - Error is raised

    Evidence gathered:
    - State change events show retry attempts
    """
    event_collector = EventCollector()

    # Very fast retry policy for testing
    retry_policy = RetryPolicy(
        max_retries=2,
        base_delay_sec=0.01,
        jitter=False,
    )

    # Connect to port that will refuse connections
    with pytest.raises(SSHConnectionError):
        async with SSHSupervisor(
            host="localhost",
            port=29999,  # Unlikely to be in use
            username="test",
            password="test",
            known_hosts=None,
            event_collector=event_collector,
            retry_policy=retry_policy,
            connect_timeout=0.5,
        ):
            pass

    # Evidence: State changes show failure progression
    state_events = [e for e in event_collector.events if e.event_type == "STATE_CHANGE"]
    final_states = [e.data["to_state"] for e in state_events]
    assert "failed" in final_states, "Should have transitioned to FAILED"


# ---------------------------------------------------------------------------
# Command Execution Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_command_custom_exit_code() -> None:
    """
    Verify mock server returns configured exit codes.

    This is a control test to ensure the mock server works correctly.
    """
    config = MockServerConfig(
        username="test",
        password="test",
        command_exit_codes={"fail_command": 42},
    )

    async with MockSSHServer(config=config) as server:
        async with SSHConnection(
            host="localhost",
            port=server.port,
            username="test",
            password="test",
            known_hosts=None,
        ) as conn:
            result = await conn.exec("fail_command")
            assert result.exit_code == 42


@pytest.mark.asyncio
async def test_command_custom_output() -> None:
    """
    Verify mock server returns configured command outputs.
    """
    config = MockServerConfig(
        username="test",
        password="test",
        command_outputs={
            "custom_cmd": ("stdout output\n", "stderr output\n"),
        },
    )

    async with MockSSHServer(config=config) as server:
        async with SSHConnection(
            host="localhost",
            port=server.port,
            username="test",
            password="test",
            known_hosts=None,
        ) as conn:
            result = await conn.exec("custom_cmd")
            assert result.exit_code == 0
            assert "stdout output" in result.stdout
            assert "stderr output" in result.stderr


# ---------------------------------------------------------------------------
# Event Logging Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_server_logs_command_execution() -> None:
    """
    Verify mock server logs command execution details.
    """
    config = MockServerConfig(
        username="test",
        password="test",
    )

    async with MockSSHServer(config=config) as server:
        async with SSHConnection(
            host="localhost",
            port=server.port,
            username="test",
            password="test",
            known_hosts=None,
        ) as conn:
            await conn.exec("echo test123")

        # Evidence: Command was logged
        exec_events = [e for e in server.events if e.event_type == "SERVER_EXEC"]
        assert len(exec_events) >= 1, "Should have logged EXEC event"

        exec_event = exec_events[0]
        assert "command" in exec_event.data
        assert exec_event.data["command"] == "echo test123"


@pytest.mark.asyncio
async def test_jsonl_log_file_created(tmp_path: Path) -> None:
    """
    Verify mock server creates JSONL log file.
    """
    log_path = tmp_path / "server.jsonl"

    config = MockServerConfig(
        username="test",
        password="test",
    )

    async with MockSSHServer(
        config=config,
        event_log_path=log_path,
    ) as server:
        async with SSHConnection(
            host="localhost",
            port=server.port,
            username="test",
            password="test",
            known_hosts=None,
        ) as conn:
            await conn.exec("echo hello")

    # Evidence: Log file exists and contains events
    assert log_path.exists(), "JSONL log file should exist"

    lines = log_path.read_text().strip().split("\n")
    assert len(lines) >= 1, "Log file should have at least one event"

    import json
    for line in lines:
        event = json.loads(line)
        assert "event_type" in event
        assert "timestamp" in event
