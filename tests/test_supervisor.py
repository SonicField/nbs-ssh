"""
Supervisor FSM and reconnection tests.

Tests:
- ConnectionState transitions
- RetryPolicy exponential backoff
- SSHSupervisor reconnection logic
- STATE_CHANGE event emission
"""
from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from nbs_ssh.supervisor import ConnectionState, RetryPolicy, SSHSupervisor
from nbs_ssh.events import EventCollector, EventType

if TYPE_CHECKING:
    from conftest import SSHServerInfo


# ---------------------------------------------------------------------------
# RetryPolicy unit tests
# ---------------------------------------------------------------------------


class TestRetryPolicy:
    """Test RetryPolicy dataclass and backoff calculations."""

    def test_default_values(self) -> None:
        """Default policy has sensible defaults."""
        policy = RetryPolicy()

        assert policy.max_retries == 3
        assert policy.base_delay_sec == 1.0
        assert policy.max_delay_sec == 60.0
        assert policy.exponential_base == 2.0
        assert policy.jitter is True

    def test_validation_max_retries_negative(self) -> None:
        """max_retries must be non-negative."""
        with pytest.raises(AssertionError, match="max_retries must be non-negative"):
            RetryPolicy(max_retries=-1)

    def test_validation_base_delay_zero(self) -> None:
        """base_delay_sec must be positive."""
        with pytest.raises(AssertionError, match="base_delay_sec must be positive"):
            RetryPolicy(base_delay_sec=0)

    def test_validation_max_delay_less_than_base(self) -> None:
        """max_delay_sec must be >= base_delay_sec."""
        with pytest.raises(AssertionError, match="max_delay_sec must be >= base_delay_sec"):
            RetryPolicy(base_delay_sec=10.0, max_delay_sec=5.0)

    def test_validation_exponential_base_less_than_one(self) -> None:
        """exponential_base must be >= 1.0."""
        with pytest.raises(AssertionError, match="exponential_base must be >= 1.0"):
            RetryPolicy(exponential_base=0.5)

    def test_calculate_delay_no_jitter(self) -> None:
        """
        Exponential backoff without jitter.

        Formula: delay = base * (exponential_base ** attempt)
        """
        policy = RetryPolicy(
            base_delay_sec=1.0,
            exponential_base=2.0,
            max_delay_sec=60.0,
            jitter=False,
        )

        # Attempt 0: 1.0 * 2^0 = 1.0
        assert policy.calculate_delay(0) == 1.0

        # Attempt 1: 1.0 * 2^1 = 2.0
        assert policy.calculate_delay(1) == 2.0

        # Attempt 2: 1.0 * 2^2 = 4.0
        assert policy.calculate_delay(2) == 4.0

        # Attempt 3: 1.0 * 2^3 = 8.0
        assert policy.calculate_delay(3) == 8.0

    def test_calculate_delay_capped_at_max(self) -> None:
        """Delay is capped at max_delay_sec."""
        policy = RetryPolicy(
            base_delay_sec=1.0,
            exponential_base=2.0,
            max_delay_sec=10.0,
            jitter=False,
        )

        # Attempt 5: 1.0 * 2^5 = 32.0, capped to 10.0
        assert policy.calculate_delay(5) == 10.0

        # Attempt 10: would be 1024.0, capped to 10.0
        assert policy.calculate_delay(10) == 10.0

    def test_calculate_delay_with_jitter(self) -> None:
        """Jitter adds 0-25% variance to delay."""
        policy = RetryPolicy(
            base_delay_sec=1.0,
            exponential_base=2.0,
            max_delay_sec=60.0,
            jitter=True,
        )

        # Run multiple times to test variance
        delays = [policy.calculate_delay(0) for _ in range(100)]

        # Base delay is 1.0, with jitter should be 1.0-1.25
        assert all(1.0 <= d <= 1.25 for d in delays), \
            f"Delays should be in [1.0, 1.25], got min={min(delays)}, max={max(delays)}"

        # Should have some variance
        assert len(set(delays)) > 1, "Jitter should produce varying delays"

    def test_calculate_delay_custom_base(self) -> None:
        """Custom base delay works correctly."""
        policy = RetryPolicy(
            base_delay_sec=0.5,
            exponential_base=2.0,
            max_delay_sec=60.0,
            jitter=False,
        )

        # Attempt 0: 0.5 * 2^0 = 0.5
        assert policy.calculate_delay(0) == 0.5

        # Attempt 2: 0.5 * 2^2 = 2.0
        assert policy.calculate_delay(2) == 2.0

    def test_calculate_delay_custom_exponential_base(self) -> None:
        """Custom exponential base works correctly."""
        policy = RetryPolicy(
            base_delay_sec=1.0,
            exponential_base=3.0,
            max_delay_sec=60.0,
            jitter=False,
        )

        # Attempt 0: 1.0 * 3^0 = 1.0
        assert policy.calculate_delay(0) == 1.0

        # Attempt 1: 1.0 * 3^1 = 3.0
        assert policy.calculate_delay(1) == 3.0

        # Attempt 2: 1.0 * 3^2 = 9.0
        assert policy.calculate_delay(2) == 9.0


# ---------------------------------------------------------------------------
# ConnectionState unit tests
# ---------------------------------------------------------------------------


class TestConnectionState:
    """Test ConnectionState enum values."""

    def test_all_states_defined(self) -> None:
        """All required states are defined."""
        assert ConnectionState.DISCONNECTED.value == "disconnected"
        assert ConnectionState.CONNECTING.value == "connecting"
        assert ConnectionState.CONNECTED.value == "connected"
        assert ConnectionState.RECONNECTING.value == "reconnecting"
        assert ConnectionState.FAILED.value == "failed"

    def test_state_count(self) -> None:
        """Exactly 5 states are defined."""
        assert len(ConnectionState) == 5


# ---------------------------------------------------------------------------
# SSHSupervisor unit tests (mocked)
# ---------------------------------------------------------------------------


class TestSSHSupervisorUnit:
    """Unit tests for SSHSupervisor with mocked connections."""

    @pytest.fixture
    def event_collector(self) -> EventCollector:
        """Provide fresh event collector for each test."""
        return EventCollector()

    def test_initial_state_is_disconnected(self, event_collector: EventCollector) -> None:
        """Supervisor starts in DISCONNECTED state."""
        supervisor = SSHSupervisor(
            host="example.com",
            port=22,
            username="testuser",
            password="testpass",
            event_collector=event_collector,
        )

        assert supervisor.state == ConnectionState.DISCONNECTED
        assert supervisor.reconnection_count == 0
        assert supervisor.is_connected is False

    def test_default_retry_policy(self, event_collector: EventCollector) -> None:
        """Supervisor uses default retry policy if none provided."""
        supervisor = SSHSupervisor(
            host="example.com",
            username="testuser",
            password="testpass",
            event_collector=event_collector,
        )

        # Access private for testing
        assert supervisor._retry_policy.max_retries == 3
        assert supervisor._retry_policy.base_delay_sec == 1.0

    def test_custom_retry_policy(self, event_collector: EventCollector) -> None:
        """Supervisor uses custom retry policy when provided."""
        custom_policy = RetryPolicy(max_retries=5, base_delay_sec=2.0)
        supervisor = SSHSupervisor(
            host="example.com",
            username="testuser",
            password="testpass",
            event_collector=event_collector,
            retry_policy=custom_policy,
        )

        assert supervisor._retry_policy.max_retries == 5
        assert supervisor._retry_policy.base_delay_sec == 2.0


# ---------------------------------------------------------------------------
# SSHSupervisor integration tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_supervisor_connect_and_exec(
    ssh_server: "SSHServerInfo",
    event_collector: EventCollector,
) -> None:
    """
    SSHSupervisor connects successfully and executes commands.

    Success criteria:
    1. State transitions: DISCONNECTED -> CONNECTING -> CONNECTED
    2. Command execution returns correct result
    3. STATE_CHANGE events are emitted for each transition
    """
    assert ssh_server is not None, "SSH server fixture required"

    async with SSHSupervisor(
        host=ssh_server.host,
        port=ssh_server.port,
        username=ssh_server.username,
        password=ssh_server.password,
        known_hosts=ssh_server.known_hosts_path,
        event_collector=event_collector,
    ) as supervisor:
        # Postcondition: Connected
        assert supervisor.state == ConnectionState.CONNECTED
        assert supervisor.is_connected is True

        # Execute command
        result = await supervisor.exec("echo hello")

        assert result.exit_code == 0
        assert result.stdout.strip() == "hello"

    # Verify state change events
    state_events = [e for e in event_collector.events if e.event_type == "STATE_CHANGE"]

    # Should have at least: DISCONNECTED->CONNECTING, CONNECTING->CONNECTED, CONNECTED->DISCONNECTED
    assert len(state_events) >= 3, f"Expected >= 3 STATE_CHANGE events, got {len(state_events)}"

    # Verify transition sequence
    transitions = [(e.data["from_state"], e.data["to_state"]) for e in state_events]

    assert ("disconnected", "connecting") in transitions, "Missing DISCONNECTED->CONNECTING"
    assert ("connecting", "connected") in transitions, "Missing CONNECTING->CONNECTED"
    assert ("connected", "disconnected") in transitions, "Missing CONNECTED->DISCONNECTED"


@pytest.mark.asyncio
async def test_supervisor_wait_connected(
    ssh_server: "SSHServerInfo",
    event_collector: EventCollector,
) -> None:
    """
    wait_connected() returns True when connected.
    """
    assert ssh_server is not None

    async with SSHSupervisor(
        host=ssh_server.host,
        port=ssh_server.port,
        username=ssh_server.username,
        password=ssh_server.password,
        known_hosts=ssh_server.known_hosts_path,
        event_collector=event_collector,
    ) as supervisor:
        # Already connected via context manager
        result = await supervisor.wait_connected(timeout=1.0)
        assert result is True


@pytest.mark.asyncio
async def test_supervisor_close_transitions_to_disconnected(
    ssh_server: "SSHServerInfo",
    event_collector: EventCollector,
) -> None:
    """
    close() transitions to DISCONNECTED state.
    """
    assert ssh_server is not None

    supervisor = SSHSupervisor(
        host=ssh_server.host,
        port=ssh_server.port,
        username=ssh_server.username,
        password=ssh_server.password,
        known_hosts=ssh_server.known_hosts_path,
        event_collector=event_collector,
    )

    # Connect
    await supervisor.__aenter__()
    assert supervisor.state == ConnectionState.CONNECTED

    # Close
    await supervisor.close()
    assert supervisor.state == ConnectionState.DISCONNECTED


@pytest.mark.asyncio
async def test_supervisor_state_change_events_have_timestamps(
    ssh_server: "SSHServerInfo",
    event_collector: EventCollector,
) -> None:
    """
    All STATE_CHANGE events have valid timestamps.
    """
    assert ssh_server is not None

    async with SSHSupervisor(
        host=ssh_server.host,
        port=ssh_server.port,
        username=ssh_server.username,
        password=ssh_server.password,
        known_hosts=ssh_server.known_hosts_path,
        event_collector=event_collector,
    ):
        pass  # Just connect and disconnect

    state_events = [e for e in event_collector.events if e.event_type == "STATE_CHANGE"]

    for event in state_events:
        assert event.timestamp is not None, "STATE_CHANGE event missing timestamp"
        assert event.timestamp > 0, f"Invalid timestamp: {event.timestamp}"


@pytest.mark.asyncio
async def test_supervisor_tracks_reconnection_count(
    ssh_server: "SSHServerInfo",
    event_collector: EventCollector,
) -> None:
    """
    reconnection_count starts at 0 for initial connection.
    """
    assert ssh_server is not None

    async with SSHSupervisor(
        host=ssh_server.host,
        port=ssh_server.port,
        username=ssh_server.username,
        password=ssh_server.password,
        known_hosts=ssh_server.known_hosts_path,
        event_collector=event_collector,
    ) as supervisor:
        # Initial connection, no reconnections yet
        assert supervisor.reconnection_count == 0


@pytest.mark.asyncio
async def test_supervisor_max_retries_enforced(event_collector: EventCollector) -> None:
    """
    SSHSupervisor fails after max_retries exceeded.

    Success criteria:
    1. After max_retries connection attempts, state becomes FAILED
    2. STATE_CHANGE event shows max_retries_exceeded error
    """
    from nbs_ssh.errors import SSHConnectionError

    # Use very fast retry policy for test
    policy = RetryPolicy(max_retries=2, base_delay_sec=0.01, jitter=False)

    # Connect to non-existent server
    supervisor = SSHSupervisor(
        host="localhost",
        port=29999,  # Unlikely to be in use
        username="nobody",
        password="nopass",
        known_hosts=None,
        event_collector=event_collector,
        retry_policy=policy,
        connect_timeout=0.5,
    )

    with pytest.raises(SSHConnectionError):
        await supervisor.__aenter__()

    # Wait for state machine to settle
    await asyncio.sleep(0.1)

    # Should be in FAILED state
    assert supervisor.state == ConnectionState.FAILED

    # Verify state change events include failure
    state_events = [e for e in event_collector.events if e.event_type == "STATE_CHANGE"]
    final_states = [e.data["to_state"] for e in state_events]
    assert "failed" in final_states, "Should have transitioned to FAILED state"


@pytest.mark.asyncio
async def test_supervisor_state_change_includes_reconnection_count(
    ssh_server: "SSHServerInfo",
    event_collector: EventCollector,
) -> None:
    """
    STATE_CHANGE events include reconnection_count.
    """
    assert ssh_server is not None

    async with SSHSupervisor(
        host=ssh_server.host,
        port=ssh_server.port,
        username=ssh_server.username,
        password=ssh_server.password,
        known_hosts=ssh_server.known_hosts_path,
        event_collector=event_collector,
    ):
        pass

    state_events = [e for e in event_collector.events if e.event_type == "STATE_CHANGE"]

    for event in state_events:
        assert "reconnection_count" in event.data, \
            f"STATE_CHANGE event missing reconnection_count: {event.data}"


# ---------------------------------------------------------------------------
# Exponential backoff timing tests
# ---------------------------------------------------------------------------


class TestExponentialBackoffTiming:
    """Test that exponential backoff timing is correct."""

    def test_backoff_sequence_without_jitter(self) -> None:
        """
        Verify exponential backoff sequence.

        With base=1.0, exponential_base=2.0:
        - Attempt 0: 1s
        - Attempt 1: 2s
        - Attempt 2: 4s
        - Attempt 3: 8s
        - etc.
        """
        policy = RetryPolicy(
            base_delay_sec=1.0,
            exponential_base=2.0,
            max_delay_sec=120.0,
            jitter=False,
        )

        expected = [1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0]

        for attempt, expected_delay in enumerate(expected):
            actual = policy.calculate_delay(attempt)
            assert actual == expected_delay, \
                f"Attempt {attempt}: expected {expected_delay}, got {actual}"

    def test_backoff_respects_max_delay(self) -> None:
        """Backoff never exceeds max_delay_sec."""
        policy = RetryPolicy(
            base_delay_sec=1.0,
            exponential_base=2.0,
            max_delay_sec=5.0,
            jitter=False,
        )

        # Attempt 3 would be 8s, but capped at 5s
        assert policy.calculate_delay(3) == 5.0

        # Later attempts still capped
        assert policy.calculate_delay(10) == 5.0
        assert policy.calculate_delay(100) == 5.0

    def test_jitter_adds_variance_but_never_reduces(self) -> None:
        """
        Jitter only increases delay (0-25%), never decreases it.
        """
        policy = RetryPolicy(
            base_delay_sec=1.0,
            exponential_base=2.0,
            max_delay_sec=60.0,
            jitter=True,
        )

        for attempt in range(5):
            base_delay = policy.base_delay_sec * (policy.exponential_base ** attempt)

            # Sample multiple times
            for _ in range(50):
                actual = policy.calculate_delay(attempt)
                assert actual >= base_delay, \
                    f"Jitter should not reduce delay below base: {actual} < {base_delay}"
                assert actual <= base_delay * 1.25, \
                    f"Jitter should not exceed 25%: {actual} > {base_delay * 1.25}"
