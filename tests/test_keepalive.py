"""
Tests for keepalive and freeze detection (Slice 3).

Tests:
1. KeepaliveConfig validation
2. Keepalive events emitted
3. ProgressWatchdog triggers after timeout
4. DisconnectReason correctly classified
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from nbs_ssh.errors import DisconnectReason
from nbs_ssh.events import EventCollector, EventType
from nbs_ssh.keepalive import KeepaliveConfig, ProgressWatchdog


class TestKeepaliveConfig:
    """Tests for KeepaliveConfig dataclass validation."""

    def test_default_values(self) -> None:
        """Default config should have sensible values."""
        config = KeepaliveConfig()

        assert config.interval_sec == 30.0
        assert config.max_count == 3
        assert config.progress_timeout_sec is None

    def test_custom_values(self) -> None:
        """Custom values should be accepted."""
        config = KeepaliveConfig(
            interval_sec=10.0,
            max_count=5,
            progress_timeout_sec=60.0,
        )

        assert config.interval_sec == 10.0
        assert config.max_count == 5
        assert config.progress_timeout_sec == 60.0

    def test_interval_must_be_positive(self) -> None:
        """interval_sec must be positive."""
        with pytest.raises(AssertionError, match="interval_sec must be positive"):
            KeepaliveConfig(interval_sec=0)

        with pytest.raises(AssertionError, match="interval_sec must be positive"):
            KeepaliveConfig(interval_sec=-1)

    def test_max_count_must_be_positive(self) -> None:
        """max_count must be positive."""
        with pytest.raises(AssertionError, match="max_count must be positive"):
            KeepaliveConfig(max_count=0)

        with pytest.raises(AssertionError, match="max_count must be positive"):
            KeepaliveConfig(max_count=-1)

    def test_progress_timeout_must_be_positive_if_set(self) -> None:
        """progress_timeout_sec must be positive if set."""
        with pytest.raises(AssertionError, match="progress_timeout_sec must be positive"):
            KeepaliveConfig(progress_timeout_sec=0)

        with pytest.raises(AssertionError, match="progress_timeout_sec must be positive"):
            KeepaliveConfig(progress_timeout_sec=-1)

    def test_total_timeout_calculation(self) -> None:
        """total_timeout_sec should be interval_sec * max_count."""
        config = KeepaliveConfig(interval_sec=30.0, max_count=3)
        assert config.total_timeout_sec == 90.0

        config2 = KeepaliveConfig(interval_sec=10.0, max_count=5)
        assert config2.total_timeout_sec == 50.0

    def test_to_asyncssh_options(self) -> None:
        """to_asyncssh_options returns correct dict for AsyncSSH."""
        config = KeepaliveConfig(interval_sec=30.0, max_count=3)
        options = config.to_asyncssh_options()

        assert options["keepalive_interval"] == 30.0
        assert options["keepalive_count_max"] == 3


class TestDisconnectReason:
    """Tests for DisconnectReason enum."""

    def test_all_reasons_exist(self) -> None:
        """All required disconnect reasons should exist."""
        assert DisconnectReason.NORMAL is not None
        assert DisconnectReason.KEEPALIVE_TIMEOUT is not None
        assert DisconnectReason.PROGRESS_TIMEOUT is not None
        assert DisconnectReason.NETWORK_ERROR is not None
        assert DisconnectReason.AUTH_FAILURE is not None

    def test_reason_values(self) -> None:
        """Reasons should have string values."""
        assert DisconnectReason.NORMAL.value == "normal"
        assert DisconnectReason.KEEPALIVE_TIMEOUT.value == "keepalive_timeout"
        assert DisconnectReason.PROGRESS_TIMEOUT.value == "progress_timeout"
        assert DisconnectReason.NETWORK_ERROR.value == "network_error"
        assert DisconnectReason.AUTH_FAILURE.value == "auth_failure"


class TestProgressWatchdog:
    """Tests for ProgressWatchdog freeze detection."""

    @pytest.mark.asyncio
    async def test_watchdog_creation(self) -> None:
        """ProgressWatchdog can be created with timeout."""
        collector = EventCollector()
        watchdog = ProgressWatchdog(
            timeout_sec=1.0,
            event_collector=collector,
        )

        assert watchdog.timeout_sec == 1.0
        assert not watchdog.is_running

    @pytest.mark.asyncio
    async def test_watchdog_reset_on_progress(self) -> None:
        """Calling progress() should reset the watchdog timer."""
        collector = EventCollector()
        watchdog = ProgressWatchdog(
            timeout_sec=0.5,
            event_collector=collector,
        )

        watchdog.start()
        try:
            # Reset several times before timeout
            for _ in range(3):
                await asyncio.sleep(0.2)
                watchdog.progress()

            # Should not have timed out
            assert not watchdog.timed_out
        finally:
            watchdog.stop()

    @pytest.mark.asyncio
    async def test_watchdog_emits_warning_before_timeout(self) -> None:
        """Watchdog should emit WARNING event before hard timeout."""
        collector = EventCollector()
        watchdog = ProgressWatchdog(
            timeout_sec=0.3,
            warning_threshold=0.5,  # Warn at 50% of timeout
            event_collector=collector,
        )

        watchdog.start()
        try:
            # Wait for warning but not full timeout
            await asyncio.sleep(0.2)

            # Should have warning event
            warnings = collector.get_by_type(EventType.PROGRESS_WARNING)
            assert len(warnings) >= 1
            assert warnings[0].data.get("seconds_remaining") is not None
        finally:
            watchdog.stop()

    @pytest.mark.asyncio
    async def test_watchdog_triggers_timeout_callback(self) -> None:
        """Watchdog should call timeout callback on progress timeout."""
        collector = EventCollector()
        timeout_triggered = False

        def on_timeout() -> None:
            nonlocal timeout_triggered
            timeout_triggered = True

        watchdog = ProgressWatchdog(
            timeout_sec=0.2,
            event_collector=collector,
            on_timeout=on_timeout,
        )

        watchdog.start()
        try:
            # Wait for timeout
            await asyncio.sleep(0.4)

            assert timeout_triggered
            assert watchdog.timed_out
        finally:
            watchdog.stop()

    @pytest.mark.asyncio
    async def test_watchdog_stop_cancels_timer(self) -> None:
        """Stopping watchdog should cancel the timer."""
        collector = EventCollector()
        timeout_triggered = False

        def on_timeout() -> None:
            nonlocal timeout_triggered
            timeout_triggered = True

        watchdog = ProgressWatchdog(
            timeout_sec=0.2,
            event_collector=collector,
            on_timeout=on_timeout,
        )

        watchdog.start()
        await asyncio.sleep(0.1)
        watchdog.stop()

        # Wait past when timeout would have fired
        await asyncio.sleep(0.2)

        assert not timeout_triggered
        assert not watchdog.is_running


class TestKeepaliveEventTypes:
    """Tests for keepalive-related event types."""

    def test_keepalive_event_types_exist(self) -> None:
        """Keepalive event types should be defined."""
        assert EventType.KEEPALIVE_SENT is not None
        assert EventType.KEEPALIVE_RECEIVED is not None
        assert EventType.KEEPALIVE_TIMEOUT is not None
        assert EventType.PROGRESS_WARNING is not None

    def test_keepalive_event_values(self) -> None:
        """Keepalive events should have string values."""
        assert EventType.KEEPALIVE_SENT.value == "KEEPALIVE_SENT"
        assert EventType.KEEPALIVE_RECEIVED.value == "KEEPALIVE_RECEIVED"
        assert EventType.KEEPALIVE_TIMEOUT.value == "KEEPALIVE_TIMEOUT"
        assert EventType.PROGRESS_WARNING.value == "PROGRESS_WARNING"


class TestDisconnectWithReason:
    """Tests for disconnect events including reason."""

    @pytest.mark.asyncio
    async def test_disconnect_event_includes_reason(
        self,
        ssh_server,
        event_collector,
    ) -> None:
        """DISCONNECT event should include DisconnectReason."""
        if ssh_server is None:
            pytest.skip("SSH server not available")

        from nbs_ssh.auth import create_password_auth
        from nbs_ssh.connection import SSHConnection

        auth = create_password_auth(ssh_server.password)

        async with SSHConnection(
            host=ssh_server.host,
            port=ssh_server.port,
            username=ssh_server.username,
            auth=auth,
            event_collector=event_collector,
            known_hosts=None,
        ):
            pass  # Just connect and disconnect normally

        disconnect_events = event_collector.get_by_type(EventType.DISCONNECT)
        assert len(disconnect_events) == 1
        assert disconnect_events[0].data.get("reason") == DisconnectReason.NORMAL.value


class TestKeepaliveIntegration:
    """Integration tests for keepalive with real SSH connection."""

    @pytest.mark.asyncio
    async def test_connection_with_keepalive_config(
        self,
        ssh_server,
        event_collector,
    ) -> None:
        """SSHConnection should accept KeepaliveConfig."""
        if ssh_server is None:
            pytest.skip("SSH server not available")

        from nbs_ssh.auth import create_password_auth
        from nbs_ssh.connection import SSHConnection

        auth = create_password_auth(ssh_server.password)
        keepalive = KeepaliveConfig(
            interval_sec=10.0,
            max_count=2,
        )

        async with SSHConnection(
            host=ssh_server.host,
            port=ssh_server.port,
            username=ssh_server.username,
            auth=auth,
            event_collector=event_collector,
            known_hosts=None,
            keepalive=keepalive,
        ) as conn:
            result = await conn.exec("echo keepalive-test")
            assert result.exit_code == 0
            assert "keepalive-test" in result.stdout
