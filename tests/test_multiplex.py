"""
Tests for connection multiplexing (ControlMaster).

Falsifiable assertions:
1. Control socket is created with correct permissions when master starts
2. MultiplexClient can detect when master is running
3. Commands executed via multiplex use the shared connection
4. ControlPersist timeout causes master to exit after idle period
5. -O exit command causes master to shutdown
6. Token expansion in ControlPath works correctly
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from nbs_ssh.multiplex import (
    ControlCommand,
    ControlMaster,
    ControlMasterMode,
    ControlMessage,
    MessageType,
    MultiplexClient,
    expand_control_path,
    parse_control_persist,
)


class TestControlPathExpansion:
    """Tests for control path token expansion."""

    def test_expand_host_token(self) -> None:
        """GIVEN template with %h WHEN expanded THEN host is substituted."""
        result = expand_control_path(
            "/tmp/ssh-%h.sock",
            host="example.com",
            port=22,
        )
        assert result == Path("/tmp/ssh-example.com.sock")

    def test_expand_port_token(self) -> None:
        """GIVEN template with %p WHEN expanded THEN port is substituted."""
        result = expand_control_path(
            "/tmp/ssh-%h-%p.sock",
            host="example.com",
            port=2222,
        )
        assert result == Path("/tmp/ssh-example.com-2222.sock")

    def test_expand_remote_user_token(self) -> None:
        """GIVEN template with %r WHEN expanded THEN remote user is substituted."""
        result = expand_control_path(
            "/tmp/ssh-%r@%h.sock",
            host="example.com",
            port=22,
            remote_user="testuser",
        )
        assert result == Path("/tmp/ssh-testuser@example.com.sock")

    def test_expand_local_user_token(self) -> None:
        """GIVEN template with %u WHEN expanded THEN local user is substituted."""
        result = expand_control_path(
            "/tmp/ssh-%u@%h.sock",
            host="example.com",
            port=22,
            local_user="localuser",
        )
        assert result == Path("/tmp/ssh-localuser@example.com.sock")

    def test_expand_local_host_token(self) -> None:
        """GIVEN template with %L WHEN expanded THEN local hostname is substituted."""
        result = expand_control_path(
            "/tmp/ssh-%L-%h.sock",
            host="example.com",
            port=22,
            local_host="myhost.local",
        )
        assert result == Path("/tmp/ssh-myhost-example.com.sock")

    def test_expand_connection_hash_token(self) -> None:
        """GIVEN template with %C WHEN expanded THEN connection hash is substituted."""
        result = expand_control_path(
            "/tmp/ssh-%C.sock",
            host="example.com",
            port=22,
            remote_user="user",
            local_host="myhost",
        )
        # Hash should be 16 characters hex
        filename = result.name
        assert filename.startswith("ssh-")
        assert filename.endswith(".sock")
        hash_part = filename[4:-5]
        assert len(hash_part) == 16
        assert all(c in "0123456789abcdef" for c in hash_part)

    def test_expand_literal_percent(self) -> None:
        """GIVEN template with %% WHEN expanded THEN literal % is produced."""
        result = expand_control_path(
            "/tmp/ssh-%%-%h.sock",
            host="example.com",
            port=22,
        )
        assert result == Path("/tmp/ssh-%-example.com.sock")

    def test_expand_tilde(self) -> None:
        """GIVEN template with ~ WHEN expanded THEN home directory is substituted."""
        result = expand_control_path(
            "~/.ssh/sockets/%h.sock",
            host="example.com",
            port=22,
        )
        assert str(result).startswith(str(Path.home()))


class TestParseControlPersist:
    """Tests for ControlPersist value parsing."""

    def test_parse_yes(self) -> None:
        """GIVEN 'yes' WHEN parsed THEN returns None (infinite)."""
        assert parse_control_persist("yes") is None
        assert parse_control_persist("YES") is None
        assert parse_control_persist("true") is None
        assert parse_control_persist("1") is None

    def test_parse_no(self) -> None:
        """GIVEN 'no' WHEN parsed THEN returns 0 (exit immediately)."""
        assert parse_control_persist("no") == 0.0
        assert parse_control_persist("NO") == 0.0
        assert parse_control_persist("false") == 0.0
        assert parse_control_persist("0") == 0.0

    def test_parse_seconds(self) -> None:
        """GIVEN time in seconds WHEN parsed THEN returns correct value."""
        assert parse_control_persist("30") == 30.0
        assert parse_control_persist("30s") == 30.0

    def test_parse_minutes(self) -> None:
        """GIVEN time in minutes WHEN parsed THEN returns correct seconds."""
        assert parse_control_persist("5m") == 300.0
        assert parse_control_persist("10m") == 600.0

    def test_parse_hours(self) -> None:
        """GIVEN time in hours WHEN parsed THEN returns correct seconds."""
        assert parse_control_persist("1h") == 3600.0
        assert parse_control_persist("2h") == 7200.0

    def test_parse_days(self) -> None:
        """GIVEN time in days WHEN parsed THEN returns correct seconds."""
        assert parse_control_persist("1d") == 86400.0

    def test_parse_invalid(self) -> None:
        """GIVEN invalid value WHEN parsed THEN raises ValueError."""
        with pytest.raises(ValueError):
            parse_control_persist("invalid")
        with pytest.raises(ValueError):
            parse_control_persist("10x")


class TestControlMessage:
    """Tests for control message encoding/decoding."""

    def test_encode_decode_roundtrip(self) -> None:
        """GIVEN message WHEN encoded then decoded THEN identical message."""
        original = ControlMessage(
            msg_type=MessageType.EXEC,
            data={"command": "echo hello", "env": {"FOO": "bar"}},
        )
        encoded = original.encode()
        decoded = ControlMessage.decode(encoded[4:])  # Skip length prefix

        assert decoded.msg_type == original.msg_type
        assert decoded.data == original.data

    def test_encode_has_length_prefix(self) -> None:
        """GIVEN message WHEN encoded THEN has 4-byte length prefix."""
        msg = ControlMessage(msg_type=MessageType.CHECK)
        encoded = msg.encode()

        # First 4 bytes are length (big-endian)
        import struct
        length = struct.unpack(">I", encoded[:4])[0]
        assert length == len(encoded) - 4


@pytest.mark.skipif(sys.platform == "win32", reason="Unix sockets not available on Windows")
class TestControlMaster:
    """Tests for ControlMaster server."""

    @pytest.mark.asyncio
    async def test_socket_created_on_start(self) -> None:
        """GIVEN ControlMaster WHEN started THEN socket file is created."""
        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = Path(tmpdir) / "test.sock"

            # Create mock connection
            mock_conn = MagicMock()

            master = ControlMaster(socket_path)
            await master.start(mock_conn)

            try:
                assert socket_path.exists()
                # Check permissions (should be 0600)
                mode = os.stat(socket_path).st_mode & 0o777
                assert mode == 0o600
            finally:
                await master.stop()

    @pytest.mark.asyncio
    async def test_socket_removed_on_stop(self) -> None:
        """GIVEN running ControlMaster WHEN stopped THEN socket file is removed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = Path(tmpdir) / "test.sock"

            mock_conn = MagicMock()

            master = ControlMaster(socket_path)
            await master.start(mock_conn)

            assert socket_path.exists()

            await master.stop()

            assert not socket_path.exists()

    @pytest.mark.asyncio
    async def test_stale_socket_replaced(self) -> None:
        """GIVEN stale socket file WHEN master starts THEN replaces it."""
        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = Path(tmpdir) / "test.sock"

            # Create stale socket file
            socket_path.touch()

            mock_conn = MagicMock()

            master = ControlMaster(socket_path)
            await master.start(mock_conn)

            try:
                # Should have replaced the stale file with a real socket
                assert socket_path.exists()
            finally:
                await master.stop()


@pytest.mark.skipif(sys.platform == "win32", reason="Unix sockets not available on Windows")
class TestMultiplexClient:
    """Tests for MultiplexClient."""

    @pytest.mark.asyncio
    async def test_check_returns_false_when_no_socket(self) -> None:
        """GIVEN no socket file WHEN check() called THEN returns False."""
        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = Path(tmpdir) / "nonexistent.sock"

            client = MultiplexClient(socket_path)
            result = await client.check()

            assert result is False

    @pytest.mark.asyncio
    async def test_check_returns_true_when_master_running(self) -> None:
        """GIVEN running master WHEN check() called THEN returns True."""
        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = Path(tmpdir) / "test.sock"

            mock_conn = MagicMock()

            master = ControlMaster(socket_path)
            await master.start(mock_conn)

            try:
                client = MultiplexClient(socket_path)
                result = await client.check()

                assert result is True
            finally:
                await master.stop()

    @pytest.mark.asyncio
    async def test_request_exit_stops_master(self) -> None:
        """GIVEN running master WHEN request_exit() called THEN master stops."""
        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = Path(tmpdir) / "test.sock"

            mock_conn = MagicMock()

            master = ControlMaster(socket_path)
            await master.start(mock_conn)

            client = MultiplexClient(socket_path)
            result = await client.request_exit()

            assert result is True

            # Wait for master to stop
            await asyncio.sleep(0.1)

            assert not master.is_running

    @pytest.mark.asyncio
    async def test_exec_via_master(self) -> None:
        """GIVEN running master WHEN exec() called THEN command executed via shared connection."""
        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = Path(tmpdir) / "test.sock"

            # Create mock connection that returns a result
            mock_result = MagicMock()
            mock_result.stdout = "hello world\n"
            mock_result.stderr = ""
            mock_result.exit_status = 0

            mock_conn = MagicMock()
            mock_conn.run = AsyncMock(return_value=mock_result)

            master = ControlMaster(socket_path)
            await master.start(mock_conn)

            try:
                client = MultiplexClient(socket_path)
                stdout, stderr, exit_code = await client.exec("echo hello world")

                assert stdout == "hello world\n"
                assert stderr == ""
                assert exit_code == 0

                # Verify the command was passed to the connection
                mock_conn.run.assert_called_once()
                call_args = mock_conn.run.call_args
                assert call_args[0][0] == "echo hello world"
            finally:
                await master.stop()


class TestControlMasterModes:
    """Tests for ControlMaster mode enum."""

    def test_mode_values(self) -> None:
        """GIVEN ControlMasterMode WHEN accessed THEN has correct values."""
        assert ControlMasterMode.NO.value == "no"
        assert ControlMasterMode.YES.value == "yes"
        assert ControlMasterMode.AUTO.value == "auto"
        assert ControlMasterMode.AUTOASK.value == "autoask"


class TestControlCommands:
    """Tests for control command enum."""

    def test_command_values(self) -> None:
        """GIVEN ControlCommand WHEN accessed THEN has correct values."""
        assert ControlCommand.CHECK.value == "check"
        assert ControlCommand.EXIT.value == "exit"
        assert ControlCommand.STOP.value == "stop"
        assert ControlCommand.FORWARD.value == "forward"
        assert ControlCommand.CANCEL.value == "cancel"


@pytest.mark.skipif(sys.platform == "win32", reason="Unix sockets not available on Windows")
class TestControlPersist:
    """Tests for ControlPersist timeout behaviour."""

    @pytest.mark.asyncio
    async def test_persist_zero_exits_immediately(self) -> None:
        """GIVEN persist_time=0 WHEN last client disconnects THEN master exits."""
        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = Path(tmpdir) / "test.sock"

            mock_conn = MagicMock()

            master = ControlMaster(socket_path, persist_time=0.0)
            await master.start(mock_conn)

            # Simulate a client connecting and disconnecting
            client = MultiplexClient(socket_path)
            assert await client.check()

            # Wait for master to exit
            await asyncio.sleep(0.2)

            assert not master.is_running

    @pytest.mark.asyncio
    async def test_persist_time_delays_exit(self) -> None:
        """GIVEN persist_time>0 WHEN last client disconnects THEN master waits before exiting."""
        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = Path(tmpdir) / "test.sock"

            mock_conn = MagicMock()

            # Set persist time to 0.5 seconds
            master = ControlMaster(socket_path, persist_time=0.5)
            await master.start(mock_conn)

            try:
                # Simulate a client connecting and disconnecting
                client = MultiplexClient(socket_path)
                assert await client.check()

                # Master should still be running immediately after
                await asyncio.sleep(0.1)
                assert master.is_running

                # Wait for persist timeout
                await asyncio.sleep(0.5)

                assert not master.is_running
            finally:
                if master.is_running:
                    await master.stop()

    @pytest.mark.asyncio
    async def test_persist_none_runs_indefinitely(self) -> None:
        """GIVEN persist_time=None WHEN last client disconnects THEN master keeps running."""
        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = Path(tmpdir) / "test.sock"

            mock_conn = MagicMock()

            master = ControlMaster(socket_path, persist_time=None)
            await master.start(mock_conn)

            try:
                # Simulate a client connecting and disconnecting
                client = MultiplexClient(socket_path)
                assert await client.check()

                # Wait a bit
                await asyncio.sleep(0.2)

                # Master should still be running
                assert master.is_running
            finally:
                await master.stop()
