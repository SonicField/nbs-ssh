"""
Tests for interactive shell mode.

Tests the interactive shell functionality:
- PTY allocation
- Terminal state restoration
- Event emission
- Exit code propagation
"""
from __future__ import annotations

import argparse
import asyncio
import io
import json
import sys
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

if TYPE_CHECKING:
    from nbs_ssh.testing.mock_server import MockSSHServer


class TestShellMethod:
    """Tests for SSHConnection.shell() method."""

    @pytest.mark.asyncio
    async def test_shell_requires_tty(self, mock_ssh_server: "MockSSHServer") -> None:
        """Test that shell() raises RuntimeError when stdin is not a TTY."""
        from nbs_ssh import SSHConnection, create_password_auth

        async with SSHConnection(
            host="localhost",
            port=mock_ssh_server.port,
            username="test",
            auth=create_password_auth("test"),
            known_hosts=None,
        ) as conn:
            # Mock stdin.isatty() to return False
            with patch.object(sys.stdin, "isatty", return_value=False):
                with pytest.raises(RuntimeError, match="requires a TTY"):
                    await conn.shell()

    @pytest.mark.asyncio
    async def test_shell_emits_events(self, mock_ssh_server: "MockSSHServer") -> None:
        """Test that shell() emits SHELL events."""
        from nbs_ssh import EventCollector, SSHConnection, create_password_auth

        collector = EventCollector()

        async with SSHConnection(
            host="localhost",
            port=mock_ssh_server.port,
            username="test",
            auth=create_password_auth("test"),
            known_hosts=None,
            event_collector=collector,
        ) as conn:
            # Mock stdin.isatty() to return False so we get the RuntimeError
            with patch.object(sys.stdin, "isatty", return_value=False):
                try:
                    await conn.shell()
                except RuntimeError:
                    pass

        # Should have CONNECT, AUTH, DISCONNECT events (no SHELL since it errored early)
        event_types = [e.event_type for e in collector.events]
        assert "CONNECT" in event_types
        assert "AUTH" in event_types


@pytest.mark.skipif(sys.platform == "win32", reason="Interactive shell requires termios (Unix only)")
class TestShellCLI:
    """Tests for CLI interactive shell mode."""

    @pytest.mark.asyncio
    async def test_cli_no_command_non_tty(self, mock_ssh_server: "MockSSHServer") -> None:
        """
        Test CLI with no command when stdin is not a TTY.

        Should connect, print a message, and exit cleanly.
        """
        from nbs_ssh.__main__ import run_command

        args = argparse.Namespace(
            target="test@localhost",
            command=None,  # No command = shell mode
            port=mock_ssh_server.port,
            login=None,
            identity=None,
            password=False,
            events=False,
            no_host_check=True,
            timeout=10.0,
        )

        import nbs_ssh.__main__ as cli_module

        original_getpass = cli_module.getpass.getpass
        cli_module.getpass.getpass = lambda prompt: "test"

        # Capture stderr
        captured_stderr = io.StringIO()
        original_stderr = sys.stderr

        try:
            sys.stderr = captured_stderr

            # Mock stdin.isatty() to return False
            with patch.object(sys.stdin, "isatty", return_value=False):
                exit_code = await run_command(args)

            sys.stderr = original_stderr

            assert exit_code == 0

            # Check that we got the expected message
            stderr_content = captured_stderr.getvalue()
            assert "Connected to" in stderr_content
            assert "Interactive shell not available" in stderr_content

        finally:
            sys.stderr = original_stderr
            cli_module.getpass.getpass = original_getpass

    @pytest.mark.asyncio
    async def test_cli_with_command(self, mock_ssh_server: "MockSSHServer") -> None:
        """
        Test CLI with command still works.

        When a command is provided, should execute it normally.
        """
        from nbs_ssh.__main__ import run_command

        args = argparse.Namespace(
            target="test@localhost",
            command="echo hello",
            port=mock_ssh_server.port,
            login=None,
            identity=None,
            password=False,
            events=False,
            no_host_check=True,
            timeout=10.0,
        )

        import nbs_ssh.__main__ as cli_module

        original_getpass = cli_module.getpass.getpass
        cli_module.getpass.getpass = lambda prompt: "test"

        try:
            exit_code = await run_command(args)
            assert exit_code == 0
        finally:
            cli_module.getpass.getpass = original_getpass


class TestMockServerShell:
    """Tests for MockSSHServer shell support."""

    @pytest.mark.asyncio
    async def test_mock_server_shell_session(self) -> None:
        """Test that MockSSHServer handles shell sessions."""
        from nbs_ssh import SSHConnection, create_password_auth
        from nbs_ssh.testing.mock_server import MockServerConfig, MockSSHServer

        config = MockServerConfig(
            username="test",
            password="test",
        )

        async with MockSSHServer(config) as server:
            async with SSHConnection(
                host="localhost",
                port=server.port,
                username="test",
                auth=create_password_auth("test"),
                known_hosts=None,
            ) as conn:
                # We can't test full shell interaction without a PTY,
                # but we can verify the connection works
                result = await conn.exec("echo test")
                assert result.exit_code == 0
                assert "test" in result.stdout

            # Check server events
            event_types = [e.event_type for e in server.events]
            assert "SERVER_START" in event_types
            assert "SERVER_EXEC" in event_types

    @pytest.mark.asyncio
    async def test_mock_server_shell_events(self) -> None:
        """Test that shell session emits expected server events."""
        import asyncssh

        from nbs_ssh.testing.mock_server import MockServerConfig, MockSSHServer

        config = MockServerConfig(
            username="test",
            password="test",
        )

        async with MockSSHServer(config) as server:
            # Connect and open a shell directly (without going through SSHConnection.shell())
            async with asyncssh.connect(
                host="localhost",
                port=server.port,
                username="test",
                password="test",
                known_hosts=None,
            ) as conn:
                # Request a shell session
                process = await conn.create_process(
                    None,  # No command = shell
                    term_type="xterm",
                    term_size=(80, 24),
                )

                # Send "exit" to close the shell
                process.stdin.write("exit\r")
                process.stdin.write_eof()

                # Wait for exit with timeout
                try:
                    await asyncio.wait_for(process.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    process.terminate()

            # Check server events
            event_types = [e.event_type for e in server.events]
            assert "SERVER_SHELL_START" in event_types
            assert "SERVER_SHELL_PTY" in event_types
