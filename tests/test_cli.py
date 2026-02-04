"""
Tests for the nbs-ssh CLI interface.

Tests the command-line interface for:
- Argument parsing (user@host, port, key, password)
- Command execution via CLI
- Exit code propagation
- Event output with --events flag
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from nbs_ssh.testing.mock_server import MockSSHServer


class TestArgumentParsing:
    """Tests for CLI argument parsing."""

    def test_parse_target_with_user(self) -> None:
        """Test parsing user@host format."""
        from nbs_ssh.__main__ import parse_target

        host, user = parse_target("testuser@example.com")
        assert host == "example.com"
        assert user == "testuser"

    def test_parse_target_without_user(self) -> None:
        """Test parsing host-only format."""
        from nbs_ssh.__main__ import parse_target

        host, user = parse_target("example.com")
        assert host == "example.com"
        assert user is None

    def test_parse_target_with_at_in_user(self) -> None:
        """Test parsing when username contains @ (e.g., email-like)."""
        from nbs_ssh.__main__ import parse_target

        # Should split on rightmost @
        host, user = parse_target("user@domain@host.com")
        assert host == "host.com"
        assert user == "user@domain"

    def test_create_parser_defaults(self) -> None:
        """Test parser creates correct defaults."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["host.example.com", "echo test"])

        assert args.target == "host.example.com"
        assert args.command == "echo test"
        assert args.port == 22
        assert args.identity is None
        assert args.password is False
        assert args.events is False
        assert args.no_host_check is False
        assert args.timeout == 30.0

    def test_create_parser_custom_port(self) -> None:
        """Test parser handles custom port."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["-p", "2222", "host.example.com", "ls"])

        assert args.port == 2222

    def test_create_parser_identity_file(self) -> None:
        """Test parser handles identity file option."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["-i", "/path/to/key", "host", "cmd"])

        assert args.identity == "/path/to/key"

    def test_create_parser_password_flag(self) -> None:
        """Test parser handles --password flag."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["--password", "host", "cmd"])

        assert args.password is True

    def test_create_parser_events_flag(self) -> None:
        """Test parser handles --events flag."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["--events", "host", "cmd"])

        assert args.events is True

    def test_create_parser_login_user(self) -> None:
        """Test parser handles -l login option."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["-l", "otheruser", "host", "cmd"])

        assert args.login == "otheruser"


class TestHelpOutput:
    """Tests for help and version output."""

    def test_help_output(self) -> None:
        """Test --help shows usage information."""
        result = subprocess.run(
            [sys.executable, "-m", "nbs_ssh", "--help"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
            env={
                **subprocess.os.environ,
                "PYTHONPATH": str(Path(__file__).parent.parent / "src"),
            },
        )

        assert result.returncode == 0
        assert "nbs-ssh" in result.stdout
        assert "[user@]host" in result.stdout
        assert "--port" in result.stdout
        assert "--identity" in result.stdout
        assert "--password" in result.stdout
        assert "--events" in result.stdout

    def test_version_output(self) -> None:
        """Test --version shows version."""
        result = subprocess.run(
            [sys.executable, "-m", "nbs_ssh", "--version"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
            env={
                **subprocess.os.environ,
                "PYTHONPATH": str(Path(__file__).parent.parent / "src"),
            },
        )

        assert result.returncode == 0
        assert "0.1.0" in result.stdout


@pytest.mark.asyncio
async def test_cli_exec_command(mock_ssh_server: "MockSSHServer") -> None:
    """
    Test CLI can execute a command via MockSSHServer.

    Uses run_command directly to avoid subprocess stdin issues.
    """
    import argparse

    from nbs_ssh.__main__ import run_command

    args = argparse.Namespace(
        target=f"test@localhost",
        command="echo hello",
        port=mock_ssh_server.port,
        login=None,
        identity=None,
        password=False,
        events=False,
        no_host_check=True,
        timeout=10.0,
    )

    # Patch getpass to return test password
    import nbs_ssh.__main__ as cli_module

    original_getpass = cli_module.getpass.getpass
    cli_module.getpass.getpass = lambda prompt: "test"

    try:
        exit_code = await run_command(args)
        assert exit_code == 0
    finally:
        cli_module.getpass.getpass = original_getpass


@pytest.mark.asyncio
async def test_cli_exit_code_propagation(mock_ssh_server: "MockSSHServer") -> None:
    """
    Test CLI propagates remote command exit code.
    """
    import argparse

    from nbs_ssh.__main__ import run_command
    from nbs_ssh.testing.mock_server import MockServerConfig, MockSSHServer

    # Create server with custom exit code
    config = MockServerConfig(
        username="test",
        password="test",
        command_exit_codes={"exit 42": 42},
    )

    async with MockSSHServer(config) as server:
        args = argparse.Namespace(
            target="test@localhost",
            command="exit 42",
            port=server.port,
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
            assert exit_code == 42
        finally:
            cli_module.getpass.getpass = original_getpass


@pytest.mark.asyncio
async def test_cli_events_output(mock_ssh_server: "MockSSHServer") -> None:
    """
    Test CLI outputs JSONL events with --events flag.
    """
    import argparse
    import io
    import json
    import sys

    from nbs_ssh.__main__ import run_command

    args = argparse.Namespace(
        target="test@localhost",
        command="echo test",
        port=mock_ssh_server.port,
        login=None,
        identity=None,
        password=False,
        events=True,
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
        exit_code = await run_command(args)
        sys.stderr = original_stderr

        assert exit_code == 0

        # Parse JSONL events from stderr
        stderr_content = captured_stderr.getvalue()
        events = []
        for line in stderr_content.strip().split("\n"):
            if line.startswith("{"):
                events.append(json.loads(line))

        # Should have at least CONNECT, AUTH, EXEC, DISCONNECT
        event_types = [e.get("event_type") for e in events]
        assert "CONNECT" in event_types
        assert "AUTH" in event_types
        assert "EXEC" in event_types
        assert "DISCONNECT" in event_types

    finally:
        sys.stderr = original_stderr
        cli_module.getpass.getpass = original_getpass


@pytest.mark.asyncio
async def test_cli_connection_error() -> None:
    """
    Test CLI handles connection errors gracefully.
    """
    import argparse

    from nbs_ssh.__main__ import run_command

    args = argparse.Namespace(
        target="test@localhost",
        command="echo test",
        port=29999,  # Unlikely to be in use
        login=None,
        identity=None,
        password=False,
        events=False,
        no_host_check=True,
        timeout=2.0,
    )

    import nbs_ssh.__main__ as cli_module

    original_getpass = cli_module.getpass.getpass
    cli_module.getpass.getpass = lambda prompt: "test"

    try:
        exit_code = await run_command(args)
        assert exit_code == 1  # Error exit code
    finally:
        cli_module.getpass.getpass = original_getpass
