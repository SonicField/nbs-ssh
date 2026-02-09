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
from unittest.mock import patch

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
        assert "0.2.0" in result.stdout


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
        # Disable auto-discovery so the CLI falls through to password auth
        with patch("nbs_ssh.get_agent_available", return_value=False), \
             patch("nbs_ssh.get_default_key_paths", return_value=[]):
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
            with patch("nbs_ssh.get_agent_available", return_value=False), \
                 patch("nbs_ssh.get_default_key_paths", return_value=[]):
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
        with patch("nbs_ssh.get_agent_available", return_value=False), \
             patch("nbs_ssh.get_default_key_paths", return_value=[]):
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


@pytest.mark.asyncio
async def test_cli_uses_default_key_auth() -> None:
    """
    Test CLI uses default key when available, without prompting for password.

    Verifies the auth fallback order:
    1. SSH agent (if available)
    2. Default keys (~/.ssh/id_rsa, etc.)
    3. Password prompt (only if nothing else works)
    """
    import argparse
    import tempfile
    from pathlib import Path

    import asyncssh

    from nbs_ssh.__main__ import run_command
    from nbs_ssh.testing.mock_server import MockServerConfig, MockSSHServer

    # Generate a test keypair
    private_key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
    public_key = private_key.export_public_key().decode("utf-8")

    # Create mock server with key auth
    config = MockServerConfig(
        username="test",
        password="test",
        authorized_keys=[public_key],
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        # Write private key to a temp file
        key_path = Path(tmpdir) / "id_rsa"
        key_path.write_bytes(private_key.export_private_key())
        key_path.chmod(0o600)

        async with MockSSHServer(config) as server:
            args = argparse.Namespace(
                target="test@localhost",
                command="echo hello",
                port=server.port,
                login=None,
                identity=str(key_path),  # Explicit key
                password=False,
                events=False,
                no_host_check=True,
                timeout=10.0,
            )

            import nbs_ssh.__main__ as cli_module

            # Track if getpass was called - it should NOT be
            getpass_called = False
            original_getpass = cli_module.getpass.getpass

            def tracking_getpass(prompt: str) -> str:
                nonlocal getpass_called
                getpass_called = True
                return "wrong_password"

            cli_module.getpass.getpass = tracking_getpass

            try:
                exit_code = await run_command(args)
                assert exit_code == 0, "Key auth should succeed"
                assert not getpass_called, "Password should not be prompted when key is provided"
            finally:
                cli_module.getpass.getpass = original_getpass


@pytest.mark.asyncio
async def test_cli_falls_back_to_password_when_no_keys() -> None:
    """
    Test CLI tries keyboard-interactive before password when no agent/keys.

    OpenSSH discovery order: publickey → keyboard-interactive → password.
    When no agent or keys exist, keyboard-interactive should be tried
    first (handles Duo/2FA). Password prompt only happens as a retry
    after auth failure against a reachable server.
    """
    import argparse

    from nbs_ssh.__main__ import run_command

    args = argparse.Namespace(
        target="test@localhost",
        command="echo test",
        port=29999,  # Won't connect anyway
        login=None,
        identity=None,
        password=False,
        events=False,
        no_host_check=True,
        timeout=2.0,
    )

    import nbs_ssh.__main__ as cli_module

    # Track whether password was prompted eagerly (it shouldn't be)
    original_getpass = cli_module.getpass.getpass
    getpass_called = False

    def tracking_getpass(prompt: str) -> str:
        nonlocal getpass_called
        getpass_called = True
        return "test"

    cli_module.getpass.getpass = tracking_getpass

    try:
        with patch("nbs_ssh.get_agent_available", return_value=False), \
             patch("nbs_ssh.get_default_key_paths", return_value=[]):
            await run_command(args)  # Will fail to connect, that's OK
        # Password should NOT be prompted eagerly — keyboard-interactive
        # is tried first. Password only prompted on auth failure retry
        # against a reachable server.
        assert not getpass_called, (
            "Password should not be prompted eagerly when keyboard-interactive "
            "is available"
        )
    finally:
        cli_module.getpass.getpass = original_getpass


class TestKnownHostsDefault:
    """Tests for known_hosts default behaviour (CRIT-1 fix)."""

    def test_cli_uses_known_hosts_by_default(self) -> None:
        """
        Test CLI uses ~/.ssh/known_hosts by default (not None).

        This is the fix for the bug where () was passed as default,
        which is falsy and resulted in known_hosts=None (disabling verification).
        """
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["host.example.com", "echo test"])

        # no_host_check should be False by default
        assert args.no_host_check is False

    def test_no_host_check_flag_sets_true(self) -> None:
        """Test --no-host-check flag sets no_host_check=True."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["--no-host-check", "host.example.com", "echo test"])

        assert args.no_host_check is True

    @pytest.mark.asyncio
    async def test_known_hosts_default_path_is_used(self) -> None:
        """
        Test that run_command uses ASK policy by default.

        We patch SSHConnection to capture the host_key_policy value.
        """
        import argparse
        from pathlib import Path
        from unittest.mock import AsyncMock, patch

        from nbs_ssh.__main__ import run_command
        from nbs_ssh import HostKeyPolicy

        captured_policy = None

        # Create a mock SSHConnection that captures host_key_policy
        class MockConnection:
            def __init__(self, **kwargs):
                nonlocal captured_policy
                captured_policy = kwargs.get("host_key_policy")

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def exec(self, command):
                from nbs_ssh.connection import ExecResult
                return ExecResult(stdout="hello\n", stderr="", exit_code=0)

        args = argparse.Namespace(
            target="test@localhost",
            command="echo hello",
            port=22,
            login=None,
            identity=None,
            password=True,
            keyboard_interactive=False,
            pkcs11_provider=None,
            events=False,
            no_host_check=False,  # Default: should use ASK policy
            strict_host_key_checking="ask",
            timeout=10.0,
            proxy_jump=None,
            proxy_command=None,
        )

        import nbs_ssh.__main__ as cli_module

        original_getpass = cli_module.getpass.getpass
        cli_module.getpass.getpass = lambda prompt: "test"

        try:
            # Patch SSHConnection where it's imported inside run_command
            with patch("nbs_ssh.SSHConnection", MockConnection):
                await run_command(args)

            # host_key_policy should be ASK by default
            assert captured_policy == HostKeyPolicy.ASK
        finally:
            cli_module.getpass.getpass = original_getpass

    @pytest.mark.asyncio
    async def test_no_host_check_passes_none(self) -> None:
        """
        Test that --no-host-check uses INSECURE policy.
        """
        import argparse
        from pathlib import Path
        from unittest.mock import AsyncMock, patch

        from nbs_ssh.__main__ import run_command
        from nbs_ssh import HostKeyPolicy

        captured_policy = "NOT_SET"  # Use sentinel to distinguish from None

        class MockConnection:
            def __init__(self, **kwargs):
                nonlocal captured_policy
                captured_policy = kwargs.get("host_key_policy")

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def exec(self, command):
                from nbs_ssh.connection import ExecResult
                return ExecResult(stdout="hello\n", stderr="", exit_code=0)

        args = argparse.Namespace(
            target="test@localhost",
            command="echo hello",
            port=22,
            login=None,
            identity=None,
            password=True,
            keyboard_interactive=False,
            pkcs11_provider=None,
            events=False,
            no_host_check=True,  # Should use INSECURE policy
            strict_host_key_checking="ask",  # Overridden by no_host_check
            timeout=10.0,
            proxy_jump=None,
            proxy_command=None,
        )

        import nbs_ssh.__main__ as cli_module

        original_getpass = cli_module.getpass.getpass
        cli_module.getpass.getpass = lambda prompt: "test"

        try:
            # Patch SSHConnection where it's imported inside run_command
            with patch("nbs_ssh.SSHConnection", MockConnection):
                await run_command(args)

            # host_key_policy should be INSECURE when --no-host-check is used
            assert captured_policy == HostKeyPolicy.INSECURE
        finally:
            cli_module.getpass.getpass = original_getpass


class TestForwardingParsing:
    """Tests for port forwarding specification parsing."""

    def test_parse_local_forward_simple(self) -> None:
        """Test parsing simple local forward spec (port:host:hostport)."""
        from nbs_ssh.__main__ import parse_local_forward

        bind_host, bind_port, dest_host, dest_port = parse_local_forward("8080:localhost:80")
        assert bind_host is None
        assert bind_port == 8080
        assert dest_host == "localhost"
        assert dest_port == 80

    def test_parse_local_forward_with_bind_addr(self) -> None:
        """Test parsing local forward with bind address."""
        from nbs_ssh.__main__ import parse_local_forward

        bind_host, bind_port, dest_host, dest_port = parse_local_forward(
            "127.0.0.1:8080:localhost:80"
        )
        assert bind_host == "127.0.0.1"
        assert bind_port == 8080
        assert dest_host == "localhost"
        assert dest_port == 80

    def test_parse_local_forward_wildcard(self) -> None:
        """Test parsing local forward with wildcard bind (*)."""
        from nbs_ssh.__main__ import parse_local_forward

        bind_host, bind_port, dest_host, dest_port = parse_local_forward(
            "*:8080:localhost:80"
        )
        assert bind_host == ""  # Empty string means bind to all interfaces
        assert bind_port == 8080
        assert dest_host == "localhost"
        assert dest_port == 80

    def test_parse_local_forward_invalid(self) -> None:
        """Test parsing invalid local forward spec raises ValueError."""
        from nbs_ssh.__main__ import parse_local_forward

        import pytest

        with pytest.raises(ValueError, match="Invalid local forward spec"):
            parse_local_forward("invalid")

        with pytest.raises(ValueError, match="Invalid local forward spec"):
            parse_local_forward("8080:localhost")  # Missing hostport

    def test_parse_remote_forward(self) -> None:
        """Test parsing remote forward spec (same format as local)."""
        from nbs_ssh.__main__ import parse_remote_forward

        bind_host, bind_port, dest_host, dest_port = parse_remote_forward(
            "9090:localhost:3000"
        )
        assert bind_host is None
        assert bind_port == 9090
        assert dest_host == "localhost"
        assert dest_port == 3000

    def test_parse_dynamic_forward_simple(self) -> None:
        """Test parsing simple dynamic forward spec (port only)."""
        from nbs_ssh.__main__ import parse_dynamic_forward

        bind_host, bind_port = parse_dynamic_forward("1080")
        assert bind_host is None
        assert bind_port == 1080

    def test_parse_dynamic_forward_with_bind_addr(self) -> None:
        """Test parsing dynamic forward with bind address."""
        from nbs_ssh.__main__ import parse_dynamic_forward

        bind_host, bind_port = parse_dynamic_forward("127.0.0.1:1080")
        assert bind_host == "127.0.0.1"
        assert bind_port == 1080

    def test_parse_dynamic_forward_wildcard(self) -> None:
        """Test parsing dynamic forward with wildcard bind."""
        from nbs_ssh.__main__ import parse_dynamic_forward

        bind_host, bind_port = parse_dynamic_forward("*:1080")
        assert bind_host == ""
        assert bind_port == 1080

    def test_parse_dynamic_forward_invalid(self) -> None:
        """Test parsing invalid dynamic forward spec raises ValueError."""
        from nbs_ssh.__main__ import parse_dynamic_forward

        import pytest

        with pytest.raises(ValueError, match="Invalid dynamic forward spec"):
            parse_dynamic_forward("a:b:c")  # Too many colons


class TestForwardingCLIArgs:
    """Tests for forwarding CLI argument parsing."""

    def test_local_forward_arg(self) -> None:
        """Test -L argument is parsed correctly."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["-L", "8080:localhost:80", "host.example.com"])

        assert args.local_forward == ["8080:localhost:80"]

    def test_multiple_local_forwards(self) -> None:
        """Test multiple -L arguments are collected."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args([
            "-L", "8080:localhost:80",
            "-L", "8443:localhost:443",
            "host.example.com",
        ])

        assert args.local_forward == ["8080:localhost:80", "8443:localhost:443"]

    def test_remote_forward_arg(self) -> None:
        """Test -R argument is parsed correctly."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["-R", "9090:localhost:3000", "host.example.com"])

        assert args.remote_forward == ["9090:localhost:3000"]

    def test_dynamic_forward_arg(self) -> None:
        """Test -D argument is parsed correctly."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["-D", "1080", "host.example.com"])

        assert args.dynamic_forward == ["1080"]

    def test_no_command_arg(self) -> None:
        """Test -N argument is parsed correctly."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["-N", "-L", "8080:localhost:80", "host.example.com"])

        assert args.no_command is True
        assert args.local_forward == ["8080:localhost:80"]

    def test_verbose_arg(self) -> None:
        """Test --verbose argument is parsed correctly."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()

        # Single verbose
        args = parser.parse_args(["--verbose", "host.example.com"])
        assert args.verbose == 1

        # Double verbose
        args = parser.parse_args(["--verbose", "--verbose", "host.example.com"])
        assert args.verbose == 2

    def test_combined_forwarding_options(self) -> None:
        """Test combining multiple forwarding options."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args([
            "-L", "8080:localhost:80",
            "-R", "9090:localhost:3000",
            "-D", "1080",
            "-N",
            "host.example.com",
        ])

        assert args.local_forward == ["8080:localhost:80"]
        assert args.remote_forward == ["9090:localhost:3000"]
        assert args.dynamic_forward == ["1080"]
        assert args.no_command is True


class TestForwardingHelpOutput:
    """Tests for forwarding options in help output."""

    def test_help_shows_forwarding_options(self) -> None:
        """Test --help shows forwarding options."""
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
        assert "-L" in result.stdout
        assert "-R" in result.stdout
        assert "-D" in result.stdout
        assert "-N" in result.stdout
        assert "--verbose" in result.stdout
        assert "local-forward" in result.stdout
        assert "remote-forward" in result.stdout
        assert "dynamic-forward" in result.stdout


class TestExtendedCLIOptions:
    """Tests for extended OpenSSH-compatible CLI options."""

    def test_forward_agent_arg(self) -> None:
        """Test -A argument is parsed correctly."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["-A", "host.example.com"])

        assert args.forward_agent is True

    def test_compress_arg(self) -> None:
        """Test -C argument is parsed correctly."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["-C", "host.example.com"])

        assert args.compress is True

    def test_forward_x11_arg(self) -> None:
        """Test -X argument is parsed correctly."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["-X", "host.example.com"])

        assert args.forward_x11 is True

    def test_forward_x11_trusted_arg(self) -> None:
        """Test -Y argument is parsed correctly."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["-Y", "host.example.com"])

        assert args.forward_x11_trusted is True

    def test_force_tty_arg(self) -> None:
        """Test -t argument is parsed correctly."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["-t", "host.example.com", "command"])

        assert args.force_tty is True

    def test_disable_tty_arg(self) -> None:
        """Test -T argument is parsed correctly."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["-T", "host.example.com", "command"])

        assert args.disable_tty is True

    def test_quiet_arg(self) -> None:
        """Test -q argument is parsed correctly."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["-q", "host.example.com"])

        assert args.quiet is True

    def test_combined_extended_options(self) -> None:
        """Test combining multiple extended options."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args([
            "-A", "-C", "-X", "-t", "-q",
            "host.example.com", "command",
        ])

        assert args.forward_agent is True
        assert args.compress is True
        assert args.forward_x11 is True
        assert args.force_tty is True
        assert args.quiet is True

    def test_defaults_are_false(self) -> None:
        """Test that extended options default to False."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["host.example.com"])

        assert args.forward_agent is False
        assert args.compress is False
        assert args.forward_x11 is False
        assert args.forward_x11_trusted is False
        assert args.force_tty is False
        assert args.disable_tty is False
        assert args.quiet is False


class TestExtendedOptionsHelpOutput:
    """Tests for extended options in help output."""

    def test_help_shows_extended_options(self) -> None:
        """Test --help shows extended OpenSSH options."""
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
        assert "-A" in result.stdout
        assert "-C" in result.stdout
        assert "-X" in result.stdout
        assert "-Y" in result.stdout
        assert "-t" in result.stdout
        assert "-T" in result.stdout
        assert "-q" in result.stdout
        assert "agent forwarding" in result.stdout.lower()
        assert "compression" in result.stdout.lower()
        assert "x11" in result.stdout.lower()


@pytest.mark.asyncio
async def test_extended_options_passed_to_connection() -> None:
    """
    Test that extended options are passed to SSHConnection.
    """
    import argparse
    from unittest.mock import patch, MagicMock

    from nbs_ssh.__main__ import run_command

    captured_options = {}

    class MockConnection:
        def __init__(self, **kwargs):
            captured_options.update(kwargs)
            # Mock the internal connection for ForwardManager
            self._conn = MagicMock()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def exec(self, command, term_type=None, env=None):
            from nbs_ssh.connection import ExecResult
            captured_options["exec_term_type"] = term_type
            return ExecResult(stdout="hello\n", stderr="", exit_code=0)

    args = argparse.Namespace(
        target="test@localhost",
        command="echo hello",
        port=22,
        login=None,
        identity=None,
        password=True,
        keyboard_interactive=False,
        pkcs11_provider=None,
        events=False,
        no_host_check=True,
        strict_host_key_checking="no",
        timeout=10.0,
        proxy_jump=None,
        proxy_command=None,
        local_forward=None,
        remote_forward=None,
        dynamic_forward=None,
        no_command=False,
        verbose=0,
        forward_agent=True,
        compress=True,
        forward_x11=True,
        forward_x11_trusted=False,
        force_tty=True,
        disable_tty=False,
        quiet=False,
    )

    import nbs_ssh.__main__ as cli_module

    original_getpass = cli_module.getpass.getpass
    cli_module.getpass.getpass = lambda prompt: "test"

    try:
        with patch("nbs_ssh.SSHConnection", MockConnection):
            await run_command(args)

        # Verify extended options were passed to connection
        assert captured_options.get("agent_forwarding") is True
        assert captured_options.get("compression") is True
        assert captured_options.get("x11_forwarding") is True
        # Verify term_type was passed to exec
        assert captured_options.get("exec_term_type") is not None
    finally:
        cli_module.getpass.getpass = original_getpass


class TestSSHConfigIntegration:
    """Tests for SSH config file integration."""

    def test_config_file_option_parsing(self) -> None:
        """Test -F option is parsed correctly."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["-F", "/custom/config", "host.example.com"])

        assert args.config_file == "/custom/config"

    def test_print_config_option_parsing(self) -> None:
        """Test -G option is parsed correctly."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["-G", "host.example.com"])

        assert args.print_config is True

    def test_default_config_file_is_none(self) -> None:
        """Test that config_file defaults to None (use default paths)."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["host.example.com"])

        assert args.config_file is None

    @pytest.mark.asyncio
    async def test_cli_loads_custom_config_file(self) -> None:
        """
        Test CLI loads and applies custom SSH config file.
        """
        import argparse
        import tempfile
        from unittest.mock import patch

        from nbs_ssh.__main__ import run_command

        captured_options = {}

        class MockConnection:
            def __init__(self, **kwargs):
                captured_options.update(kwargs)
                from unittest.mock import MagicMock
                self._conn = MagicMock()

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def exec(self, command, term_type=None, env=None):
                from nbs_ssh.connection import ExecResult
                return ExecResult(stdout="hello\n", stderr="", exit_code=0)

        # Create a temp config file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".config", delete=False) as f:
            f.write("Host myserver\n")
            f.write("    HostName actual.server.com\n")
            f.write("    Port 2222\n")
            f.write("    User admin\n")
            config_path = f.name

        try:
            args = argparse.Namespace(
                target="myserver",
                command="echo hello",
                port=22,  # Default, should be overridden by config
                login=None,
                identity=None,
                password=True,
                keyboard_interactive=False,
                pkcs11_provider=None,
                events=False,
                no_host_check=True,
                strict_host_key_checking="no",
                timeout=30.0,
                proxy_jump=None,
                proxy_command=None,
                local_forward=None,
                remote_forward=None,
                dynamic_forward=None,
                no_command=False,
                verbose=0,
                forward_agent=False,
                compress=False,
                forward_x11=False,
                forward_x11_trusted=False,
                force_tty=False,
                disable_tty=False,
                quiet=False,
                config_file=config_path,
                print_config=False,
            )

            import nbs_ssh.__main__ as cli_module

            original_getpass = cli_module.getpass.getpass
            cli_module.getpass.getpass = lambda prompt: "test"

            try:
                with patch("nbs_ssh.SSHConnection", MockConnection):
                    await run_command(args)

                # Config file should have set hostname to actual.server.com
                assert captured_options.get("host") == "actual.server.com"
                # Config file should have set port to 2222
                assert captured_options.get("port") == 2222
                # Config file should have set username to admin
                assert captured_options.get("username") == "admin"
            finally:
                cli_module.getpass.getpass = original_getpass
        finally:
            import os
            os.unlink(config_path)

    @pytest.mark.asyncio
    async def test_cli_args_override_config(self) -> None:
        """
        Test that CLI arguments override SSH config settings.
        """
        import argparse
        import tempfile
        from unittest.mock import patch

        from nbs_ssh.__main__ import run_command

        captured_options = {}

        class MockConnection:
            def __init__(self, **kwargs):
                captured_options.update(kwargs)
                from unittest.mock import MagicMock
                self._conn = MagicMock()

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def exec(self, command, term_type=None, env=None):
                from nbs_ssh.connection import ExecResult
                return ExecResult(stdout="hello\n", stderr="", exit_code=0)

        # Create a temp config file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".config", delete=False) as f:
            f.write("Host myserver\n")
            f.write("    HostName actual.server.com\n")
            f.write("    Port 2222\n")
            f.write("    User configuser\n")
            config_path = f.name

        try:
            # Set explicit port and user from CLI
            args = argparse.Namespace(
                target="cliuser@myserver",  # User from CLI target
                command="echo hello",
                port=3333,  # Explicit port should override config
                login=None,
                identity=None,
                password=True,
                keyboard_interactive=False,
                pkcs11_provider=None,
                events=False,
                no_host_check=True,
                strict_host_key_checking="no",
                timeout=30.0,
                proxy_jump=None,
                proxy_command=None,
                local_forward=None,
                remote_forward=None,
                dynamic_forward=None,
                no_command=False,
                verbose=0,
                forward_agent=False,
                compress=False,
                forward_x11=False,
                forward_x11_trusted=False,
                force_tty=False,
                disable_tty=False,
                quiet=False,
                config_file=config_path,
                print_config=False,
            )

            import nbs_ssh.__main__ as cli_module

            original_getpass = cli_module.getpass.getpass
            cli_module.getpass.getpass = lambda prompt: "test"

            try:
                with patch("nbs_ssh.SSHConnection", MockConnection):
                    await run_command(args)

                # HostName from config should still apply
                assert captured_options.get("host") == "actual.server.com"
                # CLI port should override config
                assert captured_options.get("port") == 3333
                # CLI user should override config
                assert captured_options.get("username") == "cliuser"
            finally:
                cli_module.getpass.getpass = original_getpass
        finally:
            import os
            os.unlink(config_path)

    @pytest.mark.asyncio
    async def test_cli_login_option_overrides_config(self) -> None:
        """
        Test that -l option overrides SSH config user.
        """
        import argparse
        import tempfile
        from unittest.mock import patch

        from nbs_ssh.__main__ import run_command

        captured_options = {}

        class MockConnection:
            def __init__(self, **kwargs):
                captured_options.update(kwargs)
                from unittest.mock import MagicMock
                self._conn = MagicMock()

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def exec(self, command, term_type=None, env=None):
                from nbs_ssh.connection import ExecResult
                return ExecResult(stdout="hello\n", stderr="", exit_code=0)

        # Create a temp config file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".config", delete=False) as f:
            f.write("Host myserver\n")
            f.write("    User configuser\n")
            config_path = f.name

        try:
            args = argparse.Namespace(
                target="myserver",
                command="echo hello",
                port=22,
                login="loginuser",  # -l option should override config
                identity=None,
                password=True,
                keyboard_interactive=False,
                pkcs11_provider=None,
                events=False,
                no_host_check=True,
                strict_host_key_checking="no",
                timeout=30.0,
                proxy_jump=None,
                proxy_command=None,
                local_forward=None,
                remote_forward=None,
                dynamic_forward=None,
                no_command=False,
                verbose=0,
                forward_agent=False,
                compress=False,
                forward_x11=False,
                forward_x11_trusted=False,
                force_tty=False,
                disable_tty=False,
                quiet=False,
                config_file=config_path,
                print_config=False,
            )

            import nbs_ssh.__main__ as cli_module

            original_getpass = cli_module.getpass.getpass
            cli_module.getpass.getpass = lambda prompt: "test"

            try:
                with patch("nbs_ssh.SSHConnection", MockConnection):
                    await run_command(args)

                # -l option should override config
                assert captured_options.get("username") == "loginuser"
            finally:
                cli_module.getpass.getpass = original_getpass
        finally:
            import os
            os.unlink(config_path)

    @pytest.mark.asyncio
    async def test_config_proxy_jump_applied(self) -> None:
        """
        Test that ProxyJump from config is applied.
        """
        import argparse
        import tempfile
        from unittest.mock import patch

        from nbs_ssh.__main__ import run_command

        captured_options = {}

        class MockConnection:
            def __init__(self, **kwargs):
                captured_options.update(kwargs)
                from unittest.mock import MagicMock
                self._conn = MagicMock()

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def exec(self, command, term_type=None, env=None):
                from nbs_ssh.connection import ExecResult
                return ExecResult(stdout="hello\n", stderr="", exit_code=0)

        # Create a temp config file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".config", delete=False) as f:
            f.write("Host myserver\n")
            f.write("    ProxyJump jumphost.example.com\n")
            config_path = f.name

        try:
            args = argparse.Namespace(
                target="myserver",
                command="echo hello",
                port=22,
                login=None,
                identity=None,
                password=True,
                keyboard_interactive=False,
                pkcs11_provider=None,
                events=False,
                no_host_check=True,
                strict_host_key_checking="no",
                timeout=30.0,
                proxy_jump=None,  # Not set on CLI
                proxy_command=None,
                local_forward=None,
                remote_forward=None,
                dynamic_forward=None,
                no_command=False,
                verbose=0,
                forward_agent=False,
                compress=False,
                forward_x11=False,
                forward_x11_trusted=False,
                force_tty=False,
                disable_tty=False,
                quiet=False,
                config_file=config_path,
                print_config=False,
            )

            import nbs_ssh.__main__ as cli_module

            original_getpass = cli_module.getpass.getpass
            cli_module.getpass.getpass = lambda prompt: "test"

            try:
                with patch("nbs_ssh.SSHConnection", MockConnection):
                    await run_command(args)

                # ProxyJump from config should be applied
                assert captured_options.get("proxy_jump") == "jumphost.example.com"
            finally:
                cli_module.getpass.getpass = original_getpass
        finally:
            import os
            os.unlink(config_path)

    @pytest.mark.asyncio
    async def test_config_forward_agent_applied(self) -> None:
        """
        Test that ForwardAgent from config is applied.
        """
        import argparse
        import tempfile
        from unittest.mock import patch

        from nbs_ssh.__main__ import run_command

        captured_options = {}

        class MockConnection:
            def __init__(self, **kwargs):
                captured_options.update(kwargs)
                from unittest.mock import MagicMock
                self._conn = MagicMock()

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def exec(self, command, term_type=None, env=None):
                from nbs_ssh.connection import ExecResult
                return ExecResult(stdout="hello\n", stderr="", exit_code=0)

        # Create a temp config file with ForwardAgent yes
        with tempfile.NamedTemporaryFile(mode="w", suffix=".config", delete=False) as f:
            f.write("Host myserver\n")
            f.write("    ForwardAgent yes\n")
            config_path = f.name

        try:
            args = argparse.Namespace(
                target="myserver",
                command="echo hello",
                port=22,
                login=None,
                identity=None,
                password=True,
                keyboard_interactive=False,
                pkcs11_provider=None,
                events=False,
                no_host_check=True,
                strict_host_key_checking="no",
                timeout=30.0,
                proxy_jump=None,
                proxy_command=None,
                local_forward=None,
                remote_forward=None,
                dynamic_forward=None,
                no_command=False,
                verbose=0,
                forward_agent=False,  # Not set on CLI
                compress=False,
                forward_x11=False,
                forward_x11_trusted=False,
                force_tty=False,
                disable_tty=False,
                quiet=False,
                config_file=config_path,
                print_config=False,
            )

            import nbs_ssh.__main__ as cli_module

            original_getpass = cli_module.getpass.getpass
            cli_module.getpass.getpass = lambda prompt: "test"

            try:
                with patch("nbs_ssh.SSHConnection", MockConnection):
                    await run_command(args)

                # ForwardAgent from config should be applied
                assert captured_options.get("agent_forwarding") is True
            finally:
                cli_module.getpass.getpass = original_getpass
        finally:
            import os
            os.unlink(config_path)

    @pytest.mark.asyncio
    async def test_print_config_option(self, capsys) -> None:
        """
        Test -G option prints resolved config and exits.
        """
        import argparse
        import tempfile

        from nbs_ssh.__main__ import run_command

        # Create a temp config file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".config", delete=False) as f:
            f.write("Host myserver\n")
            f.write("    HostName actual.server.com\n")
            f.write("    Port 2222\n")
            f.write("    User admin\n")
            f.write("    ForwardAgent yes\n")
            config_path = f.name

        try:
            args = argparse.Namespace(
                target="myserver",
                command=None,
                port=22,
                login=None,
                identity=None,
                password=False,
                keyboard_interactive=False,
                pkcs11_provider=None,
                events=False,
                no_host_check=True,
                strict_host_key_checking="no",
                timeout=30.0,
                proxy_jump=None,
                proxy_command=None,
                local_forward=None,
                remote_forward=None,
                dynamic_forward=None,
                no_command=False,
                verbose=0,
                forward_agent=False,
                compress=False,
                forward_x11=False,
                forward_x11_trusted=False,
                force_tty=False,
                disable_tty=False,
                quiet=False,
                config_file=config_path,
                print_config=True,  # -G option
            )

            exit_code = await run_command(args)
            assert exit_code == 0

            captured = capsys.readouterr()
            assert "host myserver" in captured.out
            assert "hostname actual.server.com" in captured.out
            assert "port 2222" in captured.out
            assert "user admin" in captured.out
            assert "forwardagent yes" in captured.out
        finally:
            import os
            os.unlink(config_path)


class TestSSHConfigHelpOutput:
    """Tests for SSH config options in help output."""

    def test_help_shows_config_options(self) -> None:
        """Test --help shows -F and -G options."""
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
        assert "-F" in result.stdout
        assert "-G" in result.stdout
        assert "config file" in result.stdout.lower()


class TestSSHOptionsParsing:
    """Tests for -o option parsing."""

    def test_parse_ssh_options_simple(self) -> None:
        """Test parsing simple SSH options."""
        from nbs_ssh.__main__ import parse_ssh_options

        result = parse_ssh_options(["BatchMode=yes", "SendEnv=LANG"])
        assert result == {"batchmode": "yes", "sendenv": "LANG"}

    def test_parse_ssh_options_case_insensitive(self) -> None:
        """Test option names are case-insensitive."""
        from nbs_ssh.__main__ import parse_ssh_options

        result = parse_ssh_options(["BATCHMODE=yes", "batchmode=no"])
        # Last value wins
        assert result["batchmode"] == "no"

    def test_parse_ssh_options_empty(self) -> None:
        """Test parsing empty options."""
        from nbs_ssh.__main__ import parse_ssh_options

        result = parse_ssh_options(None)
        assert result == {}

        result = parse_ssh_options([])
        assert result == {}

    def test_parse_ssh_options_invalid_format(self) -> None:
        """Test invalid option format raises ValueError."""
        from nbs_ssh.__main__ import parse_ssh_options

        with pytest.raises(ValueError, match="Invalid SSH option format"):
            parse_ssh_options(["BatchMode"])  # Missing =

    def test_cli_option_parsing(self) -> None:
        """Test -o argument is parsed correctly."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["-o", "BatchMode=yes", "host.example.com"])

        assert args.ssh_options == ["BatchMode=yes"]

    def test_cli_multiple_options(self) -> None:
        """Test multiple -o arguments are collected."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args([
            "-o", "BatchMode=yes",
            "-o", "SendEnv=LANG",
            "-o", "VisualHostKey=yes",
            "host.example.com",
        ])

        assert args.ssh_options == ["BatchMode=yes", "SendEnv=LANG", "VisualHostKey=yes"]


class TestSendEnvSetEnv:
    """Tests for SendEnv and SetEnv options."""

    def test_get_send_env_vars_exact_match(self) -> None:
        """Test SendEnv with exact variable name."""
        import os
        from nbs_ssh.__main__ import get_send_env_vars

        # Set a test env var
        original = os.environ.get("TEST_SENDENV_VAR")
        os.environ["TEST_SENDENV_VAR"] = "test_value"

        try:
            result = get_send_env_vars(["TEST_SENDENV_VAR"])
            assert result.get("TEST_SENDENV_VAR") == "test_value"
        finally:
            if original is None:
                os.environ.pop("TEST_SENDENV_VAR", None)
            else:
                os.environ["TEST_SENDENV_VAR"] = original

    def test_get_send_env_vars_pattern(self) -> None:
        """Test SendEnv with glob pattern."""
        import os
        from nbs_ssh.__main__ import get_send_env_vars

        # Set test env vars
        os.environ["TEST_PATTERN_A"] = "value_a"
        os.environ["TEST_PATTERN_B"] = "value_b"

        try:
            result = get_send_env_vars(["TEST_PATTERN_*"])
            assert "TEST_PATTERN_A" in result
            assert "TEST_PATTERN_B" in result
        finally:
            os.environ.pop("TEST_PATTERN_A", None)
            os.environ.pop("TEST_PATTERN_B", None)

    def test_parse_set_env(self) -> None:
        """Test SetEnv parsing."""
        from nbs_ssh.__main__ import parse_set_env

        result = parse_set_env(["FOO=bar", "BAZ=qux"])
        assert result == {"FOO": "bar", "BAZ": "qux"}

    def test_parse_set_env_empty_value(self) -> None:
        """Test SetEnv with empty value."""
        from nbs_ssh.__main__ import parse_set_env

        result = parse_set_env(["EMPTY=", "NO_EQUALS"])
        assert result["EMPTY"] == ""
        assert result["NO_EQUALS"] == ""


class TestBatchMode:
    """Tests for BatchMode option."""

    @pytest.mark.asyncio
    async def test_batch_mode_fails_on_password_prompt(self) -> None:
        """Test BatchMode=yes fails when password would be needed."""
        import argparse
        from unittest.mock import patch

        from nbs_ssh.__main__ import run_command

        args = argparse.Namespace(
            target="test@localhost",
            command="echo hello",
            port=29999,  # Won't connect anyway
            login=None,
            identity=None,
            password=True,  # Explicitly request password (would prompt)
            keyboard_interactive=False,
            pkcs11_provider=None,
            events=False,
            no_host_check=True,
            strict_host_key_checking="ask",
            timeout=2.0,
            proxy_jump=None,
            proxy_command=None,
            local_forward=None,
            remote_forward=None,
            dynamic_forward=None,
            no_command=False,
            verbose=0,
            forward_agent=False,
            compress=False,
            forward_x11=False,
            forward_x11_trusted=False,
            force_tty=False,
            disable_tty=False,
            quiet=False,
            config_file=None,
            print_config=False,
            ssh_options=["BatchMode=yes"],
        )

        exit_code = await run_command(args)
        assert exit_code == 1  # Should fail due to batch mode

    @pytest.mark.asyncio
    async def test_batch_mode_uses_strict_host_key(self) -> None:
        """Test BatchMode=yes uses STRICT host key policy."""
        import argparse
        from unittest.mock import patch

        from nbs_ssh.__main__ import run_command
        from nbs_ssh import HostKeyPolicy

        captured_policy = None

        class MockConnection:
            def __init__(self, **kwargs):
                nonlocal captured_policy
                captured_policy = kwargs.get("host_key_policy")
                from unittest.mock import MagicMock
                self._conn = MagicMock()

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def exec(self, command, term_type=None, env=None):
                from nbs_ssh.connection import ExecResult
                return ExecResult(stdout="hello\n", stderr="", exit_code=0)

        args = argparse.Namespace(
            target="test@localhost",
            command="echo hello",
            port=22,
            login=None,
            identity="/path/to/fake/key",  # Provide key to avoid password prompt
            password=False,
            keyboard_interactive=False,
            pkcs11_provider=None,
            events=False,
            no_host_check=False,
            strict_host_key_checking="ask",  # Default, but batch mode should override
            timeout=10.0,
            proxy_jump=None,
            proxy_command=None,
            local_forward=None,
            remote_forward=None,
            dynamic_forward=None,
            no_command=False,
            verbose=0,
            forward_agent=False,
            compress=False,
            forward_x11=False,
            forward_x11_trusted=False,
            force_tty=False,
            disable_tty=False,
            quiet=False,
            config_file=None,
            print_config=False,
            ssh_options=["BatchMode=yes"],
        )

        # Need to patch Path.exists for the identity file
        with patch("nbs_ssh.SSHConnection", MockConnection):
            with patch("pathlib.Path.exists", return_value=True):
                await run_command(args)

        # In batch mode with ask policy, should switch to STRICT
        assert captured_policy == HostKeyPolicy.STRICT


class TestVisualHostKey:
    """Tests for VisualHostKey option."""

    def test_generate_visual_host_key(self) -> None:
        """Test visual host key generation produces valid ASCII art."""
        from nbs_ssh.__main__ import generate_visual_host_key
        import asyncssh

        # Generate a test key
        key = asyncssh.generate_private_key("ssh-ed25519")
        public_key = key.convert_to_public()

        art = generate_visual_host_key(public_key)

        # Should have borders
        assert art.startswith("+")
        assert art.endswith("+")
        assert "|" in art

        # Should have start and end markers
        assert "S" in art
        assert "E" in art

        # Should have key type in header
        assert "ssh-ed25519" in art or "ed25519" in art.lower()

    def test_visual_host_key_dimensions(self) -> None:
        """Test visual host key has correct dimensions."""
        from nbs_ssh.__main__ import generate_visual_host_key
        import asyncssh

        key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
        public_key = key.convert_to_public()

        art = generate_visual_host_key(public_key, size=17)
        lines = art.split("\n")

        # Default size is 17 wide, 9 tall (plus 2 border lines = 11 total)
        assert len(lines) == 11  # 9 + 2 borders

        # Each line should be width + 2 (for | borders)
        for line in lines[1:-1]:  # Exclude top/bottom borders
            assert len(line) == 19  # 17 + 2 for |


class TestHashKnownHosts:
    """Tests for HashKnownHosts option."""

    def test_hash_hostname_format(self) -> None:
        """Test that hashed hostnames follow OpenSSH format."""
        from nbs_ssh.host_key import _hash_hostname

        salt = b"12345678901234567890"  # 20 bytes
        result = _hash_hostname("example.com", salt)

        assert result.startswith("|1|")
        parts = result.split("|")
        assert len(parts) == 4
        # Salt and hash should be base64-encoded
        import base64
        base64.b64decode(parts[2])  # Should not raise
        base64.b64decode(parts[3])  # Should not raise

    def test_check_hashed_hostname(self) -> None:
        """Test that hashed hostname verification works."""
        from nbs_ssh.host_key import _hash_hostname, _check_hashed_hostname

        salt = b"abcdefghijklmnopqrst"  # 20 bytes
        hashed = _hash_hostname("myhost.example.com", salt)

        assert _check_hashed_hostname(hashed, "myhost.example.com")
        assert not _check_hashed_hostname(hashed, "other.example.com")


class TestSSHOptionsHelpOutput:
    """Tests for SSH options in help output."""

    def test_help_shows_o_option(self) -> None:
        """Test --help shows -o option."""
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
        assert "-o" in result.stdout
        assert "BatchMode" in result.stdout
        assert "SendEnv" in result.stdout

