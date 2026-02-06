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
    Test CLI prompts for password when no agent or keys are available.
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

    # Mock both agent check and key paths to return nothing
    original_getpass = cli_module.getpass.getpass
    getpass_called = False

    def tracking_getpass(prompt: str) -> str:
        nonlocal getpass_called
        getpass_called = True
        return "test"

    cli_module.getpass.getpass = tracking_getpass

    # Also mock get_agent_available and get_default_key_paths
    import nbs_ssh.__main__

    # Save originals
    from nbs_ssh import get_agent_available, get_default_key_paths

    # Patch to return no auth methods
    nbs_ssh.__main__.get_agent_available = lambda: False
    nbs_ssh.__main__.get_default_key_paths = lambda: []

    try:
        await run_command(args)  # Will fail to connect, that's OK
        assert getpass_called, "Password should be prompted when no agent or keys"
    finally:
        cli_module.getpass.getpass = original_getpass
        nbs_ssh.__main__.get_agent_available = get_agent_available
        nbs_ssh.__main__.get_default_key_paths = get_default_key_paths


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

        async def exec(self, command, term_type=None):
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

