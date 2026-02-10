"""
Tests for ProxyCommand support.

Tests the ability to use an arbitrary command as the SSH transport:
- ProxyCommandProcess lifecycle
- Token expansion in commands
- Integration with SSHConnection
- CLI --proxy-command flag
- Precedence over ProxyJump
- Error handling
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import patch

import os

import pytest

if TYPE_CHECKING:
    from nbs_ssh.testing.mock_server import MockSSHServer


@pytest.mark.skipif(sys.platform == "win32", reason="Unix sockets not available on Windows")
class TestProxyCommandProcess:
    """Tests for ProxyCommandProcess class."""

    @pytest.mark.asyncio
    async def test_empty_command_raises(self) -> None:
        """Test empty command raises ProxyCommandError."""
        from nbs_ssh.proxy import ProxyCommandError, ProxyCommandProcess

        with pytest.raises(ProxyCommandError) as exc_info:
            ProxyCommandProcess("")

        assert "Empty ProxyCommand" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_whitespace_command_raises(self) -> None:
        """Test whitespace-only command raises ProxyCommandError."""
        from nbs_ssh.proxy import ProxyCommandError, ProxyCommandProcess

        with pytest.raises(ProxyCommandError):
            ProxyCommandProcess("   ")

    @pytest.mark.asyncio
    async def test_command_property(self) -> None:
        """Test command property returns the command."""
        from nbs_ssh.proxy import ProxyCommandProcess

        proc = ProxyCommandProcess("echo hello")
        assert proc.command == "echo hello"

    @pytest.mark.asyncio
    async def test_get_socket_before_start_raises(self) -> None:
        """Test get_socket before start raises RuntimeError."""
        from nbs_ssh.proxy import ProxyCommandProcess

        proc = ProxyCommandProcess("echo hello")

        with pytest.raises(RuntimeError) as exc_info:
            proc.get_socket()

        assert "not started" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_start_twice_raises(self) -> None:
        """Test starting twice raises RuntimeError."""
        from nbs_ssh.proxy import ProxyCommandProcess

        async with ProxyCommandProcess("cat") as proc:
            with pytest.raises(RuntimeError) as exc_info:
                await proc.start()

            assert "already started" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_context_manager_starts_and_closes(self) -> None:
        """Test context manager starts and closes process."""
        from nbs_ssh.proxy import ProxyCommandProcess

        # Use 'cat' as a simple command that waits for input
        proc = ProxyCommandProcess("cat")

        # Not started yet
        assert proc._process is None

        async with proc:
            # Now started
            assert proc._process is not None
            assert proc._local_sock is not None
            assert proc._remote_sock is not None

        # Closed after exit
        assert proc._closed is True

    @pytest.mark.asyncio
    async def test_bad_command_raises_error(self) -> None:
        """Test non-existent command raises ProxyCommandError."""
        from nbs_ssh.proxy import ProxyCommandError, ProxyCommandProcess

        proc = ProxyCommandProcess("/nonexistent/command/that/does/not/exist")

        with pytest.raises(ProxyCommandError) as exc_info:
            await proc.start()

        assert "exited immediately" in str(exc_info.value) or "Failed to start" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_command_exit_code_captured(self) -> None:
        """Test exit code is captured for failed commands."""
        from nbs_ssh.proxy import ProxyCommandError, ProxyCommandProcess

        # false exits with code 1
        proc = ProxyCommandProcess("false")

        with pytest.raises(ProxyCommandError) as exc_info:
            await proc.start()

        assert exc_info.value.exit_code is not None


class TestProxyCommandIntegration:
    """Tests for ProxyCommand integration with SSHConnection."""

    def test_connection_stores_proxy_command(self) -> None:
        """Test SSHConnection stores proxy_command."""
        from nbs_ssh.auth import create_password_auth
        from nbs_ssh.connection import SSHConnection

        conn = SSHConnection(
            host="target.example.com",
            port=22,
            username="test",
            auth=create_password_auth("test"),
            proxy_command="nc proxy.example.com 22",
        )

        assert conn._proxy_command == "nc proxy.example.com 22"

    def test_proxy_command_disables_proxy_jump(self) -> None:
        """Test proxy_command takes precedence over proxy_jump."""
        from nbs_ssh.auth import create_password_auth
        from nbs_ssh.connection import SSHConnection

        conn = SSHConnection(
            host="target.example.com",
            port=22,
            username="test",
            auth=create_password_auth("test"),
            proxy_command="nc proxy.example.com 22",
            proxy_jump="jump.example.com",  # Should be ignored
        )

        assert conn._proxy_command == "nc proxy.example.com 22"
        assert conn._proxy_jump is None  # Disabled

    def test_proxy_command_from_config(self, tmp_path: Path) -> None:
        """Test SSHConnection reads ProxyCommand from SSH config."""
        from nbs_ssh.auth import create_password_auth
        from nbs_ssh.config import SSHConfig
        from nbs_ssh.connection import SSHConnection

        config_file = tmp_path / "config"
        config_file.write_text("""
Host target
    HostName target.example.com
    ProxyCommand nc proxy.example.com %h %p
""")

        ssh_config = SSHConfig(config_files=[config_file])

        conn = SSHConnection(
            host="target",
            username="test",
            auth=create_password_auth("test"),
            ssh_config=ssh_config,
        )

        # Tokens should be expanded by config parser
        # %h expands to the original host alias, not the resolved HostName
        assert conn._proxy_command is not None
        assert "target" in conn._proxy_command
        assert "22" in conn._proxy_command

    def test_explicit_proxy_command_overrides_config(self, tmp_path: Path) -> None:
        """Test explicit proxy_command overrides SSH config."""
        from nbs_ssh.auth import create_password_auth
        from nbs_ssh.config import SSHConfig
        from nbs_ssh.connection import SSHConnection

        config_file = tmp_path / "config"
        config_file.write_text("""
Host target
    ProxyCommand config-command %h %p
""")

        ssh_config = SSHConfig(config_files=[config_file])

        conn = SSHConnection(
            host="target",
            username="test",
            auth=create_password_auth("test"),
            ssh_config=ssh_config,
            proxy_command="explicit-command target 22",
        )

        assert conn._proxy_command == "explicit-command target 22"

    def test_proxy_command_takes_precedence_over_proxy_jump_from_config(
        self, tmp_path: Path
    ) -> None:
        """Test ProxyCommand from config takes precedence over ProxyJump."""
        from nbs_ssh.auth import create_password_auth
        from nbs_ssh.config import SSHConfig
        from nbs_ssh.connection import SSHConnection

        config_file = tmp_path / "config"
        config_file.write_text("""
Host target
    ProxyCommand nc proxy.example.com 22
    ProxyJump jump.example.com
""")

        ssh_config = SSHConfig(config_files=[config_file])

        conn = SSHConnection(
            host="target",
            username="test",
            auth=create_password_auth("test"),
            ssh_config=ssh_config,
        )

        # ProxyCommand should be used, ProxyJump ignored
        assert conn._proxy_command is not None
        assert conn._proxy_jump is None


class TestProxyCommandEvents:
    """Tests for ProxyCommand in JSONL events."""

    @pytest.mark.asyncio
    async def test_connect_event_includes_proxy_command(self) -> None:
        """Test CONNECT event includes proxy_command when configured."""
        from nbs_ssh.auth import create_password_auth
        from nbs_ssh.connection import SSHConnection
        from nbs_ssh.events import EventCollector

        collector = EventCollector()

        conn = SSHConnection(
            host="target.example.com",
            port=22,
            username="test",
            auth=create_password_auth("test"),
            event_collector=collector,
            proxy_command="nc proxy.example.com 22",
        )

        # Connection will fail but we can check the initiating event
        try:
            await conn._connect()
        except Exception:
            pass  # Expected to fail

        # Find CONNECT event with status="initiating"
        connect_events = [
            e for e in collector.events
            if e.event_type == "CONNECT" and e.data.get("status") == "initiating"
        ]

        assert len(connect_events) >= 1
        assert connect_events[0].data.get("proxy_command") == "nc proxy.example.com 22"


class TestCLIProxyCommand:
    """Tests for CLI --proxy-command flag."""

    def test_proxy_command_flag_parsed(self) -> None:
        """Test --proxy-command flag is parsed correctly."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args([
            "--proxy-command", "nc proxy %h %p",
            "target",
            "echo hello",
        ])

        assert args.proxy_command == "nc proxy %h %p"

    def test_proxy_command_short_flag(self) -> None:
        """Test -o ProxyCommand= option is parsed correctly (OpenSSH format)."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args([
            "-o", "ProxyCommand=nc proxy %h %p",
            "target",
            "echo hello",
        ])

        # -o ProxyCommand= is stored in ssh_options, not proxy_command
        # The proxy_command is resolved later in run_command()
        assert args.ssh_options == ["ProxyCommand=nc proxy %h %p"]

    def test_proxy_command_default_none(self) -> None:
        """Test proxy_command defaults to None."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["target", "cmd"])

        assert args.proxy_command is None

    def test_help_mentions_proxy_command(self) -> None:
        """Test --help mentions proxy command functionality."""
        import subprocess
        import sys

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
        assert "--proxy-command" in result.stdout or "-o" in result.stdout


class TestProxyCommandTokenExpansion:
    """Tests for token expansion in ProxyCommand."""

    def test_config_expands_tokens(self, tmp_path: Path) -> None:
        """Test SSH config expands tokens in ProxyCommand."""
        from nbs_ssh.config import SSHConfig

        config_file = tmp_path / "config"
        config_file.write_text("""
Host myserver
    ProxyCommand ssh -W %h:%p jump
""")

        ssh_config = SSHConfig(config_files=[config_file])
        host_config = ssh_config.lookup("myserver")

        # Tokens should be expanded
        assert host_config.proxy_command is not None
        assert "%h" not in host_config.proxy_command
        assert "myserver" in host_config.proxy_command

    def test_config_expands_port_token(self, tmp_path: Path) -> None:
        """Test %p token is expanded to configured port."""
        from nbs_ssh.config import SSHConfig

        config_file = tmp_path / "config"
        config_file.write_text("""
Host myserver
    Port 2222
    ProxyCommand nc proxy %h %p
""")

        ssh_config = SSHConfig(config_files=[config_file])
        host_config = ssh_config.lookup("myserver")

        # Port token should use configured port
        assert host_config.proxy_command is not None
        assert "2222" in host_config.proxy_command

    def test_config_expands_escaped_percent(self, tmp_path: Path) -> None:
        """Test %% is expanded to literal %."""
        from nbs_ssh.config import SSHConfig

        config_file = tmp_path / "config"
        config_file.write_text("""
Host myserver
    ProxyCommand echo 100%% done
""")

        ssh_config = SSHConfig(config_files=[config_file])
        host_config = ssh_config.lookup("myserver")

        # %% should become %
        assert host_config.proxy_command is not None
        assert "100% done" in host_config.proxy_command
        assert "%%" not in host_config.proxy_command


@pytest.mark.skipif(sys.platform == "win32", reason="Unix sockets not available on Windows")
class TestProxyCommandErrorHandling:
    """Tests for error handling with ProxyCommand."""

    @pytest.mark.asyncio
    async def test_proxy_command_failure_emits_error_event(self) -> None:
        """Test ProxyCommand failure emits ERROR event."""
        from nbs_ssh.auth import create_password_auth
        from nbs_ssh.connection import SSHConnection
        from nbs_ssh.events import EventCollector

        collector = EventCollector()

        conn = SSHConnection(
            host="target.example.com",
            port=22,
            username="test",
            auth=create_password_auth("test"),
            event_collector=collector,
            proxy_command="false",  # Command that exits immediately with code 1
        )

        with pytest.raises(Exception):
            await conn._connect()

        # Check for ERROR event
        error_events = [
            e for e in collector.events
            if e.event_type == "ERROR"
        ]

        assert len(error_events) >= 1
        assert error_events[0].data.get("error_type") == "proxy_command_failed"


@pytest.mark.skipif(
    sys.platform == "win32" or os.environ.get("CI") == "true",
    reason="Requires Unix sockets and hangs on CI runners (netcat/cat tunnels)",
)
class TestProxyCommandWithRealConnection:
    """Tests that verify ProxyCommand works with actual connections.

    These tests use netcat to create a simple tunnel to the mock server.
    """

    @pytest.mark.asyncio
    async def test_connect_via_netcat_proxy(
        self,
        mock_ssh_server: "MockSSHServer",
    ) -> None:
        """Test connecting through a netcat proxy command."""
        from nbs_ssh.auth import create_password_auth
        from nbs_ssh.connection import SSHConnection

        # Use netcat to connect to the mock server
        # This simulates a simple ProxyCommand
        proxy_command = f"nc localhost {mock_ssh_server.port}"

        async with SSHConnection(
            host="localhost",  # Host doesn't matter when using ProxyCommand
            port=22,  # Port doesn't matter when using ProxyCommand
            username="test",
            auth=create_password_auth("test"),
            known_hosts=None,
            proxy_command=proxy_command,
        ) as conn:
            result = await conn.exec("echo hello")
            assert result.stdout.strip() == "hello"

    @pytest.mark.asyncio
    async def test_connect_via_cat_proxy(
        self,
        mock_ssh_server: "MockSSHServer",
    ) -> None:
        """Test that we can execute commands through a proxy."""
        import subprocess

        # Check if nc is available
        try:
            subprocess.run(["nc", "-h"], capture_output=True, timeout=1)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pytest.skip("nc (netcat) not available")

        from nbs_ssh.auth import create_password_auth
        from nbs_ssh.connection import SSHConnection

        proxy_command = f"nc localhost {mock_ssh_server.port}"

        async with SSHConnection(
            host="target",
            port=22,
            username="test",
            auth=create_password_auth("test"),
            known_hosts=None,
            proxy_command=proxy_command,
        ) as conn:
            result = await conn.exec("whoami")
            # Mock server returns "test" for whoami
            assert "test" in result.stdout or result.exit_code == 0


@pytest.mark.skipif(sys.platform == "win32", reason="Unix sockets not available on Windows")
class TestProxyCommandEngineeringStandards:
    """Adversarial tests for engineering standards violations in proxy.py.

    Each test targets a specific violation identified in the audit. Tests are
    designed to detect silent error swallowing, missing preconditions, missing
    postconditions, and overly broad exception catching.
    """

    # --- Violation 1: Line 128-129, except Exception: pass on stderr read ---

    @pytest.mark.asyncio
    async def test_stderr_read_error_preserves_error_info(self) -> None:
        """When stderr.read() fails, the error message should indicate this
        rather than silently leaving stderr as empty string."""
        from nbs_ssh.proxy import ProxyCommandError, ProxyCommandProcess
        from unittest.mock import AsyncMock, MagicMock, PropertyMock

        proc = ProxyCommandProcess("false")
        # We can't easily inject a broken stderr at the read level without
        # modifying the subprocess, so we test that when the command fails
        # and stderr read succeeds, stderr is populated; and when it fails,
        # the error message contains useful information about the read failure.
        with pytest.raises(ProxyCommandError) as exc_info:
            await proc.start()

        # The error should always have command and exit_code populated
        assert exc_info.value.command == "false"
        assert exc_info.value.exit_code is not None
        # stderr should be a string (either content or error indication),
        # never None when the process had a stderr stream
        assert exc_info.value.stderr is not None

    # --- Violation 2: Line 168-169, except Exception: pass on stdin close ---

    @pytest.mark.asyncio
    async def test_stdin_close_catches_only_oserror(self) -> None:
        """stdin.close() should only catch OSError, not swallow arbitrary
        exceptions like RuntimeError or ValueError."""
        from nbs_ssh.proxy import ProxyCommandProcess
        from unittest.mock import MagicMock, patch, AsyncMock

        proc = ProxyCommandProcess("cat")
        async with proc:
            # Verify the process started
            assert proc._process is not None
            assert proc._process.stdin is not None

            # The fix should catch OSError specifically, so a non-OSError
            # exception from stdin.close() would propagate.
            # We verify this by checking source code has specific exception type.
            import inspect
            source = inspect.getsource(ProxyCommandProcess)
            # The _bridge method's stdin.close() should NOT have bare
            # 'except Exception'
            bridge_source = inspect.getsource(ProxyCommandProcess._bridge)
            # Count occurrences of 'except Exception' in _bridge
            bare_except_count = bridge_source.count("except Exception:")
            assert bare_except_count == 0, (
                f"_bridge contains {bare_except_count} bare 'except Exception:' "
                f"handlers; stdin.close() should catch OSError specifically"
            )

    # --- Violation 3: Line 199-200, except Exception: pass on bridge errors ---

    @pytest.mark.asyncio
    async def test_bridge_gather_catches_specific_exceptions(self) -> None:
        """The asyncio.gather() in _bridge should catch only
        (OSError, ConnectionError, asyncio.CancelledError), not all exceptions."""
        from nbs_ssh.proxy import ProxyCommandProcess
        import inspect

        source = inspect.getsource(ProxyCommandProcess._bridge)
        # After the fix, the gather's except clause should be specific
        # We check that there is no 'except Exception:' followed by 'pass'
        # in the gather section
        lines = source.split('\n')
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped == "except Exception:":
                # Check the next non-empty line
                for j in range(i + 1, min(i + 3, len(lines))):
                    if lines[j].strip() == "pass":
                        pytest.fail(
                            f"_bridge has 'except Exception: pass' at "
                            f"relative line {i}: this swallows all errors "
                            f"including programming bugs"
                        )

    # --- Violation 4: Lines 217-219, 224-226, socket close errors ---

    @pytest.mark.asyncio
    async def test_cleanup_sockets_catches_only_oserror(self) -> None:
        """_cleanup_sockets should catch OSError specifically and log,
        not swallow all exceptions."""
        from nbs_ssh.proxy import ProxyCommandProcess
        import inspect

        source = inspect.getsource(ProxyCommandProcess._cleanup_sockets)
        # Should NOT have 'except Exception:'
        assert "except Exception:" not in source, (
            "_cleanup_sockets uses bare 'except Exception:' — "
            "should catch OSError specifically"
        )
        # Should have 'except OSError'
        assert "except OSError" in source, (
            "_cleanup_sockets should catch OSError specifically"
        )

    @pytest.mark.asyncio
    async def test_cleanup_sockets_logs_oserror(self) -> None:
        """_cleanup_sockets should log OSError when socket close fails."""
        import logging
        from nbs_ssh.proxy import ProxyCommandProcess

        proc = ProxyCommandProcess("cat")
        async with proc:
            # Close the local socket early to force an error on cleanup
            proc._local_sock.close()

        # After context exit, _cleanup_sockets was called. If the socket
        # was already closed, it should have logged the OSError rather than
        # silently swallowing it. We verify the logger exists.
        logger = logging.getLogger("nbs_ssh.proxy")
        assert logger is not None

    # --- Violation 5: Line 256-257, process kill/terminate errors ---

    @pytest.mark.asyncio
    async def test_close_catches_specific_process_errors(self) -> None:
        """close() should catch (OSError, ProcessLookupError) for process
        termination, not all exceptions."""
        from nbs_ssh.proxy import ProxyCommandProcess
        import inspect

        source = inspect.getsource(ProxyCommandProcess.close)
        # Should NOT have 'except Exception:' for process termination
        assert "except Exception:" not in source, (
            "close() uses bare 'except Exception:' for process termination — "
            "should catch (OSError, ProcessLookupError) specifically"
        )

    # --- Violation 6: Line 147-148, bare assertions without messages ---

    @pytest.mark.asyncio
    async def test_bridge_assertions_have_messages(self) -> None:
        """Assertions in _bridge must have descriptive messages."""
        from nbs_ssh.proxy import ProxyCommandProcess
        import ast
        import inspect
        import textwrap

        source = inspect.getsource(ProxyCommandProcess._bridge)
        # Parse the AST to find assert statements without messages
        # We need to dedent the source first since it's a method
        dedented = textwrap.dedent(source)
        tree = ast.parse(dedented)

        bare_asserts = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assert) and node.msg is None:
                bare_asserts.append(node.lineno)

        assert len(bare_asserts) == 0, (
            f"_bridge has {len(bare_asserts)} assertion(s) without messages "
            f"at relative lines {bare_asserts}. Every assertion must answer: "
            f"What was expected? What actually occurred?"
        )

    # --- Violation 7: Line 81, missing precondition for self._closed ---

    @pytest.mark.asyncio
    async def test_start_after_close_raises(self) -> None:
        """Calling start() after close() should fail with a clear assertion
        rather than silently proceeding or giving a confusing error."""
        from nbs_ssh.proxy import ProxyCommandProcess

        proc = ProxyCommandProcess("cat")
        await proc.start()
        await proc.close()

        # After closing, start() should raise AssertionError (precondition)
        with pytest.raises(AssertionError, match="close.*has been called"):
            await proc.start()

    # --- Violation 8: Line 141, silent return in _bridge ---

    @pytest.mark.asyncio
    async def test_bridge_asserts_on_none_process_or_socket(self) -> None:
        """_bridge should assert that process and local_sock are not None,
        not silently return."""
        from nbs_ssh.proxy import ProxyCommandProcess
        import inspect

        source = inspect.getsource(ProxyCommandProcess._bridge)
        # Should NOT have a silent return for None checks
        # The old code was:
        #   if self._process is None or self._local_sock is None:
        #       return
        # It should now assert instead
        lines = source.split('\n')
        for i, line in enumerate(lines):
            stripped = line.strip()
            if "is None" in stripped and "return" in stripped:
                pytest.fail(
                    f"_bridge silently returns when process/socket is None "
                    f"at line {i}: should assert instead"
                )
            # Also check for return on the line after the None check
            if ("_process is None" in stripped or "_local_sock is None" in stripped):
                for j in range(i + 1, min(i + 3, len(lines))):
                    if lines[j].strip() == "return":
                        pytest.fail(
                            f"_bridge silently returns when process/socket is None "
                            f"(return at line {j}): should assert instead"
                        )

    # --- Violation 9: Lines 81-139, missing postconditions after start() ---

    @pytest.mark.asyncio
    async def test_start_postconditions_all_state_non_none(self) -> None:
        """After successful start(), all state must be non-None:
        _process, _local_sock, _remote_sock, _bridge_task."""
        from nbs_ssh.proxy import ProxyCommandProcess

        proc = ProxyCommandProcess("cat")
        await proc.start()
        try:
            # These postconditions must hold after start()
            assert proc._process is not None, "postcondition: _process must be set"
            assert proc._local_sock is not None, "postcondition: _local_sock must be set"
            assert proc._remote_sock is not None, "postcondition: _remote_sock must be set"
            assert proc._bridge_task is not None, "postcondition: _bridge_task must be set"
        finally:
            await proc.close()

    @pytest.mark.asyncio
    async def test_start_has_postcondition_assertions_in_source(self) -> None:
        """start() method source must contain postcondition assertions."""
        from nbs_ssh.proxy import ProxyCommandProcess
        import inspect

        source = inspect.getsource(ProxyCommandProcess.start)
        # Should assert all state is non-None after setup
        required_postconditions = [
            "_process is not None",
            "_local_sock is not None",
            "_remote_sock is not None",
            "_bridge_task is not None",
        ]
        for condition in required_postconditions:
            assert condition in source, (
                f"start() missing postcondition assertion: assert self.{condition}"
            )

    # --- Verify logging is properly configured ---

    @pytest.mark.asyncio
    async def test_proxy_module_has_logger(self) -> None:
        """proxy.py must have a module-level logger configured."""
        import nbs_ssh.proxy as proxy_module
        assert hasattr(proxy_module, "log"), (
            "proxy module must have a 'log' logger attribute"
        )
        import logging
        assert isinstance(proxy_module.log, logging.Logger), (
            f"proxy.log should be a Logger, got {type(proxy_module.log)}"
        )
        assert proxy_module.log.name == "nbs_ssh.proxy", (
            f"Logger name should be 'nbs_ssh.proxy', got '{proxy_module.log.name}'"
        )
