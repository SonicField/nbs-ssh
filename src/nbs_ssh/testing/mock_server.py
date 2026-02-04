"""
Mock SSH server for falsifiable integration testing.

Provides:
- MockServerConfig: Configuration for mock server behaviours
- MockSSHServer: Async context manager that runs a configurable SSH server

The mock server supports:
- Port 0 binding with dynamic port allocation
- Configurable attack behaviours for security testing
- JSONL event logging for debugging
- Full AsyncSSH server implementation

Example:
    async with MockSSHServer(config) as server:
        async with SSHConnection(
            host="localhost",
            port=server.port,
            username="test",
            password="test",
        ) as conn:
            result = await conn.exec("echo hello")
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any, Callable

import asyncssh
from asyncssh import SSHKey

from nbs_ssh.events import Event, EventCollector, EventType


@dataclass
class MockServerConfig:
    """
    Configuration for mock SSH server behaviours.

    Supports various attack and chaos scenarios for falsification testing.

    Attributes:
        username: Username to accept (default: "test")
        password: Password to accept (default: "test")
        host_key_path: Path to host key (auto-generated if None)
        delay_auth: Delay in seconds before auth response
        delay_channel: Delay in seconds before channel open
        reject_ciphers: Ciphers to reject during negotiation
        reject_kex: Key exchange algorithms to reject
        reject_macs: MAC algorithms to reject
        drop_after_bytes: Close connection after N bytes sent
        drop_after_seconds: Close connection after N seconds
        send_malformed: Send protocol-invalid data
        auth_attempts_before_success: Fail N times then succeed
        command_exit_codes: Map commands to exit codes
        command_outputs: Map commands to (stdout, stderr)
        slow_output_bytes_per_sec: Throttle command output
        only_offer_ciphers: Only offer these ciphers (for security tests)
        only_offer_kex: Only offer these KEX algorithms
        only_offer_macs: Only offer these MAC algorithms
    """
    username: str = "test"
    password: str = "test"
    host_key_path: Path | None = None

    # Timing behaviours
    delay_auth: float = 0.0
    delay_channel: float = 0.0

    # Algorithm rejection
    reject_ciphers: list[str] = field(default_factory=list)
    reject_kex: list[str] = field(default_factory=list)
    reject_macs: list[str] = field(default_factory=list)

    # Algorithm offering (for security tests)
    only_offer_ciphers: list[str] | None = None
    only_offer_kex: list[str] | None = None
    only_offer_macs: list[str] | None = None

    # Chaos behaviours
    drop_after_bytes: int | None = None
    drop_after_seconds: float | None = None
    send_malformed: bool = False
    auth_attempts_before_success: int = 0

    # Command behaviours
    command_exit_codes: dict[str, int] = field(default_factory=dict)
    command_outputs: dict[str, tuple[str, str]] = field(default_factory=dict)
    slow_output_bytes_per_sec: int | None = None
    execute_commands: bool = False  # Actually execute commands via shell

    def __post_init__(self) -> None:
        """Validate configuration."""
        assert self.delay_auth >= 0, f"delay_auth must be >= 0, got {self.delay_auth}"
        assert self.delay_channel >= 0, f"delay_channel must be >= 0, got {self.delay_channel}"
        if self.drop_after_bytes is not None:
            assert self.drop_after_bytes > 0, \
                f"drop_after_bytes must be > 0, got {self.drop_after_bytes}"
        if self.drop_after_seconds is not None:
            assert self.drop_after_seconds > 0, \
                f"drop_after_seconds must be > 0, got {self.drop_after_seconds}"
        assert self.auth_attempts_before_success >= 0, \
            f"auth_attempts_before_success must be >= 0, got {self.auth_attempts_before_success}"


class MockSSHServerProtocol(asyncssh.SSHServer):
    """
    SSH server protocol handler with configurable behaviours.

    Implements AsyncSSH's SSHServer interface with support for:
    - Password authentication with optional delay and failures
    - Algorithm negotiation logging
    - Connection lifecycle logging
    """

    def __init__(
        self,
        config: MockServerConfig,
        emitter: "MockServerEventEmitter",
    ) -> None:
        """
        Initialise the protocol handler.

        Args:
            config: Server behaviour configuration
            emitter: Event emitter for logging
        """
        self._config = config
        self._emitter = emitter
        self._auth_attempts = 0
        self._conn: asyncssh.SSHServerConnection | None = None

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        """Called when connection is established."""
        self._conn = conn
        self._emitter.emit(
            "SERVER_CONNECT",
            peer=str(conn.get_extra_info("peername")),
        )

    def connection_lost(self, exc: Exception | None) -> None:
        """Called when connection is lost."""
        self._emitter.emit(
            "SERVER_DISCONNECT",
            error=str(exc) if exc else None,
        )

    def begin_auth(self, username: str) -> bool:
        """
        Handle start of authentication.

        Returns True if auth is required, False to skip auth entirely.
        """
        self._emitter.emit(
            "SERVER_AUTH_BEGIN",
            username=username,
            expected_username=self._config.username,
        )
        return True  # Always require auth

    def password_auth_supported(self) -> bool:
        """Indicate that password auth is supported."""
        return True

    async def validate_password(self, username: str, password: str) -> bool:
        """
        Validate password authentication.

        Supports:
        - Configurable delay before response
        - Configurable number of failures before success
        """
        self._auth_attempts += 1

        # Apply delay if configured
        if self._config.delay_auth > 0:
            await asyncio.sleep(self._config.delay_auth)

        # Check if we should fail this attempt
        if self._auth_attempts <= self._config.auth_attempts_before_success:
            self._emitter.emit(
                "SERVER_AUTH",
                username=username,
                method="password",
                success=False,
                attempt=self._auth_attempts,
                reason="configured_failure",
            )
            return False

        # Check credentials
        valid = (
            username == self._config.username and
            password == self._config.password
        )

        self._emitter.emit(
            "SERVER_AUTH",
            username=username,
            method="password",
            success=valid,
            attempt=self._auth_attempts,
            reason="credentials_match" if valid else "invalid_credentials",
        )

        return valid

    def public_key_auth_supported(self) -> bool:
        """Indicate that public key auth is supported (for future use)."""
        return False  # Not implemented yet


async def handle_mock_process(
    process: asyncssh.SSHServerProcess,
    config: MockServerConfig,
    emitter: "MockServerEventEmitter",
) -> None:
    """
    Handle command execution on mock server.

    This is called as the process_factory for each exec request.

    Supports:
    - Configurable command outputs
    - Configurable exit codes
    - Output throttling
    - Default echo behaviour
    - Real command execution (when execute_commands=True)
    """
    command = process.command or ""

    emitter.emit(
        "SERVER_EXEC",
        command=command,
    )

    # If execute_commands is enabled, actually run the command
    if config.execute_commands:
        await _execute_real_command(process, command, emitter)
        return

    # Check for configured output
    if command in config.command_outputs:
        stdout, stderr = config.command_outputs[command]
    else:
        # Default: echo-like behaviour for "echo" commands
        if command.startswith("echo "):
            stdout = command[5:] + "\n"
            stderr = ""
        elif command == "whoami":
            stdout = config.username + "\n"
            stderr = ""
        else:
            stdout = ""
            stderr = ""

    # Get exit code
    exit_code = config.command_exit_codes.get(command, 0)

    # Apply output throttling if configured
    if config.slow_output_bytes_per_sec and stdout:
        bytes_per_chunk = max(1, config.slow_output_bytes_per_sec // 10)
        delay_per_chunk = 0.1

        for i in range(0, len(stdout), bytes_per_chunk):
            chunk = stdout[i:i + bytes_per_chunk]
            process.stdout.write(chunk)
            await asyncio.sleep(delay_per_chunk)
    else:
        if stdout:
            process.stdout.write(stdout)

    if stderr:
        process.stderr.write(stderr)

    emitter.emit(
        "SERVER_EXEC_COMPLETE",
        command=command,
        exit_code=exit_code,
        stdout_len=len(stdout),
        stderr_len=len(stderr),
    )

    process.exit(exit_code)


async def _execute_real_command(
    process: asyncssh.SSHServerProcess,
    command: str,
    emitter: "MockServerEventEmitter",
) -> None:
    """
    Execute a command via shell and stream output to the SSH process.

    This provides real command execution with proper streaming,
    allowing tests to verify streaming behaviour without Docker.
    """
    try:
        # Create subprocess with pipes for stdout/stderr
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        async def stream_output(
            stream: asyncio.StreamReader | None,
            writer: asyncssh.SSHWriter,
            stream_name: str,
        ) -> int:
            """Stream from subprocess to SSH process, return bytes written."""
            if stream is None:
                return 0
            total_bytes = 0
            while True:
                # Read in small chunks for realistic streaming
                chunk = await stream.read(64)
                if not chunk:
                    break
                writer.write(chunk.decode("utf-8", errors="replace"))
                total_bytes += len(chunk)
                # Small yield to allow interleaving
                await asyncio.sleep(0)
            return total_bytes

        # Stream stdout and stderr concurrently
        stdout_task = asyncio.create_task(
            stream_output(proc.stdout, process.stdout, "stdout")
        )
        stderr_task = asyncio.create_task(
            stream_output(proc.stderr, process.stderr, "stderr")
        )

        stdout_bytes, stderr_bytes = await asyncio.gather(stdout_task, stderr_task)

        # Wait for process to complete
        exit_code = await proc.wait()

        emitter.emit(
            "SERVER_EXEC_COMPLETE",
            command=command,
            exit_code=exit_code,
            stdout_len=stdout_bytes,
            stderr_len=stderr_bytes,
        )

        process.exit(exit_code)

    except Exception as e:
        emitter.emit(
            "SERVER_EXEC_ERROR",
            command=command,
            error=str(e),
        )
        process.stderr.write(f"Error executing command: {e}\n")
        process.exit(1)


class MockServerEventEmitter:
    """
    Event emitter for mock server logging.

    Writes JSONL events matching the client event format for
    unified log analysis.
    """

    def __init__(
        self,
        collector: EventCollector | None = None,
        jsonl_path: Path | str | None = None,
    ) -> None:
        """
        Initialise the emitter.

        Args:
            collector: Optional in-memory event collector
            jsonl_path: Optional path for JSONL file output
        """
        self._collector = collector
        self._jsonl_path = Path(jsonl_path) if jsonl_path else None
        self._file: IO[str] | None = None

    def open(self) -> None:
        """Open JSONL file for writing."""
        if self._jsonl_path:
            self._jsonl_path.parent.mkdir(parents=True, exist_ok=True)
            self._file = open(self._jsonl_path, "a", encoding="utf-8")

    def close(self) -> None:
        """Close JSONL file."""
        if self._file:
            self._file.close()
            self._file = None

    def emit(self, event_type: str, **data: Any) -> None:
        """
        Emit an event.

        Args:
            event_type: Type of event (SERVER_* types)
            **data: Event-specific data
        """
        timestamp_ms = time.time() * 1000
        event_dict = {
            "event_type": event_type,
            "timestamp": timestamp_ms,
            "data": data,
        }

        if self._collector:
            # Create Event objects for collection
            # Note: We use the raw event_type which may not be in EventType enum
            # This is intentional - server events are distinct from client events
            self._collector._events.append(
                _MockEvent(event_type=event_type, timestamp=timestamp_ms, data=data)
            )

        if self._file:
            self._file.write(json.dumps(event_dict) + "\n")
            self._file.flush()


@dataclass
class _MockEvent:
    """
    Mock event for server-side logging.

    Similar to Event but doesn't validate event_type against client EventType enum.
    """
    event_type: str
    timestamp: float
    data: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        """Serialise to JSON."""
        return json.dumps({
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "data": self.data,
        })


class MockSSHServer:
    """
    Async context manager for running a mock SSH server.

    Binds to port 0 for dynamic port allocation, making tests
    parallelisable without port conflicts.

    Usage:
        config = MockServerConfig(username="test", password="test")
        async with MockSSHServer(config) as server:
            # server.port contains the assigned port
            async with SSHConnection(..., port=server.port) as conn:
                result = await conn.exec("echo hello")

            # Access server logs
            for event in server.events:
                print(event)
    """

    def __init__(
        self,
        config: MockServerConfig | None = None,
        event_collector: EventCollector | None = None,
        event_log_path: Path | str | None = None,
    ) -> None:
        """
        Initialise mock server.

        Args:
            config: Server behaviour configuration (default: basic auth)
            event_collector: Optional in-memory event collector
            event_log_path: Optional path for JSONL event log
        """
        self._config = config or MockServerConfig()
        self._event_collector = event_collector or EventCollector()
        self._event_log_path = event_log_path

        self._emitter = MockServerEventEmitter(
            collector=self._event_collector,
            jsonl_path=event_log_path,
        )

        self._server: asyncssh.SSHAcceptor | None = None
        self._port: int = 0
        self._host_key_path: Path | None = None
        self._temp_key_file: str | None = None
        self._drop_task: asyncio.Task | None = None

    @property
    def port(self) -> int:
        """Return the assigned port (only valid after entering context)."""
        assert self._port > 0, "Port not assigned - server not started"
        return self._port

    @property
    def events(self) -> list:
        """Return collected events."""
        return self._event_collector._events

    @property
    def config(self) -> MockServerConfig:
        """Return the server configuration."""
        return self._config

    async def __aenter__(self) -> "MockSSHServer":
        """Start the mock server."""
        await self._start()
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Stop the mock server."""
        await self._stop()

    async def _start(self) -> None:
        """Start the SSH server."""
        self._emitter.open()

        # Generate or use host key
        if self._config.host_key_path:
            self._host_key_path = self._config.host_key_path
        else:
            # Generate temporary host key
            fd, path = tempfile.mkstemp(suffix="_host_key")
            os.close(fd)
            self._temp_key_file = path

            # Generate RSA key (key_size is a keyword argument)
            key = asyncssh.generate_private_key("ssh-rsa", comment=b"test", key_size=2048)
            # Export key data and write manually
            key_data = key.export_private_key()
            with open(path, "wb") as f:
                f.write(key_data)
            self._host_key_path = Path(path)

        # Build server options
        server_options: dict[str, Any] = {
            "server_host_keys": [str(self._host_key_path)],
            "process_factory": self._process_factory,
        }

        # Configure algorithm restrictions if specified
        if self._config.only_offer_ciphers is not None:
            server_options["encryption_algs"] = self._config.only_offer_ciphers

        if self._config.only_offer_kex is not None:
            server_options["kex_algs"] = self._config.only_offer_kex

        if self._config.only_offer_macs is not None:
            server_options["mac_algs"] = self._config.only_offer_macs

        # Start server on port 0 for dynamic allocation
        self._server = await asyncssh.create_server(
            lambda: MockSSHServerProtocol(self._config, self._emitter),
            "",
            0,  # Port 0 = dynamic allocation
            **server_options,
        )

        # Get assigned port
        self._port = self._server.sockets[0].getsockname()[1]

        self._emitter.emit(
            "SERVER_START",
            port=self._port,
            config={
                "username": self._config.username,
                "delay_auth": self._config.delay_auth,
                "delay_channel": self._config.delay_channel,
                "auth_attempts_before_success": self._config.auth_attempts_before_success,
            },
        )

        # Schedule connection drop if configured
        if self._config.drop_after_seconds is not None:
            self._drop_task = asyncio.create_task(
                self._drop_after_delay(self._config.drop_after_seconds)
            )

    async def _stop(self) -> None:
        """Stop the SSH server."""
        # Cancel drop task if running
        if self._drop_task:
            self._drop_task.cancel()
            try:
                await self._drop_task
            except asyncio.CancelledError:
                pass

        # Close server
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        # Cleanup temporary key
        if self._temp_key_file:
            try:
                os.unlink(self._temp_key_file)
            except OSError:
                pass
            self._temp_key_file = None

        self._emitter.emit("SERVER_STOP", port=self._port)
        self._emitter.close()

    async def _drop_after_delay(self, delay: float) -> None:
        """Drop all connections after a delay."""
        await asyncio.sleep(delay)
        self._emitter.emit("SERVER_DROP", reason="drop_after_seconds", delay=delay)
        if self._server:
            self._server.close()

    async def _process_factory(
        self,
        process: asyncssh.SSHServerProcess,
    ) -> None:
        """Create a process handler for command execution."""
        await handle_mock_process(process, self._config, self._emitter)


async def generate_test_host_key(path: Path | str) -> None:
    """
    Generate a test RSA host key at the specified path.

    Useful for creating persistent test keys that can be used
    with known_hosts files.

    Args:
        path: Path to write the private key
    """
    path = Path(path)
    key = asyncssh.generate_private_key("ssh-rsa", comment=b"test", key_size=2048)

    # Export and write private key
    key_data = key.export_private_key()
    with open(path, "wb") as f:
        f.write(key_data)

    # Also write public key
    pub_path = path.with_suffix(".pub")
    pub_data = key.export_public_key()
    with open(pub_path, "wb") as f:
        f.write(pub_data)
