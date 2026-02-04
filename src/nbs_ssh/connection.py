"""
SSH connection wrapper with JSONL event logging.

Provides:
- SSHConnection: Async context manager for SSH connections
- ExecResult: Result of command execution

All operations emit structured events for AI-inspectable diagnostics.

Error types are imported from nbs_ssh.errors for programmatic handling.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator, Sequence

import asyncssh

from nbs_ssh.auth import (
    AuthConfig,
    AuthMethod,
    create_key_auth,
    create_password_auth,
    get_agent_keys,
    load_private_key,
)
from nbs_ssh.errors import (
    AgentError,
    AuthenticationError,
    AuthFailed,
    ConnectionRefused,
    ConnectionTimeout,
    DisconnectReason,
    ErrorContext,
    HostKeyMismatch,
    HostUnreachable,
    KeyLoadError,
    NoMutualKex,
    SSHConnectionError,
    SSHError,
)
from nbs_ssh.events import EventCollector, EventEmitter, EventType
from nbs_ssh.evidence import AlgorithmInfo, EvidenceBundle, HostInfo, TimingInfo
from nbs_ssh.keepalive import KeepaliveConfig


# Re-export for backwards compatibility
SSHAuthenticationError = AuthFailed


@dataclass
class ExecResult:
    """Result of a command execution."""
    stdout: str
    stderr: str
    exit_code: int


@dataclass
class StreamEvent:
    """
    A single event from a streaming command execution.

    Attributes:
        timestamp: Unix timestamp in milliseconds when event was received
        stream: Source of the data - 'stdout', 'stderr', or 'exit'
        data: The data received (empty string for exit events)
        exit_code: Exit code (only set for stream='exit')
    """
    timestamp: float
    stream: str  # 'stdout', 'stderr', or 'exit'
    data: str = ""
    exit_code: int | None = None

    def __post_init__(self) -> None:
        """Validate event fields."""
        assert self.stream in ("stdout", "stderr", "exit"), \
            f"stream must be 'stdout', 'stderr', or 'exit', got '{self.stream}'"
        assert self.timestamp > 0, f"timestamp must be positive, got {self.timestamp}"


class StreamExecResult:
    """
    Async iterator that yields StreamEvents as command output arrives.

    Supports cancellation via the cancel() method, which sends SIGTERM
    to the remote process and stops iteration.

    Usage:
        stream = conn.stream_exec("long_command")
        async for event in stream:
            print(event.stream, event.data)

        # Or to cancel early:
        await stream.cancel()
    """

    def __init__(
        self,
        process: asyncssh.SSHClientProcess,
        emitter: "EventEmitter",
        command: str,
    ) -> None:
        self._process = process
        self._emitter = emitter
        self._command = command
        self._cancelled = False
        self._bytes_stdout = 0
        self._bytes_stderr = 0
        self._exit_code: int | None = None
        self._start_ms = time.time() * 1000
        self._done = False

    async def cancel(self) -> None:
        """Cancel the running command."""
        if self._cancelled or self._done:
            return

        self._cancelled = True
        try:
            self._process.terminate()
            # Give process time to clean up
            await asyncio.wait_for(self._process.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            # Force kill if terminate didn't work
            self._process.kill()
        except Exception:
            pass  # Process may already be gone

    def __aiter__(self) -> AsyncIterator[StreamEvent]:
        return self

    async def __anext__(self) -> StreamEvent:
        """Yield the next stream event."""
        if self._done:
            raise StopAsyncIteration

        if self._cancelled:
            self._done = True
            self._emit_exec_event()
            raise StopAsyncIteration

        try:
            # Create tasks for reading from stdout and stderr
            stdout_task = asyncio.create_task(
                self._read_from_stream(self._process.stdout, "stdout")
            )
            stderr_task = asyncio.create_task(
                self._read_from_stream(self._process.stderr, "stderr")
            )
            wait_task = asyncio.create_task(self._process.wait())

            # Wait for first available data
            done, pending = await asyncio.wait(
                {stdout_task, stderr_task, wait_task},
                return_when=asyncio.FIRST_COMPLETED,
            )

            # Cancel pending tasks
            for task in pending:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

            # Check what completed
            for task in done:
                result = task.result()
                if result is not None:
                    return result

            # If wait_task completed, we're done
            if wait_task in done:
                self._exit_code = self._process.exit_status or 0
                self._done = True
                self._emit_exec_event()
                return StreamEvent(
                    timestamp=time.time() * 1000,
                    stream="exit",
                    exit_code=self._exit_code,
                )

            # No data available but not done - shouldn't happen
            raise StopAsyncIteration

        except asyncio.CancelledError:
            self._cancelled = True
            self._done = True
            self._emit_exec_event()
            raise StopAsyncIteration

    async def _read_from_stream(
        self,
        stream: asyncssh.SSHReader,
        stream_name: str,
    ) -> StreamEvent | None:
        """Read data from a stream and return a StreamEvent if data available."""
        try:
            # Read whatever is available (non-blocking after first char)
            data = await asyncio.wait_for(stream.read(4096), timeout=0.1)
            if data:
                if stream_name == "stdout":
                    self._bytes_stdout += len(data)
                else:
                    self._bytes_stderr += len(data)
                return StreamEvent(
                    timestamp=time.time() * 1000,
                    stream=stream_name,
                    data=data,
                )
        except (asyncio.TimeoutError, asyncio.CancelledError):
            pass
        return None

    def _emit_exec_event(self) -> None:
        """Emit the EXEC event with streaming metadata."""
        duration_ms = (time.time() * 1000) - self._start_ms
        self._emitter.emit(
            EventType.EXEC,
            command=self._command,
            streaming=True,
            bytes_stdout=self._bytes_stdout,
            bytes_stderr=self._bytes_stderr,
            exit_code=self._exit_code,
            cancelled=self._cancelled,
            duration_ms=duration_ms,
        )


class SSHConnection:
    """
    Async SSH connection with event logging.

    Usage:
        # Using AuthConfig
        auth = AuthConfig(method=AuthMethod.PASSWORD, password="secret")
        async with SSHConnection(host, port, username, auth=auth) as conn:
            result = await conn.exec("echo hello")

        # Legacy interface (password/client_keys)
        async with SSHConnection(host, port, username, password=...) as conn:
            result = await conn.exec("echo hello")

    All operations emit events:
    - CONNECT: When connection is established
    - AUTH: When authentication completes (includes method and timing)
    - EXEC: For each command execution
    - DISCONNECT: When connection closes
    - ERROR: On any failure
    """

    def __init__(
        self,
        host: str,
        port: int = 22,
        username: str | None = None,
        password: str | None = None,
        client_keys: Sequence[Path | str] | None = None,
        known_hosts: Path | str | None = None,
        event_collector: EventCollector | None = None,
        event_log_path: Path | str | None = None,
        connect_timeout: float = 30.0,
        auth: AuthConfig | Sequence[AuthConfig] | None = None,
        keepalive: KeepaliveConfig | None = None,
    ) -> None:
        """
        Initialise SSH connection parameters.

        Args:
            host: SSH server hostname or IP
            port: SSH server port (default 22)
            username: Username for authentication
            password: Password for password auth (legacy, prefer auth=)
            client_keys: Paths to private keys (legacy, prefer auth=)
            known_hosts: Path to known_hosts file (None to disable checking)
            event_collector: Optional collector for in-memory event capture
            event_log_path: Optional path for JSONL event log
            connect_timeout: Connection timeout in seconds
            auth: AuthConfig or list of AuthConfigs to try in order
            keepalive: Optional KeepaliveConfig for connection keepalive
        """
        # Preconditions
        assert host, "Host must be specified"
        assert port > 0, f"Port must be positive, got {port}"

        self._host = host
        self._port = port
        self._username = username
        self._known_hosts = str(known_hosts) if known_hosts else None
        self._connect_timeout = connect_timeout
        self._keepalive = keepalive
        self._disconnect_reason = DisconnectReason.NORMAL

        # Build auth configs from either new or legacy interface
        self._auth_configs = self._build_auth_configs(auth, password, client_keys)

        assert self._auth_configs, \
            "At least one auth method required (password, client_keys, or auth=)"

        self._emitter = EventEmitter(
            collector=event_collector,
            jsonl_path=event_log_path,
        )

        self._conn: asyncssh.SSHClientConnection | None = None

        # Timing tracking for evidence bundles
        self._timing = TimingInfo()
        self._last_error_context: ErrorContext | None = None

    def _build_auth_configs(
        self,
        auth: AuthConfig | Sequence[AuthConfig] | None,
        password: str | None,
        client_keys: Sequence[Path | str] | None,
    ) -> list[AuthConfig]:
        """Build list of auth configs from new or legacy interface."""
        if auth is not None:
            if isinstance(auth, AuthConfig):
                return [auth]
            return list(auth)

        # Legacy interface: build configs from password/client_keys
        configs: list[AuthConfig] = []

        if client_keys:
            for key_path in client_keys:
                configs.append(create_key_auth(key_path))

        if password:
            configs.append(create_password_auth(password))

        return configs

    async def __aenter__(self) -> "SSHConnection":
        """Connect and authenticate."""
        await self._connect()
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Disconnect and cleanup."""
        await self._disconnect()

    async def _connect(self) -> None:
        """Establish SSH connection with auth method fallback."""
        connect_data = {
            "host": self._host,
            "port": self._port,
            "username": self._username,
        }

        # Track connection timing
        self._timing.connect_start_ms = time.time() * 1000

        self._emitter.emit(EventType.CONNECT, status="initiating", **connect_data)

        # Build error context for exception handling
        error_ctx = ErrorContext(
            host=self._host,
            port=self._port,
            username=self._username,
        )

        # Try each auth method in order
        last_error: Exception | None = None
        successful_method: str | None = None

        # Track auth timing
        self._timing.auth_start_ms = time.time() * 1000

        for auth_config in self._auth_configs:
            auth_start_ms = time.time() * 1000

            try:
                await self._try_auth_method(auth_config)
                successful_method = auth_config.method.value
                auth_duration_ms = (time.time() * 1000) - auth_start_ms

                # Track timing
                self._timing.auth_end_ms = time.time() * 1000
                self._timing.connect_end_ms = time.time() * 1000

                self._emitter.emit(
                    EventType.AUTH,
                    status="success",
                    method=successful_method,
                    username=self._username,
                    duration_ms=auth_duration_ms,
                )
                break

            except (AuthenticationError, asyncssh.PermissionDenied) as e:
                auth_duration_ms = (time.time() * 1000) - auth_start_ms
                last_error = e

                self._emitter.emit(
                    EventType.AUTH,
                    status="failed",
                    method=auth_config.method.value,
                    username=self._username,
                    duration_ms=auth_duration_ms,
                    error_type=type(e).__name__,
                    error_message=str(e),
                )
                # Continue to next auth method
                continue

            except Exception as e:
                # Non-auth error, don't try other methods
                last_error = e
                mapped_error = self._map_exception(e, error_ctx)
                self._emitter.emit(
                    EventType.ERROR,
                    error_type=mapped_error.error_type,
                    message=str(mapped_error),
                    **connect_data,
                )
                raise mapped_error

        if self._conn is None:
            # All auth methods failed
            error_ctx.auth_method = ",".join(c.method.value for c in self._auth_configs)
            self._last_error_context = error_ctx

            self._emitter.emit(
                EventType.ERROR,
                error_type="authentication_failed",
                message="All authentication methods failed",
                methods_tried=[c.method.value for c in self._auth_configs],
                **connect_data,
            )

            if last_error:
                raise self._map_exception(last_error, error_ctx)
            else:
                raise AuthFailed("All authentication methods failed", context=error_ctx)

        self._emitter.emit(
            EventType.CONNECT,
            status="connected",
            auth_method=successful_method,
            **connect_data,
        )

    async def _try_auth_method(self, auth_config: AuthConfig) -> None:
        """Try a single authentication method."""
        options: dict[str, Any] = {
            "host": self._host,
            "port": self._port,
            "username": self._username,
            "connect_timeout": self._connect_timeout,
        }

        # Add keepalive options if configured
        if self._keepalive is not None:
            options.update(self._keepalive.to_asyncssh_options())

        if self._known_hosts is None:
            options["known_hosts"] = None
        else:
            options["known_hosts"] = self._known_hosts

        if auth_config.method == AuthMethod.PASSWORD:
            options["password"] = auth_config.password
            options["client_keys"] = []  # Disable key auth

        elif auth_config.method == AuthMethod.PRIVATE_KEY:
            assert auth_config.key_path is not None
            # Load key with our error handling
            key = load_private_key(auth_config.key_path, auth_config.passphrase)
            options["client_keys"] = [key]
            options["password"] = None  # Disable password auth

        elif auth_config.method == AuthMethod.SSH_AGENT:
            # Get keys from agent
            agent_keys = await get_agent_keys()
            if not agent_keys:
                raise AgentError("No keys available from SSH agent")
            options["client_keys"] = agent_keys
            options["password"] = None

        self._conn = await asyncssh.connect(**options)

    def _map_exception(
        self,
        exc: Exception,
        ctx: ErrorContext,
    ) -> SSHError:
        """Map AsyncSSH exceptions to our error taxonomy."""
        ctx.original_error = str(exc)

        if isinstance(exc, AuthenticationError):
            # Already our error type
            return exc

        if isinstance(exc, asyncssh.PermissionDenied):
            return AuthFailed(f"Authentication failed: {exc}", context=ctx)

        if isinstance(exc, asyncssh.HostKeyNotVerifiable):
            return HostKeyMismatch(f"Host key verification failed: {exc}", context=ctx)

        if isinstance(exc, asyncssh.KeyExchangeFailed):
            return NoMutualKex(f"Key exchange failed: {exc}", context=ctx)

        if isinstance(exc, asyncssh.ConnectionLost):
            return SSHConnectionError(f"Connection lost: {exc}", context=ctx)

        if isinstance(exc, OSError):
            error_str = str(exc).lower()
            if "connection refused" in error_str:
                return ConnectionRefused(f"Connection refused: {exc}", context=ctx)
            if "timed out" in error_str or "timeout" in error_str:
                return ConnectionTimeout(f"Connection timed out: {exc}", context=ctx)
            if "unreachable" in error_str or "no route" in error_str:
                return HostUnreachable(f"Host unreachable: {exc}", context=ctx)
            return SSHConnectionError(f"Connection failed: {exc}", context=ctx)

        if isinstance(exc, asyncio.TimeoutError):
            return ConnectionTimeout(f"Connection timed out: {exc}", context=ctx)

        return SSHError(f"Unexpected error: {exc}", context=ctx)

    async def _disconnect(self, reason: DisconnectReason | None = None) -> None:
        """Close SSH connection."""
        if reason is not None:
            self._disconnect_reason = reason

        # Track disconnect timing
        self._timing.disconnect_ms = time.time() * 1000

        if self._conn:
            self._emitter.emit(
                EventType.DISCONNECT,
                host=self._host,
                port=self._port,
                reason=self._disconnect_reason.value,
            )
            self._conn.close()
            await self._conn.wait_closed()
            self._conn = None

        self._emitter.close()

    async def exec(self, command: str) -> ExecResult:
        """
        Execute a command on the remote host.

        Args:
            command: The command to execute

        Returns:
            ExecResult with stdout, stderr, and exit_code
        """
        # Precondition: connected
        assert self._conn is not None, "Not connected. Use async with SSHConnection(...):"

        with self._emitter.timed_event(EventType.EXEC, command=command) as event_data:
            try:
                result = await self._conn.run(command, check=False)

                exit_code = result.exit_status if result.exit_status is not None else -1
                stdout = result.stdout or ""
                stderr = result.stderr or ""

                event_data["exit_code"] = exit_code
                event_data["stdout_len"] = len(stdout)
                event_data["stderr_len"] = len(stderr)

                return ExecResult(
                    stdout=stdout,
                    stderr=stderr,
                    exit_code=exit_code,
                )

            except Exception as e:
                event_data["error"] = str(e)
                raise

    def stream_exec(self, command: str) -> StreamExecResult:
        """
        Execute a command and stream output as it arrives.

        Unlike exec(), this method yields StreamEvent objects as output
        becomes available, enabling real-time processing of command output.

        Args:
            command: The command to execute

        Returns:
            StreamExecResult: Async iterator yielding StreamEvents

        Usage:
            async for event in conn.stream_exec("long_command"):
                if event.stream == "stdout":
                    print(event.data, end="")
                elif event.stream == "exit":
                    print(f"Exited with code {event.exit_code}")
        """
        # Precondition: connected
        assert self._conn is not None, "Not connected. Use async with SSHConnection(...):"

        # Start the process
        process = self._conn.create_process(command)

        # Return the async iterator wrapper
        # Note: process is a coroutine, we need to handle it in the iterator
        return _StreamExecResultFactory(process, self._emitter, command)

    def get_evidence_bundle(
        self,
        transcript: "Transcript | None" = None,
    ) -> EvidenceBundle:
        """
        Create an evidence bundle with all diagnostic information.

        Captures events, timing, algorithms, and error context for
        debugging connection issues. Secrets are redacted by default
        when exporting.

        Args:
            transcript: Optional automation transcript to include

        Returns:
            EvidenceBundle with all diagnostic data
        """
        from nbs_ssh.automation import Transcript

        # Get events from collector if available
        events: list = []
        if self._emitter._collector:
            events = list(self._emitter._collector.events)

        # Extract algorithm info from AsyncSSH connection
        algorithms = AlgorithmInfo.from_asyncssh_conn(self._conn)

        # Build host info
        host_info = HostInfo(
            host=self._host,
            port=self._port,
            username=self._username,
        )

        # Build error context dict
        error_context: dict = {}
        if self._last_error_context:
            error_context = self._last_error_context.to_dict()

        return EvidenceBundle(
            events=events,
            transcript=transcript,
            algorithms=algorithms,
            disconnect_reason=self._disconnect_reason,
            timing=self._timing,
            host_info=host_info,
            error_context=error_context,
        )


class _StreamExecResultFactory:
    """
    Factory that creates StreamExecResult after process starts.

    This exists because create_process returns a coroutine, and we need
    to await it before creating the StreamExecResult.
    """

    def __init__(
        self,
        process_coro,
        emitter: "EventEmitter",
        command: str,
    ) -> None:
        self._process_coro = process_coro
        self._emitter = emitter
        self._command = command
        self._stream_result: StreamExecResult | None = None

    def __aiter__(self) -> "_StreamExecResultFactory":
        return self

    async def __anext__(self) -> StreamEvent:
        if self._stream_result is None:
            # First iteration - start the process
            process = await self._process_coro
            self._stream_result = StreamExecResult(process, self._emitter, self._command)

        return await self._stream_result.__anext__()

    async def cancel(self) -> None:
        """Cancel the running command."""
        if self._stream_result is not None:
            await self._stream_result.cancel()

