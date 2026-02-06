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
import os
import signal
import sys
import termios
import time
import tty
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Sequence

import asyncssh

from nbs_ssh.auth import (
    AuthConfig,
    AuthMethod,
    check_agent_available,
    check_gssapi_available,
    check_pkcs11_available,
    create_agent_auth,
    create_cert_auth,
    create_gssapi_auth,
    create_key_auth,
    create_keyboard_interactive_auth,
    create_password_auth,
    create_pkcs11_auth,
    get_agent_keys,
    load_certificate,
    load_pkcs11_keys,
    load_private_key,
)
from nbs_ssh.errors import (
    AgentError,
    AuthenticationError,
    AuthFailed,
    CertificateError,
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
from nbs_ssh.host_key import (
    HostKeyCapturingClient,
    HostKeyChangedError,
    HostKeyPolicy,
    HostKeyResult,
    HostKeyUnknownError,
    HostKeyVerifier,
    get_key_fingerprint,
)
from nbs_ssh.platform import get_default_key_paths, get_known_hosts_read_paths, get_known_hosts_write_path
from nbs_ssh.events import EventCollector, EventEmitter, EventType
from nbs_ssh.evidence import AlgorithmInfo, EvidenceBundle, HostInfo, TimingInfo
from nbs_ssh.config import SSHConfig, SSHHostConfig
from nbs_ssh.keepalive import KeepaliveConfig
from nbs_ssh.proxy import ProxyCommandError, ProxyCommandProcess
from nbs_ssh.secure_string import SecureString
from nbs_ssh.validation import validate_hostname, validate_port, validate_username


def _reveal(value: str | SecureString | None) -> str | None:
    """
    Explicitly reveal a SecureString for passing to asyncssh.

    This function makes the intent clear: we are deliberately extracting
    the secret value to pass to an external API.
    """
    if value is None:
        return None
    if isinstance(value, SecureString):
        return value.reveal()
    return value


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

        # Loop until we have data to return or process completes
        # Note: CancelledError is NOT caught here - it must propagate for
        # asyncio.timeout() to work correctly
        while True:
            # Create tasks for reading from stdout and stderr
            stdout_task = asyncio.create_task(
                self._read_from_stream(self._process.stdout, "stdout")
            )
            stderr_task = asyncio.create_task(
                self._read_from_stream(self._process.stderr, "stderr")
            )
            wait_task = asyncio.create_task(self._process.wait())

            try:
                # Wait for first available data
                done, pending = await asyncio.wait(
                    {stdout_task, stderr_task, wait_task},
                    return_when=asyncio.FIRST_COMPLETED,
                )
            except asyncio.CancelledError:
                # Clean up tasks before propagating cancellation
                for task in [stdout_task, stderr_task, wait_task]:
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
                raise  # Re-raise to allow asyncio.timeout() to work

            # Cancel pending tasks
            for task in pending:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

            # Check stdout and stderr tasks for data (not wait_task!)
            # wait_task.result() returns SSHCompletedProcess, not StreamEvent
            for task in done:
                if task is not wait_task:
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

            # No data available but process still running - continue waiting

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
        port: int | None = None,
        username: str | None = None,
        password: str | None = None,
        client_keys: Sequence[Path | str] | None = None,
        known_hosts: list[Path | str] | Path | str | None = None,
        host_key_policy: HostKeyPolicy | None = None,
        on_unknown_host_key: Callable[[str, int, "asyncssh.SSHKey"], bool] | None = None,
        event_collector: EventCollector | None = None,
        event_log_path: Path | str | None = None,
        connect_timeout: float | None = None,
        auth: AuthConfig | Sequence[AuthConfig] | None = None,
        keepalive: KeepaliveConfig | None = None,
        proxy_jump: str | Sequence[str] | None = None,
        proxy_command: str | None = None,
        use_ssh_config: bool = True,
        ssh_config: SSHConfig | None = None,
        agent_forwarding: bool = False,
        x11_forwarding: bool = False,
        compression: bool = False,
    ) -> None:
        """
        Initialise SSH connection parameters.

        Args:
            host: SSH server hostname or IP (can be an alias from ~/.ssh/config)
            port: SSH server port (default 22, or from SSH config)
            username: Username for authentication (defaults to SSH config or current user)
            password: Password for password auth (legacy, prefer auth=)
            client_keys: Paths to private keys (legacy, prefer auth=)
            known_hosts: Path(s) to known_hosts file(s). Accepts a single path,
                         a list of paths (for user + system files), or None to
                         disable host key checking. AsyncSSH will check hosts
                         against all provided files. When host_key_policy is set,
                         this is used as the source for verification; if not set,
                         platform defaults are used.
            host_key_policy: Host key verification policy:
                - STRICT: Reject unknown hosts (for scripts)
                - ASK: Prompt for unknown hosts (requires on_unknown_host_key callback)
                - ACCEPT_NEW: Accept and save unknown hosts silently
                - INSECURE: Accept all (testing only, equivalent to known_hosts=None)
                - None: Use AsyncSSH default behaviour with known_hosts parameter
            on_unknown_host_key: Callback for ASK policy. Called with (host, port, key),
                                 should return True to accept the key.
            event_collector: Optional collector for in-memory event capture
            event_log_path: Optional path for JSONL event log
            connect_timeout: Connection timeout in seconds (default 30, or from SSH config)
            auth: AuthConfig or list of AuthConfigs to try in order
            keepalive: Optional KeepaliveConfig for connection keepalive
            proxy_jump: Jump host(s) for connection tunnelling (like ssh -J).
                        Can be a single host string "[user@]host[:port]",
                        a comma-separated string of hosts, or a list of hosts.
            proxy_command: Command whose stdin/stdout becomes the SSH transport
                           (like ssh -o ProxyCommand=...). Tokens (%h, %p) should
                           already be expanded. Takes precedence over proxy_jump.
            use_ssh_config: Whether to read ~/.ssh/config and /etc/ssh/ssh_config
            ssh_config: Pre-loaded SSHConfig object (if None, loads default configs)
            agent_forwarding: Enable SSH agent forwarding (like ssh -A)
            x11_forwarding: Enable X11 forwarding (like ssh -X/-Y)
            compression: Enable compression (like ssh -C)
        """
        # Preconditions
        assert host, "Host must be specified"

        # Load SSH config if enabled
        self._host_config: SSHHostConfig | None = None
        self._original_host = host

        if use_ssh_config:
            if ssh_config is None:
                ssh_config = SSHConfig()
            self._host_config = ssh_config.lookup(host)

        # Apply SSH config settings (explicit parameters take precedence)
        if self._host_config:
            # HostName aliasing
            host = self._host_config.get_hostname(host)

            # Port from config if not specified
            if port is None:
                port = self._host_config.port

            # Username from config if not specified
            if username is None:
                username = self._host_config.user

            # ConnectTimeout from config if not specified
            if connect_timeout is None and self._host_config.connect_timeout is not None:
                connect_timeout = float(self._host_config.connect_timeout)

            # ProxyCommand from config if not specified
            # ProxyCommand takes precedence over ProxyJump (matches OpenSSH)
            if proxy_command is None and self._host_config.proxy_command:
                proxy_command = self._host_config.proxy_command

            # ProxyJump from config if not specified
            # Only use if ProxyCommand is not set (ProxyCommand takes precedence)
            if proxy_command is None and proxy_jump is None and self._host_config.proxy_jump:
                proxy_jump = self._host_config.proxy_jump

        # Apply defaults for parameters not set by config
        if port is None:
            port = 22
        if connect_timeout is None:
            connect_timeout = 30.0

        assert port > 0, f"Port must be positive, got {port}"

        # Validate inputs to prevent injection attacks (HIGH-4, MED-2, MED-8)
        host = validate_hostname(host)
        port = validate_port(port)
        if username is not None:
            username = validate_username(username)

        self._host = host
        self._port = port
        self._username = username
        # Normalise known_hosts to format asyncssh expects
        # asyncssh accepts: None, string path, or list of string paths
        if known_hosts is None:
            self._known_hosts: list[str] | str | None = None
        elif isinstance(known_hosts, list):
            self._known_hosts = [str(p) for p in known_hosts]
        else:
            self._known_hosts = str(known_hosts)

        # Host key verification settings
        self._host_key_policy = host_key_policy
        self._on_unknown_host_key = on_unknown_host_key
        self._host_key_verifier: HostKeyVerifier | None = None
        self._host_key_client: HostKeyCapturingClient | None = None

        self._connect_timeout = connect_timeout
        self._keepalive = keepalive
        self._disconnect_reason = DisconnectReason.NORMAL

        # ProxyCommand takes precedence over ProxyJump (matches OpenSSH)
        self._proxy_command = proxy_command
        self._proxy_process: ProxyCommandProcess | None = None

        # Normalise proxy_jump to a comma-separated string for asyncssh
        # Only used if proxy_command is not set
        self._proxy_jump = None if proxy_command else self._normalise_proxy_jump(proxy_jump)

        # Build auth configs from either new or legacy interface
        self._auth_configs = self._build_auth_configs(auth, password, client_keys)

        if not self._auth_configs:
            raise AuthFailed(
                "No authentication methods available. "
                "No SSH agent running and no keys found at default locations "
                "(~/.ssh/id_rsa, ~/.ssh/id_ed25519, etc.). "
                "Provide explicit auth via password=, client_keys=, or auth= parameter."
            )

        self._emitter = EventEmitter(
            collector=event_collector,
            jsonl_path=event_log_path,
        )

        self._conn: asyncssh.SSHClientConnection | None = None

        # Timing tracking for evidence bundles
        self._timing = TimingInfo()
        self._last_error_context: ErrorContext | None = None

        # Extended connection options (OpenSSH compatibility)
        self._agent_forwarding = agent_forwarding
        self._x11_forwarding = x11_forwarding
        self._compression = compression

    def _build_auth_configs(
        self,
        auth: AuthConfig | Sequence[AuthConfig] | None,
        password: str | None,
        client_keys: Sequence[Path | str] | None,
    ) -> list[AuthConfig]:
        """Build list of auth configs from new or legacy interface.

        When no explicit auth is provided, automatically tries:
        1. SSH agent (if available)
        2. Default keys (~/.ssh/id_rsa, ~/.ssh/id_ed25519, etc.)
        """
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

        # If explicit auth was provided via legacy interface, use it
        if configs:
            return configs

        # Auto-discovery: try GSSAPI, agent, and default keys
        # This mirrors OpenSSH behaviour for library users

        # GSSAPI/Kerberos (if available and credentials exist)
        if check_gssapi_available():
            configs.append(create_gssapi_auth())

        # SSH agent (if available)
        if check_agent_available():
            configs.append(create_agent_auth())

        # Default keys from SSH config and standard locations
        for key_path in get_default_key_paths():
            # Check both existence and readability
            if key_path.exists() and os.access(key_path, os.R_OK):
                configs.append(create_key_auth(key_path))

        return configs

    @staticmethod
    def _normalise_proxy_jump(
        proxy_jump: str | Sequence[str] | None,
    ) -> str | None:
        """
        Normalise proxy_jump to asyncssh tunnel format.

        AsyncSSH's tunnel parameter accepts a comma-separated string
        of hosts in the format [user@]host[:port].

        Args:
            proxy_jump: None, a single host string, comma-separated hosts,
                        or a sequence of host strings

        Returns:
            Comma-separated string of jump hosts, or None
        """
        if proxy_jump is None:
            return None

        if isinstance(proxy_jump, str):
            # Already a string (possibly comma-separated)
            return proxy_jump.strip() if proxy_jump.strip() else None

        # Sequence of hosts - join with commas
        hosts = [h.strip() for h in proxy_jump if h.strip()]
        return ",".join(hosts) if hosts else None

    async def __aenter__(self) -> "SSHConnection":
        """Connect and authenticate."""
        await self._connect()
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Disconnect and cleanup."""
        await self._disconnect()

    async def _connect(self) -> None:
        """Establish SSH connection with auth method fallback."""
        connect_data: dict[str, Any] = {
            "host": self._host,
            "port": self._port,
            "username": self._username,
        }

        # Include proxy_jump in event data if configured
        if self._proxy_jump is not None:
            connect_data["proxy_jump"] = self._proxy_jump

        # Include proxy_command in event data if configured
        if self._proxy_command is not None:
            connect_data["proxy_command"] = self._proxy_command

        # Track connection timing
        self._timing.connect_start_ms = time.time() * 1000

        self._emitter.emit(EventType.CONNECT, status="initiating", **connect_data)

        # Build error context for exception handling
        error_ctx = ErrorContext(
            host=self._host,
            port=self._port,
            username=self._username,
        )

        # Start ProxyCommand process if configured
        if self._proxy_command is not None:
            try:
                self._proxy_process = ProxyCommandProcess(self._proxy_command)
                await self._proxy_process.start()
            except ProxyCommandError as e:
                self._emitter.emit(
                    EventType.ERROR,
                    error_type="proxy_command_failed",
                    message=str(e),
                    command=e.command,
                    exit_code=e.exit_code,
                    **connect_data,
                )
                raise SSHConnectionError(str(e), context=error_ctx) from e

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

            except (AuthenticationError, KeyLoadError, asyncssh.PermissionDenied) as e:
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

        # Add extended connection options (OpenSSH compatibility)
        if self._agent_forwarding:
            options["agent_forwarding"] = True
        if self._x11_forwarding:
            options["x11_forwarding"] = True
        if self._compression:
            options["compression_algs"] = ["zlib@openssh.com", "zlib"]

        # Add ProxyCommand socket if configured (takes precedence over ProxyJump)
        if self._proxy_process is not None:
            options["sock"] = self._proxy_process.get_socket()
        # Add proxy/tunnel if configured (ProxyJump support)
        elif self._proxy_jump is not None:
            options["tunnel"] = self._proxy_jump

        # Set up host key verification
        verifier: HostKeyVerifier | None = None
        if self._host_key_policy is not None:
            if self._host_key_policy == HostKeyPolicy.INSECURE:
                # Skip verification entirely
                options["known_hosts"] = None
            else:
                # Set up our custom verification
                # Determine which known_hosts files to use
                if self._known_hosts is not None:
                    # User specified explicit paths
                    if isinstance(self._known_hosts, list):
                        read_paths = [Path(p) for p in self._known_hosts]
                        # Use first path for writing (like OpenSSH)
                        write_path = read_paths[0] if read_paths else get_known_hosts_write_path()
                    else:
                        read_paths = [Path(self._known_hosts)]
                        write_path = read_paths[0]
                else:
                    # Use platform defaults
                    read_paths = get_known_hosts_read_paths()
                    write_path = get_known_hosts_write_path()

                verifier = HostKeyVerifier(
                    known_hosts_paths=read_paths,
                    write_path=write_path,
                    policy=self._host_key_policy,
                )
                self._host_key_verifier = verifier

                # Pass empty known_hosts to trigger our callback
                # When known_hosts=() (empty), asyncssh won't find any entries
                # and will call validate_host_public_key to let us decide
                options["known_hosts"] = ()
        else:
            # No policy - use asyncssh's built-in verification
            if self._known_hosts is None:
                options["known_hosts"] = None
            else:
                options["known_hosts"] = self._known_hosts

        # Determine if we need keyboard-interactive
        kbdint_config: AuthConfig | None = None
        if auth_config.method == AuthMethod.KEYBOARD_INTERACTIVE:
            kbdint_config = auth_config
            options["client_keys"] = []
            options["password"] = None
            options["preferred_auth"] = ["keyboard-interactive"]

        elif auth_config.method == AuthMethod.PASSWORD:
            options["password"] = _reveal(auth_config.password)
            options["client_keys"] = []

        elif auth_config.method == AuthMethod.PRIVATE_KEY:
            assert auth_config.key_path is not None
            key = load_private_key(auth_config.key_path, _reveal(auth_config.passphrase))
            options["client_keys"] = [key]
            options["password"] = None
            if auth_config.certificate_path is not None:
                cert = load_certificate(auth_config.certificate_path)
                options["client_certs"] = [cert]

        elif auth_config.method == AuthMethod.SSH_AGENT:
            agent_keys = await get_agent_keys()
            if not agent_keys:
                raise AgentError("No keys available from SSH agent")
            options["client_keys"] = agent_keys
            options["password"] = None

        elif auth_config.method == AuthMethod.GSSAPI:
            options["gss_auth"] = True
            options["gss_kex"] = True
            options["gss_host"] = self._host
            options["client_keys"] = []
            options["password"] = None

        elif auth_config.method == AuthMethod.PKCS11:
            assert auth_config.pkcs11_provider is not None
            pkcs11_keys = load_pkcs11_keys(
                provider=auth_config.pkcs11_provider,
                pin=_reveal(auth_config.pkcs11_pin),
                token_label=auth_config.pkcs11_token_label,
                token_serial=auth_config.pkcs11_token_serial,
                key_label=auth_config.pkcs11_key_label,
                key_id=auth_config.pkcs11_key_id,
            )
            if not pkcs11_keys:
                raise KeyLoadError(
                    f"No keys found on PKCS#11 provider {auth_config.pkcs11_provider}",
                    key_path=auth_config.pkcs11_provider,
                    reason="no_keys_found",
                )
            options["client_keys"] = list(pkcs11_keys)
            options["password"] = None

        # Create connection using combined client for host key verification
        if verifier is not None or kbdint_config is not None:
            # Use combined client
            client_instance: _CombinedSSHClient | None = None

            def create_client() -> _CombinedSSHClient:
                nonlocal client_instance
                client_instance = _CombinedSSHClient(
                    verifier=verifier,
                    on_unknown=self._on_unknown_host_key,
                    auth_config=kbdint_config,
                )
                client_instance.set_connection_info(self._host, self._port)
                return client_instance

            try:
                self._conn = await asyncssh.connect(
                    client_factory=create_client, **options
                )
            except asyncssh.HostKeyNotVerifiable as e:
                # asyncssh may still raise this if our callback returned False
                if client_instance is not None:
                    result = client_instance.verification_result
                    server_key = client_instance.server_key

                    if result == HostKeyResult.CHANGED and server_key is not None:
                        # Raise our detailed error
                        stored_fps = verifier.get_stored_fingerprints(
                            self._host, self._port
                        ) if verifier else []
                        raise HostKeyChangedError(
                            host=self._host,
                            port=self._port,
                            server_fingerprint=get_key_fingerprint(server_key),
                            stored_fingerprints=stored_fps,
                        ) from e

                    elif result == HostKeyResult.UNKNOWN and server_key is not None:
                        raise HostKeyUnknownError(
                            host=self._host,
                            port=self._port,
                            fingerprint=get_key_fingerprint(server_key),
                        ) from e

                raise

            # Post-connection: save host key if needed
            if (
                client_instance is not None
                and verifier is not None
                and client_instance.server_key is not None
            ):
                result = client_instance.verification_result
                if result == HostKeyResult.UNKNOWN:
                    # Key was accepted - save it
                    policy = self._host_key_policy
                    if policy in (HostKeyPolicy.ACCEPT_NEW, HostKeyPolicy.ASK):
                        verifier.save_host_key(
                            self._host,
                            self._port,
                            client_instance.server_key,
                        )

            self._host_key_client = client_instance
        else:
            # No special handling needed
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

        # Close ProxyCommand process if active
        if self._proxy_process is not None:
            await self._proxy_process.close()
            self._proxy_process = None

        self._emitter.close()

    async def exec(self, command: str, term_type: str | None = None) -> ExecResult:
        """
        Execute a command on the remote host.

        Args:
            command: The command to execute
            term_type: Terminal type for pseudo-tty allocation (e.g., 'xterm-256color').
                       If None, no PTY is allocated. Use this for commands that
                       require a TTY (like ssh -t).

        Returns:
            ExecResult with stdout, stderr, and exit_code
        """
        # Precondition: connected
        assert self._conn is not None, "Not connected. Use async with SSHConnection(...):"

        with self._emitter.timed_event(EventType.EXEC, command=command) as event_data:
            try:
                result = await self._conn.run(command, check=False, term_type=term_type)

                exit_code = result.exit_status if result.exit_status is not None else -1
                stdout = result.stdout or ""
                stderr = result.stderr or ""

                event_data["exit_code"] = exit_code
                event_data["stdout_len"] = len(stdout)
                event_data["stderr_len"] = len(stderr)
                if term_type is not None:
                    event_data["term_type"] = term_type

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

    async def shell(self) -> int:
        """
        Open an interactive shell session with PTY.

        This method:
        - Requests a PTY from the remote server
        - Puts the local terminal in raw mode
        - Forwards stdin to remote, remote stdout/stderr to local
        - Handles terminal resize (SIGWINCH)
        - Restores terminal on exit (even on crash)

        Returns:
            Exit code from the shell session
        """
        # Precondition: connected
        assert self._conn is not None, "Not connected. Use async with SSHConnection(...):"

        # Check if stdin is a TTY - if not, we can't do interactive mode
        if not sys.stdin.isatty():
            raise RuntimeError("Interactive shell requires a TTY (stdin is not a terminal)")

        # Get current terminal size
        try:
            term_size = os.get_terminal_size()
            term_width = term_size.columns
            term_height = term_size.lines
        except OSError:
            # Fallback to standard size
            term_width = 80
            term_height = 24

        # Get terminal type from environment
        term_type = os.environ.get("TERM", "xterm")

        start_ms = time.time() * 1000

        self._emitter.emit(
            EventType.SHELL,
            status="starting",
            term=term_type,
            width=term_width,
            height=term_height,
        )

        # Save terminal state for restoration
        stdin_fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(stdin_fd)

        exit_code = 0
        process = None

        try:
            # Start shell process with PTY
            process = await self._conn.create_process(
                None,  # No command = shell
                term_type=term_type,
                term_size=(term_width, term_height),
            )

            # Put terminal in raw mode
            tty.setraw(stdin_fd)

            # Set up SIGWINCH handler for terminal resize
            resize_event = asyncio.Event()

            def handle_sigwinch(signum: int, frame: Any) -> None:
                resize_event.set()

            old_sigwinch = signal.signal(signal.SIGWINCH, handle_sigwinch)

            try:
                # Run the interactive session
                exit_code = await self._run_shell_session(
                    process, stdin_fd, resize_event
                )
            finally:
                # Restore SIGWINCH handler
                signal.signal(signal.SIGWINCH, old_sigwinch)

        except Exception as e:
            self._emitter.emit(
                EventType.SHELL,
                status="error",
                error=str(e),
            )
            raise

        finally:
            # Always restore terminal state
            termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old_settings)

            # Emit completion event
            duration_ms = (time.time() * 1000) - start_ms
            self._emitter.emit(
                EventType.SHELL,
                status="completed",
                exit_code=exit_code,
                duration_ms=duration_ms,
            )

        return exit_code

    async def _run_shell_session(
        self,
        process: asyncssh.SSHClientProcess,
        stdin_fd: int,
        resize_event: asyncio.Event,
    ) -> int:
        """
        Run the interactive shell session loop.

        Handles:
        - Reading from stdin and sending to remote
        - Reading from remote and writing to stdout
        - Terminal resize events
        """
        loop = asyncio.get_event_loop()

        # Create tasks for reading/writing
        done = False

        async def read_stdin() -> None:
            """Read from local stdin and send to remote."""
            nonlocal done
            while not done:
                try:
                    # Use executor for blocking stdin read
                    data = await loop.run_in_executor(
                        None, lambda: os.read(stdin_fd, 1024)
                    )
                    if data:
                        process.stdin.write(data.decode("utf-8", errors="replace"))
                    else:
                        # EOF on stdin
                        process.stdin.write_eof()
                        break
                except (OSError, asyncio.CancelledError):
                    break

        async def read_remote() -> None:
            """Read from remote and write to local stdout."""
            nonlocal done
            while not done:
                try:
                    data = await process.stdout.read(1024)
                    if data:
                        sys.stdout.write(data)
                        sys.stdout.flush()
                    else:
                        # Remote closed
                        break
                except (asyncssh.ChannelOpenError, asyncio.CancelledError):
                    break

        async def handle_resize() -> None:
            """Handle terminal resize events."""
            nonlocal done
            while not done:
                await resize_event.wait()
                resize_event.clear()
                try:
                    term_size = os.get_terminal_size()
                    process.change_terminal_size(term_size.columns, term_size.lines)
                except OSError:
                    pass

        # Start all tasks
        stdin_task = asyncio.create_task(read_stdin())
        remote_task = asyncio.create_task(read_remote())
        resize_task = asyncio.create_task(handle_resize())
        wait_task = asyncio.create_task(process.wait())

        try:
            # Wait for process to complete or remote to close
            await asyncio.wait(
                {stdin_task, remote_task, wait_task},
                return_when=asyncio.FIRST_COMPLETED,
            )

            done = True

        finally:
            # Cancel all tasks
            for task in [stdin_task, remote_task, resize_task]:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        return process.exit_status or 0

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


class _KbdintSSHClient(asyncssh.SSHClient):
    """
    SSH client that handles keyboard-interactive authentication.

    This client class is used when keyboard-interactive auth is requested.
    It responds to challenges either using:
    - A stored password (for simple password-like prompts)
    - A callback function (for custom/2FA prompts)
    """

    def __init__(self, auth_config: AuthConfig) -> None:
        """
        Initialise with authentication configuration.

        Args:
            auth_config: AuthConfig with password and/or kbdint_response_callback
        """
        super().__init__()
        self._auth_config = auth_config
        self._challenge_count = 0

    def kbdint_auth_requested(self) -> str | None:
        """
        Called when server requests keyboard-interactive auth.

        Returns:
            Submethods string (empty string for default) or None to cancel.
        """
        return ""  # Accept all keyboard-interactive submethods

    def kbdint_challenge_received(
        self,
        name: str,
        instructions: str,
        lang: str,
        prompts: list[tuple[str, bool]],
    ) -> list[str] | None:
        """
        Called when server sends a keyboard-interactive challenge.

        Args:
            name: Challenge name (may be empty)
            instructions: Instructions to display (may be empty)
            lang: Language tag (usually empty)
            prompts: List of (prompt_text, echo_enabled) tuples

        Returns:
            List of responses matching prompts, or None to cancel.
        """
        self._challenge_count += 1

        # If callback is provided, use it
        if self._auth_config.kbdint_response_callback is not None:
            return self._auth_config.kbdint_response_callback(
                name, instructions, prompts
            )

        # Otherwise, use password for all prompts
        if self._auth_config.password is not None:
            password_str = _reveal(self._auth_config.password)
            return [password_str] * len(prompts)

        # No way to respond - cancel auth
        return None


class _CombinedSSHClient(asyncssh.SSHClient):
    """
    SSH client that handles both host key verification and keyboard-interactive auth.

    Combines HostKeyCapturingClient functionality with keyboard-interactive
    authentication handling.
    """

    def __init__(
        self,
        verifier: HostKeyVerifier | None = None,
        on_unknown: Callable[[str, int, asyncssh.SSHKey], bool] | None = None,
        auth_config: AuthConfig | None = None,
    ) -> None:
        """
        Initialise combined client.

        Args:
            verifier: HostKeyVerifier for checking keys (None to skip)
            on_unknown: Callback for unknown host keys
            auth_config: AuthConfig for keyboard-interactive (None to skip)
        """
        super().__init__()
        self._verifier = verifier
        self._on_unknown = on_unknown
        self._auth_config = auth_config
        self._host: str = ""
        self._port: int = 22
        self._result: HostKeyResult | None = None
        self._server_key: asyncssh.SSHKey | None = None
        self._challenge_count = 0

    def set_connection_info(self, host: str, port: int) -> None:
        """Set the host/port for this connection."""
        self._host = host
        self._port = port

    @property
    def verification_result(self) -> HostKeyResult | None:
        """Get the result of host key verification."""
        return self._result

    @property
    def server_key(self) -> asyncssh.SSHKey | None:
        """Get the server's host key."""
        return self._server_key

    def validate_host_public_key(
        self,
        host: str,
        addr: tuple[str, int],
        port: int,
        key: asyncssh.SSHKey,
    ) -> bool:
        """Validate the server's host public key."""
        # Store the key for later use
        self._server_key = key

        # If no verifier, accept all (INSECURE mode or no policy set)
        if self._verifier is None:
            self._result = HostKeyResult.TRUSTED
            return True

        # Use stored host/port if provided, otherwise use callback args
        check_host = self._host or host or addr[0]
        check_port = self._port or port

        result = self._verifier.check_host_key(check_host, check_port, key)
        self._result = result

        if result == HostKeyResult.TRUSTED:
            return True

        elif result == HostKeyResult.REVOKED:
            # Always reject revoked keys
            return False

        elif result == HostKeyResult.CHANGED:
            # Key mismatch - reject
            return False

        elif result == HostKeyResult.UNKNOWN:
            # Handle based on policy
            policy = self._verifier._policy

            if policy == HostKeyPolicy.INSECURE:
                return True
            elif policy == HostKeyPolicy.ACCEPT_NEW:
                return True
            elif policy == HostKeyPolicy.STRICT:
                return False
            elif policy == HostKeyPolicy.ASK:
                if self._on_unknown:
                    return self._on_unknown(check_host, check_port, key)
                return False

        return False

    # Keyboard-interactive methods
    def kbdint_auth_requested(self) -> str | None:
        """Called when server requests keyboard-interactive auth."""
        if self._auth_config is None:
            return None
        return ""

    def kbdint_challenge_received(
        self,
        name: str,
        instructions: str,
        lang: str,
        prompts: list[tuple[str, bool]],
    ) -> list[str] | None:
        """Called when server sends a keyboard-interactive challenge."""
        if self._auth_config is None:
            return None

        self._challenge_count += 1

        # If callback is provided, use it
        if self._auth_config.kbdint_response_callback is not None:
            return self._auth_config.kbdint_response_callback(
                name, instructions, prompts
            )

        # Otherwise, use password for all prompts
        if self._auth_config.password is not None:
            password_str = _reveal(self._auth_config.password)
            return [password_str] * len(prompts)

        # No way to respond - cancel auth
        return None


