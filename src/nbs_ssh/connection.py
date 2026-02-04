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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

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
    ErrorContext,
    HostKeyMismatch,
    HostUnreachable,
    KeyLoadError,
    NoMutualKex,
    SSHConnectionError,
    SSHError,
)
from nbs_ssh.events import EventCollector, EventEmitter, EventType


# Re-export for backwards compatibility
SSHAuthenticationError = AuthFailed


@dataclass
class ExecResult:
    """Result of a command execution."""
    stdout: str
    stderr: str
    exit_code: int


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
        """
        # Preconditions
        assert host, "Host must be specified"
        assert port > 0, f"Port must be positive, got {port}"

        self._host = host
        self._port = port
        self._username = username
        self._known_hosts = str(known_hosts) if known_hosts else None
        self._connect_timeout = connect_timeout

        # Build auth configs from either new or legacy interface
        self._auth_configs = self._build_auth_configs(auth, password, client_keys)

        assert self._auth_configs, \
            "At least one auth method required (password, client_keys, or auth=)"

        self._emitter = EventEmitter(
            collector=event_collector,
            jsonl_path=event_log_path,
        )

        self._conn: asyncssh.SSHClientConnection | None = None

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

        for auth_config in self._auth_configs:
            auth_start_ms = time.time() * 1000

            try:
                await self._try_auth_method(auth_config)
                successful_method = auth_config.method.value
                auth_duration_ms = (time.time() * 1000) - auth_start_ms

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

    async def _disconnect(self) -> None:
        """Close SSH connection."""
        if self._conn:
            self._emitter.emit(
                EventType.DISCONNECT,
                host=self._host,
                port=self._port,
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
