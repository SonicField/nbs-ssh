"""
SSH connection wrapper with JSONL event logging.

Provides:
- SSHConnection: Async context manager for SSH connections
- SSHConnectionError: Base exception for connection failures
- ExecResult: Result of command execution

All operations emit structured events for AI-inspectable diagnostics.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

import asyncssh

from nbs_ssh.events import EventCollector, EventEmitter, EventType


class SSHConnectionError(Exception):
    """Base exception for SSH connection errors."""
    pass


class SSHAuthenticationError(SSHConnectionError):
    """Authentication failed."""
    pass


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
        async with SSHConnection(host, port, username, password=...) as conn:
            result = await conn.exec("echo hello")
            print(result.stdout)

    All operations emit events:
    - CONNECT: When connection is established
    - AUTH: When authentication completes
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
    ) -> None:
        """
        Initialise SSH connection parameters.

        Args:
            host: SSH server hostname or IP
            port: SSH server port (default 22)
            username: Username for authentication
            password: Password for password auth
            client_keys: Paths to private keys for key auth
            known_hosts: Path to known_hosts file (None to disable checking)
            event_collector: Optional collector for in-memory event capture
            event_log_path: Optional path for JSONL event log
            connect_timeout: Connection timeout in seconds
        """
        # Preconditions
        assert host, "Host must be specified"
        assert port > 0, f"Port must be positive, got {port}"
        assert password or client_keys, \
            "Either password or client_keys must be provided for authentication"

        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._client_keys = [str(p) for p in client_keys] if client_keys else None
        self._known_hosts = str(known_hosts) if known_hosts else None
        self._connect_timeout = connect_timeout

        self._emitter = EventEmitter(
            collector=event_collector,
            jsonl_path=event_log_path,
        )

        self._conn: asyncssh.SSHClientConnection | None = None

    async def __aenter__(self) -> "SSHConnection":
        """Connect and authenticate."""
        await self._connect()
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Disconnect and cleanup."""
        await self._disconnect()

    async def _connect(self) -> None:
        """Establish SSH connection."""
        connect_data = {
            "host": self._host,
            "port": self._port,
            "username": self._username,
        }

        self._emitter.emit(EventType.CONNECT, status="initiating", **connect_data)

        try:
            # Build connection options
            options: dict[str, Any] = {
                "host": self._host,
                "port": self._port,
                "username": self._username,
                "connect_timeout": self._connect_timeout,
            }

            if self._password:
                options["password"] = self._password

            if self._client_keys:
                options["client_keys"] = self._client_keys

            if self._known_hosts is None:
                # Disable host key checking (for testing only)
                options["known_hosts"] = None
            else:
                options["known_hosts"] = self._known_hosts

            self._conn = await asyncssh.connect(**options)

            self._emitter.emit(
                EventType.CONNECT,
                status="connected",
                **connect_data,
            )

            # Auth is implicit in asyncssh connect, emit AUTH event
            self._emitter.emit(
                EventType.AUTH,
                status="success",
                method="password" if self._password else "publickey",
                username=self._username,
            )

        except asyncssh.PermissionDenied as e:
            self._emitter.emit(
                EventType.ERROR,
                error_type="authentication_failed",
                message=str(e),
                **connect_data,
            )
            raise SSHAuthenticationError(f"Authentication failed: {e}") from e

        except asyncssh.ConnectionLost as e:
            self._emitter.emit(
                EventType.ERROR,
                error_type="connection_lost",
                message=str(e),
                **connect_data,
            )
            raise SSHConnectionError(f"Connection lost: {e}") from e

        except OSError as e:
            self._emitter.emit(
                EventType.ERROR,
                error_type="connection_failed",
                message=str(e),
                **connect_data,
            )
            raise SSHConnectionError(f"Connection failed: {e}") from e

        except Exception as e:
            self._emitter.emit(
                EventType.ERROR,
                error_type="unknown",
                message=str(e),
                **connect_data,
            )
            raise SSHConnectionError(f"Unexpected error: {e}") from e

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
