"""
SSH connection supervisor with state machine and automatic reconnection.

Provides:
- ConnectionState: State machine states
- RetryPolicy: Exponential backoff configuration
- SSHSupervisor: Supervised connection wrapper with auto-reconnect

The supervisor manages the connection lifecycle, automatically reconnecting
on transient failures with exponential backoff.
"""
from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Sequence

from nbs_ssh.auth import AuthConfig
from nbs_ssh.connection import ExecResult, SSHConnection
from nbs_ssh.errors import (
    AuthenticationError,
    ConnectionRefused,
    ConnectionTimeout,
    DisconnectReason,
    SSHConnectionError,
    SSHError,
)
from nbs_ssh.events import EventCollector, EventEmitter, EventType
from nbs_ssh.forwarding import ForwardHandle, ForwardManager
from nbs_ssh.keepalive import KeepaliveConfig


class ConnectionState(str, Enum):
    """
    State machine states for SSH connection lifecycle.

    State transitions:
        DISCONNECTED -> CONNECTING (on connect attempt)
        CONNECTING -> CONNECTED (on success)
        CONNECTING -> RECONNECTING (on transient failure, if retries remain)
        CONNECTING -> FAILED (on permanent failure or max retries)
        CONNECTED -> DISCONNECTED (on clean close)
        CONNECTED -> RECONNECTING (on unexpected disconnect)
        RECONNECTING -> CONNECTING (after backoff delay)
        RECONNECTING -> FAILED (on max retries exceeded)
        FAILED -> DISCONNECTED (on reset)
    """
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    FAILED = "failed"


@dataclass
class RetryPolicy:
    """
    Configuration for connection retry behaviour with exponential backoff.

    The backoff delay is calculated as:
        delay = min(base_delay_sec * (exponential_base ** attempt), max_delay_sec)

    If jitter is enabled, random variance (0-25%) is added to prevent
    thundering herd when multiple clients reconnect simultaneously.

    Attributes:
        max_retries: Maximum number of reconnection attempts (0 = no retries)
        base_delay_sec: Initial delay between retries in seconds
        max_delay_sec: Maximum delay cap in seconds
        exponential_base: Base for exponential calculation (default 2.0)
        jitter: Add random jitter to delays to prevent thundering herd
    """
    max_retries: int = 3
    base_delay_sec: float = 1.0
    max_delay_sec: float = 60.0
    exponential_base: float = 2.0
    jitter: bool = True

    def __post_init__(self) -> None:
        """Validate policy configuration."""
        assert self.max_retries >= 0, \
            f"max_retries must be non-negative, got {self.max_retries}"
        assert self.base_delay_sec > 0, \
            f"base_delay_sec must be positive, got {self.base_delay_sec}"
        assert self.max_delay_sec >= self.base_delay_sec, \
            f"max_delay_sec must be >= base_delay_sec, got {self.max_delay_sec}"
        assert self.exponential_base >= 1.0, \
            f"exponential_base must be >= 1.0, got {self.exponential_base}"

    def calculate_delay(self, attempt: int) -> float:
        """
        Calculate backoff delay for a given attempt number.

        Args:
            attempt: The attempt number (0-indexed)

        Returns:
            Delay in seconds before next retry
        """
        assert attempt >= 0, f"attempt must be non-negative, got {attempt}"

        delay = self.base_delay_sec * (self.exponential_base ** attempt)

        if self.jitter:
            # Add 0-25% random jitter
            jitter_factor = 1.0 + random.uniform(0, 0.25)
            delay *= jitter_factor

        # Cap AFTER jitter so max_delay_sec is a true upper bound
        delay = min(delay, self.max_delay_sec)

        return delay


class SSHSupervisor:
    """
    Supervised SSH connection with automatic reconnection.

    Wraps SSHConnection with a state machine that handles:
    - Automatic reconnection on transient failures
    - Exponential backoff with configurable policy
    - State change events for monitoring
    - Command retry on connection loss

    Usage:
        async with SSHSupervisor(host, port, username, auth=auth) as supervisor:
            result = await supervisor.exec("echo hello")

        # Or with custom retry policy:
        policy = RetryPolicy(max_retries=5, base_delay_sec=2.0)
        async with SSHSupervisor(..., retry_policy=policy) as supervisor:
            ...
    """

    def __init__(
        self,
        host: str,
        port: int = 22,
        username: str | None = None,
        password: str | None = None,
        client_keys: Sequence[Path | str] | None = None,
        known_hosts: list[Path | str] | Path | str | None = None,
        event_collector: EventCollector | None = None,
        event_log_path: Path | str | None = None,
        connect_timeout: float = 30.0,
        auth: AuthConfig | Sequence[AuthConfig] | None = None,
        keepalive: KeepaliveConfig | None = None,
        retry_policy: RetryPolicy | None = None,
    ) -> None:
        """
        Initialise supervised SSH connection.

        Args:
            host: SSH server hostname or IP
            port: SSH server port (default 22)
            username: Username for authentication
            password: Password for password auth (legacy, prefer auth=)
            client_keys: Paths to private keys (legacy, prefer auth=)
            known_hosts: Path(s) to known_hosts file(s). Accepts a single path,
                         a list of paths, or None to disable host key checking.
            event_collector: Optional collector for in-memory event capture
            event_log_path: Optional path for JSONL event log
            connect_timeout: Connection timeout in seconds
            auth: AuthConfig or list of AuthConfigs to try in order
            keepalive: Optional KeepaliveConfig for connection keepalive
            retry_policy: Optional RetryPolicy for reconnection (default: 3 retries)
        """
        assert host, "Host must be specified"
        assert port > 0, f"Port must be positive, got {port}"

        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._client_keys = client_keys
        self._known_hosts = known_hosts
        self._event_collector = event_collector
        self._event_log_path = event_log_path
        self._connect_timeout = connect_timeout
        self._auth = auth
        self._keepalive = keepalive
        self._retry_policy = retry_policy or RetryPolicy()

        self._emitter = EventEmitter(
            collector=event_collector,
            jsonl_path=event_log_path,
        )

        # State machine
        self._state = ConnectionState.DISCONNECTED
        self._connection: SSHConnection | None = None
        self._reconnection_count = 0
        self._current_attempt = 0
        self._closed = False

        # Synchronisation
        self._connected_event = asyncio.Event()
        self._state_lock = asyncio.Lock()

        # Port forwarding
        self._forward_manager = ForwardManager(emitter=self._emitter)

    @property
    def state(self) -> ConnectionState:
        """Return current connection state."""
        return self._state

    @property
    def reconnection_count(self) -> int:
        """Return number of reconnections since initial connect."""
        return self._reconnection_count

    @property
    def is_connected(self) -> bool:
        """Return True if currently connected."""
        return self._state == ConnectionState.CONNECTED

    @property
    def forward_manager(self) -> ForwardManager:
        """Return the forward manager for accessing intents and handles."""
        return self._forward_manager

    async def forward_local(
        self,
        local_port: int,
        remote_host: str,
        remote_port: int,
        local_host: str = "localhost",
    ) -> ForwardHandle:
        """
        Create a local port forward.

        Traffic to local_host:local_port is forwarded through the SSH
        connection to remote_host:remote_port. The forward is automatically
        replayed on reconnection.

        Args:
            local_port: Local port to listen on (0 for auto-assign)
            remote_host: Remote host to forward to
            remote_port: Remote port to forward to
            local_host: Local interface to bind to

        Returns:
            ForwardHandle with close() method
        """
        await self._ensure_connected()
        return await self._forward_manager.forward_local(
            local_port, remote_host, remote_port, local_host,
        )

    async def forward_remote(
        self,
        remote_port: int,
        local_host: str,
        local_port: int,
        remote_host: str = "",
    ) -> ForwardHandle:
        """
        Create a remote port forward.

        Traffic to the remote side on remote_host:remote_port is
        forwarded to local_host:local_port on the client side.
        The forward is automatically replayed on reconnection.

        Args:
            remote_port: Remote port to listen on
            local_host: Local host to forward to
            local_port: Local port to forward to
            remote_host: Remote interface to bind to (empty for all)

        Returns:
            ForwardHandle with close() method
        """
        await self._ensure_connected()
        return await self._forward_manager.forward_remote(
            remote_port, local_host, local_port, remote_host,
        )

    async def forward_dynamic(
        self,
        local_port: int,
        local_host: str = "localhost",
    ) -> ForwardHandle:
        """
        Create a dynamic (SOCKS) port forward.

        Creates a SOCKS proxy on local_host:local_port.
        The forward is automatically replayed on reconnection.

        Args:
            local_port: Local port for SOCKS proxy (0 for auto-assign)
            local_host: Local interface to bind to

        Returns:
            ForwardHandle with close() method
        """
        await self._ensure_connected()
        return await self._forward_manager.forward_dynamic(local_port, local_host)

    async def _ensure_connected(self) -> None:
        """Ensure the supervisor is connected, waiting if necessary."""
        if self._state == ConnectionState.FAILED:
            raise SSHConnectionError("Connection failed and not recoverable")

        if self._state in (ConnectionState.RECONNECTING, ConnectionState.CONNECTING):
            connected = await self.wait_connected(timeout=self._connect_timeout * 2)
            if not connected:
                raise SSHConnectionError("Failed to establish connection")

        assert self._connection is not None, "No active connection"

    async def __aenter__(self) -> "SSHSupervisor":
        """Connect to the SSH server."""
        await self._connect()
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Disconnect and cleanup."""
        await self.close()

    async def close(self) -> None:
        """Close the connection cleanly."""
        self._closed = True
        await self._disconnect(clean=True)
        self._emitter.close()

    async def wait_connected(self, timeout: float | None = None) -> bool:
        """
        Wait until the supervisor is in CONNECTED state.

        Args:
            timeout: Maximum time to wait in seconds (None = wait forever)

        Returns:
            True if connected, False if timeout expired
        """
        if self._state == ConnectionState.CONNECTED:
            return True

        if self._state == ConnectionState.FAILED:
            return False

        try:
            await asyncio.wait_for(
                self._connected_event.wait(),
                timeout=timeout,
            )
            return True
        except asyncio.TimeoutError:
            return False

    async def exec(self, command: str, retry_on_disconnect: bool = True) -> ExecResult:
        """
        Execute a command on the remote host.

        If the connection is lost during execution and retry_on_disconnect
        is True, waits for reconnection and retries the command.

        Args:
            command: The command to execute
            retry_on_disconnect: Retry command if connection is lost

        Returns:
            ExecResult with stdout, stderr, and exit_code

        Raises:
            SSHError: If execution fails and cannot be retried
        """
        if self._state == ConnectionState.FAILED:
            raise SSHConnectionError("Connection failed and not recoverable")

        # Wait for connection if reconnecting
        if self._state in (ConnectionState.RECONNECTING, ConnectionState.CONNECTING):
            connected = await self.wait_connected(timeout=self._connect_timeout * 2)
            if not connected:
                raise SSHConnectionError("Failed to establish connection")

        assert self._connection is not None, "No active connection"

        try:
            return await self._connection.exec(command)
        except (SSHConnectionError, ConnectionError) as e:
            if retry_on_disconnect and not self._closed:
                # Trigger reconnection and retry
                await self._handle_disconnect(reason=DisconnectReason.NETWORK_ERROR)
                connected = await self.wait_connected(timeout=self._connect_timeout * 2)
                if connected:
                    assert self._connection is not None
                    return await self._connection.exec(command)
            raise

    def get_evidence_bundle(
        self,
        transcript: "Transcript | None" = None,
    ) -> "EvidenceBundle":
        """
        Create an evidence bundle with all diagnostic information.

        Delegates to the underlying SSHConnection if available,
        otherwise creates a minimal bundle with supervisor state.

        Args:
            transcript: Optional automation transcript to include

        Returns:
            EvidenceBundle with all diagnostic data
        """
        from nbs_ssh.evidence import EvidenceBundle, HostInfo, TimingInfo

        if self._connection is not None:
            bundle = self._connection.get_evidence_bundle(transcript)
            # Add supervisor-specific info to error context
            bundle.error_context["supervisor_state"] = self._state.value
            bundle.error_context["reconnection_count"] = self._reconnection_count
            return bundle

        # No connection - return minimal bundle
        return EvidenceBundle(
            events=list(self._event_collector.events) if self._event_collector else [],
            transcript=transcript,
            host_info=HostInfo(
                host=self._host,
                port=self._port,
                username=self._username,
            ),
            timing=TimingInfo(),
            error_context={
                "supervisor_state": self._state.value,
                "reconnection_count": self._reconnection_count,
            },
        )

    async def _connect(self) -> None:
        """Establish initial connection."""
        await self._transition_to(ConnectionState.CONNECTING)

        try:
            self._connection = SSHConnection(
                host=self._host,
                port=self._port,
                username=self._username,
                password=self._password,
                client_keys=self._client_keys,
                known_hosts=self._known_hosts,
                event_collector=self._event_collector,
                event_log_path=None,  # Supervisor manages its own log
                connect_timeout=self._connect_timeout,
                auth=self._auth,
                keepalive=self._keepalive,
            )
            await self._connection.__aenter__()
            # Set up forward manager with new connection
            self._forward_manager.set_connection(self._connection._conn)
            await self._transition_to(ConnectionState.CONNECTED)
            self._connected_event.set()

        except AuthenticationError:
            # Auth failures are permanent - don't retry
            await self._transition_to(ConnectionState.FAILED, error="authentication_failed")
            raise

        except (SSHConnectionError, ConnectionRefused, ConnectionTimeout, OSError) as e:
            # Transient failure - try reconnection
            await self._handle_connection_failure(e)

    async def _disconnect(self, clean: bool = False) -> None:
        """Disconnect from the server."""
        # Close forwards if this is a clean shutdown
        if clean:
            await self._forward_manager.close_all()
            self._forward_manager.clear_intents()

        if self._connection is not None:
            try:
                await self._connection.__aexit__(None, None, None)
            except Exception:
                pass  # Ignore errors during disconnect
            self._connection = None

        if clean:
            await self._transition_to(ConnectionState.DISCONNECTED)

    async def _handle_disconnect(self, reason: DisconnectReason) -> None:
        """Handle unexpected disconnection."""
        await self._disconnect(clean=False)

        if self._closed:
            await self._transition_to(ConnectionState.DISCONNECTED)
            return

        if self._current_attempt >= self._retry_policy.max_retries:
            await self._transition_to(
                ConnectionState.FAILED,
                error="max_retries_exceeded",
                attempts=self._current_attempt,
            )
            return

        await self._transition_to(
            ConnectionState.RECONNECTING,
            reason=reason.value,
        )

        # Start reconnection in background
        asyncio.create_task(self._reconnect_loop())

    async def _handle_connection_failure(self, error: Exception) -> None:
        """Handle connection failure during connect/reconnect."""
        self._current_attempt += 1

        if self._current_attempt > self._retry_policy.max_retries:
            await self._transition_to(
                ConnectionState.FAILED,
                error=str(error),
                attempts=self._current_attempt,
            )
            raise SSHConnectionError(
                f"Max retries ({self._retry_policy.max_retries}) exceeded: {error}"
            )

        await self._transition_to(
            ConnectionState.RECONNECTING,
            error=str(error),
            attempt=self._current_attempt,
        )

        # Run reconnection loop and wait for it to complete (or fail)
        await self._reconnect_loop()

        # If we're still not connected after the loop, raise an error
        if self._state == ConnectionState.FAILED:
            raise SSHConnectionError(
                f"Connection failed after {self._current_attempt} attempts"
            )

    async def _reconnect_loop(self) -> None:
        """Background task that handles reconnection with backoff."""
        while not self._closed and self._state == ConnectionState.RECONNECTING:
            delay = self._retry_policy.calculate_delay(self._current_attempt - 1)

            await asyncio.sleep(delay)

            if self._closed:
                break

            await self._transition_to(ConnectionState.CONNECTING)

            try:
                self._connection = SSHConnection(
                    host=self._host,
                    port=self._port,
                    username=self._username,
                    password=self._password,
                    client_keys=self._client_keys,
                    known_hosts=self._known_hosts,
                    event_collector=self._event_collector,
                    event_log_path=None,
                    connect_timeout=self._connect_timeout,
                    auth=self._auth,
                    keepalive=self._keepalive,
                )
                await self._connection.__aenter__()
                # Set up forward manager with new connection and replay forwards
                self._forward_manager.set_connection(self._connection._conn)
                await self._forward_manager.replay_all()
                await self._transition_to(ConnectionState.CONNECTED)
                self._reconnection_count += 1
                self._current_attempt = 0
                self._connected_event.set()
                return

            except AuthenticationError:
                # Auth failures are permanent
                await self._transition_to(ConnectionState.FAILED, error="authentication_failed")
                return

            except (SSHConnectionError, ConnectionRefused, ConnectionTimeout, OSError) as e:
                self._current_attempt += 1

                if self._current_attempt > self._retry_policy.max_retries:
                    await self._transition_to(
                        ConnectionState.FAILED,
                        error=str(e),
                        attempts=self._current_attempt,
                    )
                    return

                await self._transition_to(
                    ConnectionState.RECONNECTING,
                    error=str(e),
                    attempt=self._current_attempt,
                )
                # Loop continues with next attempt

    # Valid state transitions per the state machine documented in ConnectionState
    _VALID_TRANSITIONS: dict[ConnectionState, set[ConnectionState]] = {
        ConnectionState.DISCONNECTED: {ConnectionState.CONNECTING},
        ConnectionState.CONNECTING: {
            ConnectionState.CONNECTED,
            ConnectionState.RECONNECTING,
            ConnectionState.FAILED,
        },
        ConnectionState.CONNECTED: {
            ConnectionState.DISCONNECTED,
            ConnectionState.RECONNECTING,
        },
        ConnectionState.RECONNECTING: {
            ConnectionState.CONNECTING,
            ConnectionState.FAILED,
        },
        ConnectionState.FAILED: {ConnectionState.DISCONNECTED},
    }

    async def _transition_to(
        self,
        new_state: ConnectionState,
        **event_data: Any,
    ) -> None:
        """
        Transition to a new state and emit STATE_CHANGE event.

        Args:
            new_state: The state to transition to
            **event_data: Additional data for the event
        """
        async with self._state_lock:
            old_state = self._state

            assert new_state in self._VALID_TRANSITIONS.get(old_state, set()), \
                f"Invalid state transition: {old_state.value} -> {new_state.value}"

            self._state = new_state

            if new_state != ConnectionState.CONNECTED:
                self._connected_event.clear()

            self._emitter.emit(
                EventType.STATE_CHANGE,
                from_state=old_state.value,
                to_state=new_state.value,
                reconnection_count=self._reconnection_count,
                **event_data,
            )
