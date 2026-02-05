"""
Port forwarding with intent replay on reconnection.

Provides:
- ForwardType: LOCAL, REMOTE, DYNAMIC forwarding types
- ForwardIntent: Describes a forwarding intent for replay
- ForwardHandle: Handle to an active forward with close() method
- ForwardManager: Tracks active forwards and intents for replay

All operations emit FORWARD events for AI-inspectable diagnostics.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import asyncssh
    from nbs_ssh.events import EventEmitter


class ForwardType(str, Enum):
    """Types of SSH port forwarding."""
    LOCAL = "local"      # Forward local port to remote host:port
    REMOTE = "remote"    # Forward remote port to local host:port
    DYNAMIC = "dynamic"  # SOCKS proxy on local port


@dataclass(frozen=True)
class ForwardIntent:
    """
    Describes a port forwarding intent.

    This dataclass captures the full specification of a forward
    so it can be replayed after reconnection.

    Attributes:
        forward_type: Type of forwarding (LOCAL, REMOTE, DYNAMIC)
        local_host: Local bind address (default: localhost)
        local_port: Local port number
        remote_host: Remote target host (not used for DYNAMIC)
        remote_port: Remote target port (not used for DYNAMIC)
    """
    forward_type: ForwardType
    local_host: str = "localhost"
    local_port: int = 0
    remote_host: str | None = None
    remote_port: int | None = None

    def __post_init__(self) -> None:
        """Validate forward intent fields."""
        assert self.local_port >= 0, f"local_port must be >= 0, got {self.local_port}"

        if self.forward_type == ForwardType.LOCAL:
            assert self.remote_host is not None, "LOCAL forward requires remote_host"
            assert self.remote_port is not None, "LOCAL forward requires remote_port"
            assert self.remote_port > 0, f"remote_port must be > 0, got {self.remote_port}"

        elif self.forward_type == ForwardType.REMOTE:
            assert self.remote_host is not None or self.local_host is not None, \
                "REMOTE forward requires either remote_host or local_host"
            assert self.remote_port is not None or self.local_port is not None, \
                "REMOTE forward requires either remote_port or local_port"

        # DYNAMIC only needs local_host and local_port

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for event logging."""
        result = {
            "forward_type": self.forward_type.value,
            "local_host": self.local_host,
            "local_port": self.local_port,
        }
        if self.remote_host is not None:
            result["remote_host"] = self.remote_host
        if self.remote_port is not None:
            result["remote_port"] = self.remote_port
        return result


class ForwardHandle:
    """
    Handle to an active port forward.

    Provides a close() method to stop the forward.
    """

    def __init__(
        self,
        intent: ForwardIntent,
        listener: Any,  # asyncssh listener
        manager: "ForwardManager",
        actual_port: int | None = None,
    ) -> None:
        """
        Initialise a forward handle.

        Args:
            intent: The original forward intent
            listener: AsyncSSH listener object
            manager: The ForwardManager that created this handle
            actual_port: The actual bound port (may differ if 0 was requested)
        """
        self._intent = intent
        self._listener = listener
        self._manager = manager
        self._actual_port = actual_port or intent.local_port
        self._closed = False

    @property
    def intent(self) -> ForwardIntent:
        """Return the forward intent."""
        return self._intent

    @property
    def local_port(self) -> int:
        """Return the actual local port (may differ from requested if 0 was used)."""
        return self._actual_port

    @property
    def is_active(self) -> bool:
        """Return True if the forward is still active."""
        return not self._closed

    async def close(self) -> None:
        """Close the forward."""
        if self._closed:
            return

        self._closed = True
        try:
            self._listener.close()
            await self._listener.wait_closed()
        except Exception:
            pass  # Listener may already be closed

        self._manager._remove_handle(self)


class ForwardManager:
    """
    Manages port forwarding with intent tracking for reconnection replay.

    Tracks all active forwards and their intents, enabling automatic
    replay after reconnection.
    """

    def __init__(self, emitter: "EventEmitter | None" = None) -> None:
        """
        Initialise the forward manager.

        Args:
            emitter: Optional event emitter for FORWARD events
        """
        self._emitter = emitter
        self._intents: list[ForwardIntent] = []
        self._handles: list[ForwardHandle] = []
        self._conn: asyncssh.SSHClientConnection | None = None

    def set_connection(self, conn: "asyncssh.SSHClientConnection") -> None:
        """Set the SSH connection to use for forwarding."""
        self._conn = conn

    def set_emitter(self, emitter: "EventEmitter") -> None:
        """Set the event emitter."""
        self._emitter = emitter

    @property
    def intents(self) -> list[ForwardIntent]:
        """Return list of all registered intents (for replay)."""
        return list(self._intents)

    @property
    def active_forwards(self) -> list[ForwardHandle]:
        """Return list of active forward handles."""
        return [h for h in self._handles if h.is_active]

    def add_intent(self, intent: ForwardIntent) -> None:
        """Register a forwarding intent for potential replay."""
        if intent not in self._intents:
            self._intents.append(intent)

    def remove_intent(self, intent: ForwardIntent) -> None:
        """Remove a forwarding intent."""
        if intent in self._intents:
            self._intents.remove(intent)

    def clear_intents(self) -> None:
        """Clear all intents."""
        self._intents.clear()

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
        connection to remote_host:remote_port.

        Args:
            local_port: Local port to listen on (0 for auto-assign)
            remote_host: Remote host to forward to
            remote_port: Remote port to forward to
            local_host: Local interface to bind to

        Returns:
            ForwardHandle with close() method
        """
        assert self._conn is not None, "No SSH connection set"

        intent = ForwardIntent(
            forward_type=ForwardType.LOCAL,
            local_host=local_host,
            local_port=local_port,
            remote_host=remote_host,
            remote_port=remote_port,
        )

        return await self._establish_forward(intent)

    async def forward_remote(
        self,
        remote_port: int,
        local_host: str,
        local_port: int,
        remote_host: str = "localhost",
    ) -> ForwardHandle:
        """
        Create a remote port forward.

        Traffic to the remote side on remote_host:remote_port is
        forwarded to local_host:local_port on the client side.

        Security: The default remote_host="localhost" binds only to the
        loopback interface on the remote server, matching OpenSSH's
        GatewayPorts=no behaviour. To bind to all interfaces, explicitly
        pass remote_host="" or remote_host="0.0.0.0".

        Args:
            remote_port: Remote port to listen on
            local_host: Local host to forward to
            local_port: Local port to forward to
            remote_host: Remote interface to bind to (default: localhost)

        Returns:
            ForwardHandle with close() method
        """
        assert self._conn is not None, "No SSH connection set"

        intent = ForwardIntent(
            forward_type=ForwardType.REMOTE,
            local_host=local_host,
            local_port=local_port,
            remote_host=remote_host or "",
            remote_port=remote_port,
        )

        return await self._establish_forward(intent)

    async def forward_dynamic(
        self,
        local_port: int,
        local_host: str = "localhost",
    ) -> ForwardHandle:
        """
        Create a dynamic (SOCKS) port forward.

        Creates a SOCKS proxy on local_host:local_port.

        Args:
            local_port: Local port for SOCKS proxy (0 for auto-assign)
            local_host: Local interface to bind to

        Returns:
            ForwardHandle with close() method
        """
        assert self._conn is not None, "No SSH connection set"

        intent = ForwardIntent(
            forward_type=ForwardType.DYNAMIC,
            local_host=local_host,
            local_port=local_port,
        )

        return await self._establish_forward(intent)

    async def _establish_forward(self, intent: ForwardIntent) -> ForwardHandle:
        """Establish a forward from an intent."""
        assert self._conn is not None

        self._emit_forward_event(intent, status="establishing")

        try:
            listener: Any = None
            actual_port = intent.local_port

            if intent.forward_type == ForwardType.LOCAL:
                listener = await self._conn.forward_local_port(
                    intent.local_host,
                    intent.local_port,
                    intent.remote_host,
                    intent.remote_port,
                )
                actual_port = listener.get_port()

            elif intent.forward_type == ForwardType.REMOTE:
                listener = await self._conn.forward_remote_port(
                    intent.remote_host or "",
                    intent.remote_port or 0,
                    intent.local_host,
                    intent.local_port,
                )
                actual_port = listener.get_port()

            elif intent.forward_type == ForwardType.DYNAMIC:
                listener = await self._conn.forward_socks(
                    intent.local_host,
                    intent.local_port,
                )
                actual_port = listener.get_port()

            handle = ForwardHandle(
                intent=intent,
                listener=listener,
                manager=self,
                actual_port=actual_port,
            )

            # Track both intent and handle
            self.add_intent(intent)
            self._handles.append(handle)

            self._emit_forward_event(
                intent,
                status="established",
                actual_port=actual_port,
            )

            return handle

        except Exception as e:
            self._emit_forward_event(intent, status="failed", error=str(e))
            raise

    async def replay_all(self) -> list[ForwardHandle]:
        """
        Replay all registered intents.

        Called after reconnection to re-establish forwards.

        Returns:
            List of new ForwardHandle objects
        """
        handles: list[ForwardHandle] = []
        intents_to_replay = list(self._intents)

        for intent in intents_to_replay:
            try:
                handle = await self._establish_forward(intent)
                handles.append(handle)
            except Exception as e:
                self._emit_forward_event(
                    intent,
                    status="replay_failed",
                    error=str(e),
                )

        return handles

    async def close_all(self) -> None:
        """Close all active forwards."""
        for handle in list(self._handles):
            await handle.close()

    def _remove_handle(self, handle: ForwardHandle) -> None:
        """Remove a handle from tracking (called by ForwardHandle.close())."""
        if handle in self._handles:
            self._handles.remove(handle)

        self._emit_forward_event(handle.intent, status="closed")

    def _emit_forward_event(
        self,
        intent: ForwardIntent,
        status: str,
        **extra: Any,
    ) -> None:
        """Emit a FORWARD event."""
        if self._emitter is None:
            return

        from nbs_ssh.events import EventType

        self._emitter.emit(
            EventType.FORWARD,
            status=status,
            **intent.to_dict(),
            **extra,
        )
