"""
Tests for port forwarding functionality.

Tests:
- ForwardIntent validation
- ForwardManager tracks intents
- FORWARD events emitted
- Integration: Forward works (if Docker available)
"""
from __future__ import annotations

import pytest

from nbs_ssh.events import EventCollector, EventEmitter, EventType
from nbs_ssh.forwarding import ForwardHandle, ForwardIntent, ForwardManager, ForwardType


class TestForwardIntent:
    """Tests for ForwardIntent dataclass validation."""

    def test_local_forward_intent_valid(self) -> None:
        """LOCAL forward intent with all required fields is valid."""
        intent = ForwardIntent(
            forward_type=ForwardType.LOCAL,
            local_host="localhost",
            local_port=8080,
            remote_host="example.com",
            remote_port=80,
        )
        assert intent.forward_type == ForwardType.LOCAL
        assert intent.local_host == "localhost"
        assert intent.local_port == 8080
        assert intent.remote_host == "example.com"
        assert intent.remote_port == 80

    def test_local_forward_intent_missing_remote_host_fails(self) -> None:
        """LOCAL forward intent without remote_host raises AssertionError."""
        with pytest.raises(AssertionError, match="LOCAL forward requires remote_host"):
            ForwardIntent(
                forward_type=ForwardType.LOCAL,
                local_port=8080,
                remote_port=80,
            )

    def test_local_forward_intent_missing_remote_port_fails(self) -> None:
        """LOCAL forward intent without remote_port raises AssertionError."""
        with pytest.raises(AssertionError, match="LOCAL forward requires remote_port"):
            ForwardIntent(
                forward_type=ForwardType.LOCAL,
                local_port=8080,
                remote_host="example.com",
            )

    def test_dynamic_forward_intent_valid(self) -> None:
        """DYNAMIC forward intent only needs local_host and local_port."""
        intent = ForwardIntent(
            forward_type=ForwardType.DYNAMIC,
            local_host="127.0.0.1",
            local_port=1080,
        )
        assert intent.forward_type == ForwardType.DYNAMIC
        assert intent.local_host == "127.0.0.1"
        assert intent.local_port == 1080

    def test_remote_forward_intent_valid(self) -> None:
        """REMOTE forward intent is valid with remote and local ports."""
        intent = ForwardIntent(
            forward_type=ForwardType.REMOTE,
            local_host="localhost",
            local_port=3000,
            remote_host="",
            remote_port=8080,
        )
        assert intent.forward_type == ForwardType.REMOTE

    def test_remote_forward_explicit_all_interfaces(self) -> None:
        """REMOTE forward with explicit empty string binds to all interfaces."""
        intent = ForwardIntent(
            forward_type=ForwardType.REMOTE,
            local_host="localhost",
            local_port=3000,
            remote_host="",  # Explicit all-interface binding
            remote_port=8080,
        )
        assert intent.remote_host == ""

    def test_remote_forward_explicit_zero_zero(self) -> None:
        """REMOTE forward with 0.0.0.0 binds to all interfaces."""
        intent = ForwardIntent(
            forward_type=ForwardType.REMOTE,
            local_host="localhost",
            local_port=3000,
            remote_host="0.0.0.0",  # Explicit all-interface binding
            remote_port=8080,
        )
        assert intent.remote_host == "0.0.0.0"

    def test_negative_local_port_fails(self) -> None:
        """Negative local_port raises AssertionError."""
        with pytest.raises(AssertionError, match="local_port must be >= 0"):
            ForwardIntent(
                forward_type=ForwardType.DYNAMIC,
                local_port=-1,
            )

    def test_forward_intent_to_dict(self) -> None:
        """ForwardIntent.to_dict() returns serializable dictionary."""
        intent = ForwardIntent(
            forward_type=ForwardType.LOCAL,
            local_host="localhost",
            local_port=8080,
            remote_host="db.internal",
            remote_port=5432,
        )
        d = intent.to_dict()
        assert d["forward_type"] == "local"
        assert d["local_host"] == "localhost"
        assert d["local_port"] == 8080
        assert d["remote_host"] == "db.internal"
        assert d["remote_port"] == 5432

    def test_forward_intent_to_dict_omits_none_values(self) -> None:
        """ForwardIntent.to_dict() omits None remote_host/port for DYNAMIC."""
        intent = ForwardIntent(
            forward_type=ForwardType.DYNAMIC,
            local_port=1080,
        )
        d = intent.to_dict()
        assert "remote_host" not in d
        assert "remote_port" not in d


class TestForwardManager:
    """Tests for ForwardManager intent tracking."""

    def test_add_intent(self) -> None:
        """ForwardManager.add_intent() registers an intent."""
        manager = ForwardManager()
        intent = ForwardIntent(
            forward_type=ForwardType.DYNAMIC,
            local_port=1080,
        )
        manager.add_intent(intent)
        assert intent in manager.intents

    def test_add_duplicate_intent_is_idempotent(self) -> None:
        """Adding the same intent twice doesn't create duplicates."""
        manager = ForwardManager()
        intent = ForwardIntent(
            forward_type=ForwardType.DYNAMIC,
            local_port=1080,
        )
        manager.add_intent(intent)
        manager.add_intent(intent)
        assert len(manager.intents) == 1

    def test_remove_intent(self) -> None:
        """ForwardManager.remove_intent() removes a registered intent."""
        manager = ForwardManager()
        intent = ForwardIntent(
            forward_type=ForwardType.DYNAMIC,
            local_port=1080,
        )
        manager.add_intent(intent)
        manager.remove_intent(intent)
        assert intent not in manager.intents

    def test_clear_intents(self) -> None:
        """ForwardManager.clear_intents() removes all intents."""
        manager = ForwardManager()
        manager.add_intent(ForwardIntent(forward_type=ForwardType.DYNAMIC, local_port=1080))
        manager.add_intent(ForwardIntent(forward_type=ForwardType.DYNAMIC, local_port=1081))
        manager.clear_intents()
        assert len(manager.intents) == 0

    def test_intents_property_returns_copy(self) -> None:
        """ForwardManager.intents returns a copy, not the internal list."""
        manager = ForwardManager()
        intent = ForwardIntent(forward_type=ForwardType.DYNAMIC, local_port=1080)
        manager.add_intent(intent)

        # Modifying returned list shouldn't affect manager
        intents = manager.intents
        intents.clear()
        assert len(manager.intents) == 1

    def test_active_forwards_empty_initially(self) -> None:
        """ForwardManager.active_forwards is empty initially."""
        manager = ForwardManager()
        assert len(manager.active_forwards) == 0

    def test_forward_manager_without_connection_raises(self) -> None:
        """ForwardManager.forward_local() without connection raises."""
        manager = ForwardManager()

        with pytest.raises(AssertionError, match="No SSH connection set"):
            import asyncio
            asyncio.run(manager.forward_local(8080, "localhost", 80))


class TestForwardRemoteDefaults:
    """Tests for remote forwarding default behaviour (HIGH-2 fix)."""

    def test_forward_remote_defaults_to_localhost(self) -> None:
        """ForwardManager.forward_remote() defaults remote_host to localhost."""
        import asyncio
        import inspect

        # Verify the signature has the correct default
        sig = inspect.signature(ForwardManager.forward_remote)
        remote_host_param = sig.parameters["remote_host"]
        assert remote_host_param.default == "localhost", (
            f"remote_host default should be 'localhost', got {remote_host_param.default!r}"
        )


class TestForwardEvents:
    """Tests for FORWARD event emission."""

    def test_forward_event_type_exists(self) -> None:
        """EventType.FORWARD exists in the enum."""
        assert EventType.FORWARD == "FORWARD"

    def test_event_emitter_can_emit_forward(self) -> None:
        """EventEmitter can emit FORWARD events."""
        collector = EventCollector()
        emitter = EventEmitter(collector=collector)

        emitter.emit(
            EventType.FORWARD,
            forward_type="local",
            local_host="localhost",
            local_port=8080,
            remote_host="db.internal",
            remote_port=5432,
            status="established",
        )

        events = collector.get_by_type(EventType.FORWARD)
        assert len(events) == 1
        assert events[0].data["forward_type"] == "local"
        assert events[0].data["status"] == "established"
        assert events[0].data["local_port"] == 8080

    def test_forward_manager_emits_events(self) -> None:
        """ForwardManager._emit_forward_event() emits FORWARD events."""
        collector = EventCollector()
        emitter = EventEmitter(collector=collector)
        manager = ForwardManager(emitter=emitter)

        intent = ForwardIntent(
            forward_type=ForwardType.LOCAL,
            local_host="localhost",
            local_port=8080,
            remote_host="db.internal",
            remote_port=5432,
        )

        # Manually call the internal method to test emission
        manager._emit_forward_event(intent, status="test")

        events = collector.get_by_type(EventType.FORWARD)
        assert len(events) == 1
        assert events[0].data["status"] == "test"
        assert events[0].data["forward_type"] == "local"
        assert events[0].data["local_port"] == 8080
        assert events[0].data["remote_host"] == "db.internal"


class TestForwardIntentFrozen:
    """Tests that ForwardIntent is immutable."""

    def test_forward_intent_is_frozen(self) -> None:
        """ForwardIntent is a frozen dataclass."""
        intent = ForwardIntent(
            forward_type=ForwardType.DYNAMIC,
            local_port=1080,
        )
        with pytest.raises(AttributeError):
            intent.local_port = 9999  # type: ignore

    def test_forward_intent_hashable(self) -> None:
        """ForwardIntent can be used in sets (is hashable)."""
        intent1 = ForwardIntent(
            forward_type=ForwardType.DYNAMIC,
            local_port=1080,
        )
        intent2 = ForwardIntent(
            forward_type=ForwardType.DYNAMIC,
            local_port=1080,
        )
        # Same values should be equal and have same hash
        assert intent1 == intent2
        assert hash(intent1) == hash(intent2)

        # Can be used in a set
        intent_set = {intent1, intent2}
        assert len(intent_set) == 1


@pytest.mark.asyncio
class TestForwardingIntegration:
    """Integration tests for port forwarding (require Docker SSH server)."""

    async def test_local_forward_establishes(
        self,
        ssh_server,
        event_collector: EventCollector,
    ) -> None:
        """Local forward establishes and emits events."""
        if ssh_server is None:
            pytest.skip("Docker SSH server not available")

        from nbs_ssh import SSHConnection, create_password_auth

        auth = create_password_auth(ssh_server.password)

        async with SSHConnection(
            host=ssh_server.host,
            port=ssh_server.port,
            username=ssh_server.username,
            auth=auth,
            known_hosts=ssh_server.known_hosts_path,
            event_collector=event_collector,
        ) as conn:
            # Create a forward manager and set the connection
            manager = ForwardManager(emitter=conn._emitter)
            manager.set_connection(conn._conn)

            # Establish a local forward (port 0 = auto-assign)
            handle = await manager.forward_local(
                local_port=0,
                remote_host="localhost",
                remote_port=22,
            )

            # Verify forward is active
            assert handle.is_active
            assert handle.local_port > 0

            # Verify intent was stored
            assert len(manager.intents) == 1
            assert manager.intents[0].forward_type == ForwardType.LOCAL

            # Verify events were emitted
            forward_events = event_collector.get_by_type(EventType.FORWARD)
            assert len(forward_events) >= 1

            established = [e for e in forward_events if e.data.get("status") == "established"]
            assert len(established) == 1

            # Close the forward
            await handle.close()
            assert not handle.is_active

            # Verify close event was emitted
            forward_events = event_collector.get_by_type(EventType.FORWARD)
            closed = [e for e in forward_events if e.data.get("status") == "closed"]
            assert len(closed) == 1

    async def test_dynamic_socks_forward_establishes(
        self,
        ssh_server,
        event_collector: EventCollector,
    ) -> None:
        """Dynamic (SOCKS) forward establishes."""
        if ssh_server is None:
            pytest.skip("Docker SSH server not available")

        from nbs_ssh import SSHConnection, create_password_auth

        auth = create_password_auth(ssh_server.password)

        async with SSHConnection(
            host=ssh_server.host,
            port=ssh_server.port,
            username=ssh_server.username,
            auth=auth,
            known_hosts=ssh_server.known_hosts_path,
            event_collector=event_collector,
        ) as conn:
            manager = ForwardManager(emitter=conn._emitter)
            manager.set_connection(conn._conn)

            # Establish a SOCKS forward
            handle = await manager.forward_dynamic(local_port=0)

            assert handle.is_active
            assert handle.local_port > 0
            assert handle.intent.forward_type == ForwardType.DYNAMIC

            await handle.close()

    async def test_supervisor_forward_local(
        self,
        ssh_server,
        event_collector: EventCollector,
    ) -> None:
        """SSHSupervisor.forward_local() establishes forward."""
        if ssh_server is None:
            pytest.skip("Docker SSH server not available")

        from nbs_ssh import SSHSupervisor, create_password_auth

        auth = create_password_auth(ssh_server.password)

        async with SSHSupervisor(
            host=ssh_server.host,
            port=ssh_server.port,
            username=ssh_server.username,
            auth=auth,
            known_hosts=ssh_server.known_hosts_path,
            event_collector=event_collector,
        ) as supervisor:
            # Use supervisor's forwarding methods
            handle = await supervisor.forward_local(
                local_port=0,
                remote_host="localhost",
                remote_port=22,
            )

            assert handle.is_active
            assert handle.local_port > 0

            # Verify intent is stored in supervisor's forward manager
            assert len(supervisor.forward_manager.intents) == 1

            await handle.close()
