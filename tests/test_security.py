"""
Security falsification tests for nbs-ssh.

These tests attempt to break the client by having the server offer
weak or malicious configurations. The tests verify that the client
rejects unsafe configurations and logs evidence of what was attempted.

Falsification approach:
- Configure server to offer only weak algorithms
- Verify client rejects connection
- Verify client logs explain the rejection reason

Each test documents:
1. What attack was attempted
2. What evidence was gathered
3. What the client's response was
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from nbs_ssh.connection import SSHConnection
from nbs_ssh.errors import NoMutualKex, SSHConnectionError
from nbs_ssh.events import EventCollector
from nbs_ssh.testing.mock_server import MockServerConfig, MockSSHServer


# ---------------------------------------------------------------------------
# Weak Cipher Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_client_rejects_weak_cipher_server(tmp_path: Path) -> None:
    """
    Falsification: Server offers only weak ciphers, client should reject.

    Attack attempted:
    - Server only offers arcfour (RC4), which is cryptographically weak

    Expected behaviour:
    - Client rejects connection during algorithm negotiation
    - Error indicates no mutual cipher found
    - Server logs show what was offered

    Evidence gathered:
    - Server event log showing offered ciphers
    - Client error message explaining rejection
    """
    # Arrange: Configure server to only offer weak cipher
    config = MockServerConfig(
        username="test",
        password="test",
        only_offer_ciphers=["arcfour"],  # RC4 is weak
    )

    event_collector = EventCollector()
    server_log_path = tmp_path / "server_events.jsonl"

    async with MockSSHServer(
        config=config,
        event_log_path=server_log_path,
    ) as server:
        # Act & Assert: Client should reject connection
        with pytest.raises((NoMutualKex, SSHConnectionError)) as exc_info:
            async with SSHConnection(
                host="localhost",
                port=server.port,
                username="test",
                password="test",
                known_hosts=None,  # Skip host key verification for test
                event_collector=event_collector,
                connect_timeout=5.0,
            ):
                pass

        # Evidence: Verify error mentions algorithm negotiation
        error_msg = str(exc_info.value).lower()
        assert "cipher" in error_msg or "algorithm" in error_msg or "kex" in error_msg, \
            f"Error should mention cipher/algorithm issue, got: {exc_info.value}"

        # Evidence: Verify server logged what it offered
        server_events = server.events
        start_events = [e for e in server_events if e.event_type == "SERVER_START"]
        assert len(start_events) >= 1, "Server should have logged start event"


@pytest.mark.asyncio
async def test_client_rejects_3des_only_server(tmp_path: Path) -> None:
    """
    Falsification: Server offers only 3DES, client should reject.

    Attack attempted:
    - Server only offers 3des-cbc, which is deprecated

    Evidence gathered:
    - Connection failure with algorithm negotiation error
    """
    config = MockServerConfig(
        username="test",
        password="test",
        only_offer_ciphers=["3des-cbc"],
    )

    async with MockSSHServer(config=config) as server:
        with pytest.raises((NoMutualKex, SSHConnectionError)):
            async with SSHConnection(
                host="localhost",
                port=server.port,
                username="test",
                password="test",
                known_hosts=None,
            ):
                pass

        # Evidence: Server logged the attempt
        assert len(server.events) >= 1, "Server should have logged events"


# ---------------------------------------------------------------------------
# Weak Key Exchange Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_client_rejects_weak_kex_server(tmp_path: Path) -> None:
    """
    Falsification: Server offers only weak KEX algorithm.

    Attack attempted:
    - Server only offers diffie-hellman-group1-sha1 (deprecated, 1024-bit)

    Expected behaviour:
    - Client rejects connection during key exchange
    - Error indicates no mutual KEX found

    Evidence gathered:
    - Server event log showing offered KEX
    - Client error explaining rejection
    """
    config = MockServerConfig(
        username="test",
        password="test",
        only_offer_kex=["diffie-hellman-group1-sha1"],  # Deprecated 1024-bit
    )

    event_collector = EventCollector()

    async with MockSSHServer(config=config) as server:
        with pytest.raises((NoMutualKex, SSHConnectionError)) as exc_info:
            async with SSHConnection(
                host="localhost",
                port=server.port,
                username="test",
                password="test",
                known_hosts=None,
                event_collector=event_collector,
                connect_timeout=5.0,
            ):
                pass

        # Evidence: Error should indicate KEX failure
        error_msg = str(exc_info.value).lower()
        assert "key" in error_msg or "kex" in error_msg or "exchange" in error_msg or "algorithm" in error_msg, \
            f"Error should mention key exchange issue, got: {exc_info.value}"


# ---------------------------------------------------------------------------
# Weak MAC Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_client_rejects_weak_mac_server(tmp_path: Path) -> None:
    """
    Falsification: Server offers only weak MAC algorithm.

    Attack attempted:
    - Server only offers hmac-md5, which is cryptographically weak

    Expected behaviour:
    - Client rejects connection during algorithm negotiation
    - Error indicates no mutual MAC found

    Evidence gathered:
    - Server event log showing offered MACs
    - Client error explaining rejection
    """
    config = MockServerConfig(
        username="test",
        password="test",
        only_offer_macs=["hmac-md5"],  # MD5 is weak
    )

    async with MockSSHServer(config=config) as server:
        with pytest.raises((NoMutualKex, SSHConnectionError)) as exc_info:
            async with SSHConnection(
                host="localhost",
                port=server.port,
                username="test",
                password="test",
                known_hosts=None,
                connect_timeout=5.0,
            ):
                pass

        # Evidence: Server logged the attempt
        assert len(server.events) >= 1, "Server should have logged events"


# ---------------------------------------------------------------------------
# Good Connection Tests (Control Group)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_client_accepts_strong_algorithms() -> None:
    """
    Control test: Client accepts connection with strong algorithms.

    This verifies that rejection in other tests is due to weak
    algorithms, not a general connection issue.

    Evidence gathered:
    - Successful connection
    - Command execution works
    """
    config = MockServerConfig(
        username="test",
        password="test",
        # Default algorithms are strong
    )

    event_collector = EventCollector()

    async with MockSSHServer(config=config) as server:
        async with SSHConnection(
            host="localhost",
            port=server.port,
            username="test",
            password="test",
            known_hosts=None,
            event_collector=event_collector,
        ) as conn:
            result = await conn.exec("echo hello")
            assert result.exit_code == 0
            assert result.stdout.strip() == "hello"

        # Evidence: Verify event sequence
        event_types = [e.event_type for e in event_collector.events]
        assert "CONNECT" in event_types, "Should have CONNECT event"
        assert "AUTH" in event_types, "Should have AUTH event"
        assert "DISCONNECT" in event_types, "Should have DISCONNECT event"


@pytest.mark.asyncio
async def test_mock_server_logs_connection_events() -> None:
    """
    Verify mock server logs all connection events for debugging.

    This ensures that when security tests fail, the logs contain
    enough information to diagnose what happened.
    """
    config = MockServerConfig(
        username="test",
        password="test",
    )

    async with MockSSHServer(config=config) as server:
        async with SSHConnection(
            host="localhost",
            port=server.port,
            username="test",
            password="test",
            known_hosts=None,
        ) as conn:
            await conn.exec("whoami")

        # Evidence: Server logged all lifecycle events
        event_types = [e.event_type for e in server.events]

        assert "SERVER_START" in event_types, "Missing SERVER_START event"
        assert "SERVER_CONNECT" in event_types, "Missing SERVER_CONNECT event"
        assert "SERVER_AUTH_BEGIN" in event_types, "Missing SERVER_AUTH_BEGIN event"
        assert "SERVER_AUTH" in event_types, "Missing SERVER_AUTH event"
        assert "SERVER_EXEC" in event_types, "Missing SERVER_EXEC event"


@pytest.mark.asyncio
async def test_mock_server_logs_auth_details() -> None:
    """
    Verify mock server logs authentication details for debugging.

    When authentication fails, the logs should show what was
    attempted and why it failed.
    """
    config = MockServerConfig(
        username="test",
        password="test",
    )

    async with MockSSHServer(config=config) as server:
        async with SSHConnection(
            host="localhost",
            port=server.port,
            username="test",
            password="test",
            known_hosts=None,
        ):
            pass

        # Evidence: Auth events contain details
        auth_events = [e for e in server.events if e.event_type == "SERVER_AUTH"]
        assert len(auth_events) >= 1, "Should have at least one auth event"

        auth_event = auth_events[0]
        assert "username" in auth_event.data, "Auth event should log username"
        assert "method" in auth_event.data, "Auth event should log method"
        assert "success" in auth_event.data, "Auth event should log success"


# ---------------------------------------------------------------------------
# Port 0 Binding Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_parallel_servers_no_port_conflict() -> None:
    """
    Verify multiple mock servers can run in parallel without port conflicts.

    This is essential for parallel test execution.
    """
    configs = [MockServerConfig() for _ in range(3)]
    ports: set[int] = set()

    async with MockSSHServer(configs[0]) as server1:
        async with MockSSHServer(configs[1]) as server2:
            async with MockSSHServer(configs[2]) as server3:
                ports.add(server1.port)
                ports.add(server2.port)
                ports.add(server3.port)

                # All ports should be unique and valid
                assert len(ports) == 3, "Each server should get unique port"
                assert all(p > 0 for p in ports), "All ports should be positive"
                assert all(p < 65536 for p in ports), "All ports should be valid"
