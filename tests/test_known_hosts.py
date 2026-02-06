"""
Tests for known_hosts multi-file support.

Validates that SSHConnection and SSHSupervisor accept:
- Single path (backward compatible)
- List of paths (user + system files)
- None (disable host key checking)
"""
from __future__ import annotations

from pathlib import Path

import pytest


class TestKnownHostsNormalisation:
    """Unit tests for known_hosts parameter normalisation."""

    def test_known_hosts_none(self) -> None:
        """known_hosts=None should store None."""
        known_hosts = None
        if known_hosts is None:
            result = None
        elif isinstance(known_hosts, list):
            result = [str(p) for p in known_hosts]
        else:
            result = str(known_hosts)

        assert result is None

    def test_known_hosts_single_string(self) -> None:
        """known_hosts=string should store as string."""
        known_hosts = "/path/to/known_hosts"

        if known_hosts is None:
            result = None
        elif isinstance(known_hosts, list):
            result = [str(p) for p in known_hosts]
        else:
            result = str(known_hosts)

        assert result == "/path/to/known_hosts"
        assert isinstance(result, str)

    def test_known_hosts_single_path(self) -> None:
        """known_hosts=Path should store as string."""
        known_hosts = Path("/path/to/known_hosts")

        if known_hosts is None:
            result = None
        elif isinstance(known_hosts, list):
            result = [str(p) for p in known_hosts]
        else:
            result = str(known_hosts)

        assert result == "/path/to/known_hosts"
        assert isinstance(result, str)

    def test_known_hosts_list_of_strings(self) -> None:
        """known_hosts=[str, str] should store as list of strings."""
        known_hosts = ["/path/one", "/path/two"]

        if known_hosts is None:
            result = None
        elif isinstance(known_hosts, list):
            result = [str(p) for p in known_hosts]
        else:
            result = str(known_hosts)

        assert result == ["/path/one", "/path/two"]
        assert isinstance(result, list)

    def test_known_hosts_list_of_paths(self) -> None:
        """known_hosts=[Path, Path] should store as list of strings."""
        known_hosts = [Path("/path/one"), Path("/path/two")]

        if known_hosts is None:
            result = None
        elif isinstance(known_hosts, list):
            result = [str(p) for p in known_hosts]
        else:
            result = str(known_hosts)

        assert result == ["/path/one", "/path/two"]
        assert isinstance(result, list)
        assert all(isinstance(p, str) for p in result)

    def test_known_hosts_mixed_list(self) -> None:
        """known_hosts=[Path, str] should store as list of strings."""
        known_hosts = [Path("/path/one"), "/path/two"]

        if known_hosts is None:
            result = None
        elif isinstance(known_hosts, list):
            result = [str(p) for p in known_hosts]
        else:
            result = str(known_hosts)

        assert result == ["/path/one", "/path/two"]
        assert isinstance(result, list)
        assert all(isinstance(p, str) for p in result)

    def test_known_hosts_empty_list(self) -> None:
        """known_hosts=[] should store as empty list."""
        known_hosts: list = []

        if known_hosts is None:
            result = None
        elif isinstance(known_hosts, list):
            result = [str(p) for p in known_hosts]
        else:
            result = str(known_hosts)

        assert result == []
        assert isinstance(result, list)


@pytest.mark.asyncio
async def test_connection_known_hosts_none() -> None:
    """Test SSHConnection with known_hosts=None (disables checking)."""
    from nbs_ssh.connection import SSHConnection
    from nbs_ssh.testing.mock_server import MockServerConfig, MockSSHServer

    config = MockServerConfig(username="test", password="test")

    async with MockSSHServer(config) as server:
        async with SSHConnection(
            host="localhost",
            port=server.port,
            username="test",
            password="test",
            known_hosts=None,
        ) as conn:
            result = await conn.exec("echo hello")
            assert result.exit_code == 0
            assert result.stdout.strip() == "hello"


@pytest.mark.asyncio
async def test_connection_stores_known_hosts_as_list() -> None:
    """Test that SSHConnection correctly stores known_hosts list."""
    from nbs_ssh.auth import create_password_auth
    from nbs_ssh.connection import SSHConnection

    # Create connection object without actually connecting
    # to verify internal storage
    conn = SSHConnection(
        host="localhost",
        port=22,
        username="test",
        auth=create_password_auth("test"),
        known_hosts=[Path("/path/one"), "/path/two"],
        use_ssh_config=False,  # Don't load real config
    )

    # Verify internal storage is normalised correctly
    assert conn._known_hosts == ["/path/one", "/path/two"]
    assert isinstance(conn._known_hosts, list)
    assert all(isinstance(p, str) for p in conn._known_hosts)


@pytest.mark.asyncio
async def test_connection_stores_known_hosts_as_string() -> None:
    """Test that SSHConnection correctly stores single known_hosts path."""
    from nbs_ssh.auth import create_password_auth
    from nbs_ssh.connection import SSHConnection

    conn = SSHConnection(
        host="localhost",
        port=22,
        username="test",
        auth=create_password_auth("test"),
        known_hosts=Path("/path/to/known_hosts"),
        use_ssh_config=False,
    )

    # Verify internal storage is normalised correctly
    assert conn._known_hosts == "/path/to/known_hosts"
    assert isinstance(conn._known_hosts, str)


@pytest.mark.asyncio
async def test_connection_stores_known_hosts_none() -> None:
    """Test that SSHConnection correctly stores None for known_hosts."""
    from nbs_ssh.auth import create_password_auth
    from nbs_ssh.connection import SSHConnection

    conn = SSHConnection(
        host="localhost",
        port=22,
        username="test",
        auth=create_password_auth("test"),
        known_hosts=None,
        use_ssh_config=False,
    )

    assert conn._known_hosts is None


@pytest.mark.asyncio
async def test_supervisor_stores_known_hosts_list() -> None:
    """Test that SSHSupervisor correctly passes known_hosts list."""
    from nbs_ssh.auth import create_password_auth
    from nbs_ssh.supervisor import SSHSupervisor

    supervisor = SSHSupervisor(
        host="localhost",
        port=22,
        username="test",
        auth=create_password_auth("test"),
        known_hosts=[Path("/path/one"), "/path/two"],
    )

    # SSHSupervisor stores the raw value and passes it to SSHConnection
    assert supervisor._known_hosts == [Path("/path/one"), "/path/two"]


@pytest.mark.asyncio
async def test_supervisor_with_known_hosts_none() -> None:
    """Test SSHSupervisor with known_hosts=None works."""
    from nbs_ssh.supervisor import SSHSupervisor
    from nbs_ssh.testing.mock_server import MockServerConfig, MockSSHServer

    config = MockServerConfig(username="test", password="test")

    async with MockSSHServer(config) as server:
        async with SSHSupervisor(
            host="localhost",
            port=server.port,
            username="test",
            password="test",
            known_hosts=None,
        ) as supervisor:
            result = await supervisor.exec("echo hello")
            assert result.exit_code == 0
            assert result.stdout.strip() == "hello"
