"""
Tests for ProxyJump / proxy_jump support.

Tests the SSH connection tunnelling functionality for:
- Single jump host
- Multiple chained jump hosts
- CLI -J flag parsing
- Error handling for unreachable jump hosts
"""
from __future__ import annotations

import argparse
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from nbs_ssh.testing.mock_server import MockSSHServer


class TestProxyJumpNormalisation:
    """Tests for proxy_jump parameter normalisation."""

    def test_normalise_none(self) -> None:
        """Test None returns None."""
        from nbs_ssh.connection import SSHConnection

        result = SSHConnection._normalise_proxy_jump(None)
        assert result is None

    def test_normalise_empty_string(self) -> None:
        """Test empty string returns None."""
        from nbs_ssh.connection import SSHConnection

        result = SSHConnection._normalise_proxy_jump("")
        assert result is None

        result = SSHConnection._normalise_proxy_jump("   ")
        assert result is None

    def test_normalise_single_host(self) -> None:
        """Test single host string passes through."""
        from nbs_ssh.connection import SSHConnection

        result = SSHConnection._normalise_proxy_jump("bastion.example.com")
        assert result == "bastion.example.com"

    def test_normalise_host_with_user(self) -> None:
        """Test user@host format passes through."""
        from nbs_ssh.connection import SSHConnection

        result = SSHConnection._normalise_proxy_jump("admin@bastion.example.com")
        assert result == "admin@bastion.example.com"

    def test_normalise_host_with_port(self) -> None:
        """Test host:port format passes through."""
        from nbs_ssh.connection import SSHConnection

        result = SSHConnection._normalise_proxy_jump("bastion.example.com:2222")
        assert result == "bastion.example.com:2222"

    def test_normalise_comma_separated_hosts(self) -> None:
        """Test comma-separated hosts pass through."""
        from nbs_ssh.connection import SSHConnection

        result = SSHConnection._normalise_proxy_jump("hop1,hop2,hop3")
        assert result == "hop1,hop2,hop3"

    def test_normalise_list_of_hosts(self) -> None:
        """Test list of hosts joins with commas."""
        from nbs_ssh.connection import SSHConnection

        result = SSHConnection._normalise_proxy_jump(["hop1", "hop2", "hop3"])
        assert result == "hop1,hop2,hop3"

    def test_normalise_list_with_user_port(self) -> None:
        """Test list with user@host:port elements."""
        from nbs_ssh.connection import SSHConnection

        result = SSHConnection._normalise_proxy_jump([
            "user1@hop1:22",
            "user2@hop2:2222",
        ])
        assert result == "user1@hop1:22,user2@hop2:2222"

    def test_normalise_list_strips_whitespace(self) -> None:
        """Test list elements have whitespace stripped."""
        from nbs_ssh.connection import SSHConnection

        result = SSHConnection._normalise_proxy_jump([" hop1 ", " hop2 "])
        assert result == "hop1,hop2"

    def test_normalise_list_filters_empty(self) -> None:
        """Test empty list elements are filtered."""
        from nbs_ssh.connection import SSHConnection

        result = SSHConnection._normalise_proxy_jump(["hop1", "", "  ", "hop2"])
        assert result == "hop1,hop2"

    def test_normalise_empty_list(self) -> None:
        """Test empty list returns None."""
        from nbs_ssh.connection import SSHConnection

        result = SSHConnection._normalise_proxy_jump([])
        assert result is None


class TestCLIProxyJumpParsing:
    """Tests for CLI -J/--proxy-jump argument parsing."""

    def test_proxy_jump_short_flag(self) -> None:
        """Test -J flag is parsed correctly."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["-J", "bastion", "target", "echo hello"])

        assert args.proxy_jump == "bastion"

    def test_proxy_jump_long_flag(self) -> None:
        """Test --proxy-jump flag is parsed correctly."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["--proxy-jump", "bastion", "target", "cmd"])

        assert args.proxy_jump == "bastion"

    def test_proxy_jump_with_user(self) -> None:
        """Test proxy jump with user@host format."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["-J", "admin@bastion", "target", "cmd"])

        assert args.proxy_jump == "admin@bastion"

    def test_proxy_jump_chained(self) -> None:
        """Test proxy jump with comma-separated chain."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["-J", "hop1,hop2,hop3", "target", "cmd"])

        assert args.proxy_jump == "hop1,hop2,hop3"

    def test_proxy_jump_default_none(self) -> None:
        """Test proxy_jump defaults to None."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["target", "cmd"])

        assert args.proxy_jump is None

    def test_help_mentions_proxy_jump(self) -> None:
        """Test --help mentions proxy jump functionality."""
        import subprocess
        import sys
        from pathlib import Path

        result = subprocess.run(
            [sys.executable, "-m", "nbs_ssh", "--help"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
            env={
                **subprocess.os.environ,
                "PYTHONPATH": str(Path(__file__).parent.parent / "src"),
            },
        )

        assert result.returncode == 0
        assert "--proxy-jump" in result.stdout or "-J" in result.stdout
        assert "jump" in result.stdout.lower() or "tunnel" in result.stdout.lower()


class TestProxyJumpConnection:
    """Tests for actual proxy/tunnel connections."""

    @pytest.mark.asyncio
    async def test_connection_stores_proxy_jump(
        self,
        mock_ssh_server: "MockSSHServer",
    ) -> None:
        """Test SSHConnection stores normalised proxy_jump."""
        from nbs_ssh.connection import SSHConnection
        from nbs_ssh.auth import create_password_auth

        # Create connection with proxy_jump but don't connect
        # (we can't actually test tunnelling without two servers)
        conn = SSHConnection(
            host="target.example.com",
            port=22,
            username="test",
            auth=create_password_auth("test"),
            proxy_jump="bastion.example.com",
        )

        assert conn._proxy_jump == "bastion.example.com"

    @pytest.mark.asyncio
    async def test_connection_stores_proxy_jump_list(
        self,
        mock_ssh_server: "MockSSHServer",
    ) -> None:
        """Test SSHConnection normalises list proxy_jump."""
        from nbs_ssh.connection import SSHConnection
        from nbs_ssh.auth import create_password_auth

        conn = SSHConnection(
            host="target.example.com",
            port=22,
            username="test",
            auth=create_password_auth("test"),
            proxy_jump=["hop1", "hop2"],
        )

        assert conn._proxy_jump == "hop1,hop2"

    @pytest.mark.asyncio
    async def test_connection_none_proxy_jump(
        self,
        mock_ssh_server: "MockSSHServer",
    ) -> None:
        """Test SSHConnection with no proxy_jump."""
        from nbs_ssh.connection import SSHConnection
        from nbs_ssh.auth import create_password_auth

        conn = SSHConnection(
            host="localhost",
            port=mock_ssh_server.port,
            username="test",
            auth=create_password_auth("test"),
        )

        assert conn._proxy_jump is None


class TestProxyJumpEvents:
    """Tests for proxy_jump in JSONL events."""

    @pytest.mark.asyncio
    async def test_connect_event_includes_proxy_jump(self) -> None:
        """Test CONNECT event includes proxy_jump when configured."""
        from nbs_ssh.connection import SSHConnection
        from nbs_ssh.auth import create_password_auth
        from nbs_ssh.events import EventCollector

        collector = EventCollector()

        conn = SSHConnection(
            host="target.example.com",
            port=22,
            username="test",
            auth=create_password_auth("test"),
            event_collector=collector,
            proxy_jump="bastion.example.com",
        )

        # Connection will fail but we can check the initiating event
        try:
            await conn._connect()
        except Exception:
            pass  # Expected to fail - we can't connect to example.com

        # Find CONNECT event with status="initiating"
        connect_events = [
            e for e in collector.events
            if e.event_type == "CONNECT" and e.data.get("status") == "initiating"
        ]

        assert len(connect_events) >= 1
        assert connect_events[0].data.get("proxy_jump") == "bastion.example.com"


class TestProxyJumpErrorHandling:
    """Tests for error handling with proxy connections."""

    @pytest.mark.asyncio
    async def test_unreachable_jump_host_error(self) -> None:
        """Test connection fails gracefully when jump host is unreachable."""
        from nbs_ssh.connection import SSHConnection
        from nbs_ssh.auth import create_password_auth

        conn = SSHConnection(
            host="target.internal",
            port=22,
            username="test",
            auth=create_password_auth("test"),
            proxy_jump="unreachable.invalid:22",
            connect_timeout=2.0,
        )

        # Should raise an error (connection refused, timeout, or DNS failure)
        with pytest.raises(Exception):  # Could be various connection errors
            async with conn:
                pass
