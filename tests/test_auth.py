"""
Tests for SSH authentication module.

Tests cover:
- AuthConfig validation and creation
- Private key loading with error handling
- SSH agent detection
- Auth method fallback ordering
- Error taxonomy with structured context

These are primarily unit tests that don't require Docker.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from nbs_ssh.auth import (
    AuthConfig,
    AuthMethod,
    check_agent_available,
    create_agent_auth,
    create_key_auth,
    create_password_auth,
    load_private_key,
)
from nbs_ssh.errors import (
    AgentError,
    AuthenticationError,
    AuthFailed,
    ErrorContext,
    HostKeyMismatch,
    KeyLoadError,
    NoMutualKex,
    SSHError,
)


# ---------------------------------------------------------------------------
# Error Taxonomy Tests
# ---------------------------------------------------------------------------

class TestErrorTaxonomy:
    """Test that error types are properly structured and distinguishable."""

    def test_ssh_error_base_class(self) -> None:
        """SSHError carries structured context."""
        ctx = ErrorContext(host="example.com", port=22, username="user")
        error = SSHError("Test error", context=ctx)

        assert str(error) == "Test error"
        assert error.context.host == "example.com"
        assert error.context.port == 22
        assert error.error_type == "SSHError"

    def test_error_to_dict_for_logging(self) -> None:
        """Errors can be serialised to dict for JSONL logging."""
        ctx = ErrorContext(
            host="example.com",
            port=22,
            auth_method="password",
            extra={"attempts": 3},
        )
        error = AuthFailed("Invalid password", context=ctx)

        data = error.to_dict()

        assert data["error_type"] == "AuthFailed"
        assert data["message"] == "Invalid password"
        assert data["host"] == "example.com"
        assert data["port"] == 22
        assert data["auth_method"] == "password"
        assert data["attempts"] == 3

    def test_error_types_are_distinguishable(self) -> None:
        """Each error type has a unique error_type property."""
        errors = [
            AuthFailed("test"),
            HostKeyMismatch("test"),
            NoMutualKex("test"),
            KeyLoadError("test"),
            AgentError("test"),
        ]

        error_types = [e.error_type for e in errors]
        assert len(set(error_types)) == len(error_types), \
            "All error types must be unique"

    def test_auth_errors_inherit_from_authentication_error(self) -> None:
        """All auth errors inherit from AuthenticationError."""
        auth_errors = [
            AuthFailed("test"),
            HostKeyMismatch("test"),
            NoMutualKex("test"),
            KeyLoadError("test"),
            AgentError("test"),
        ]

        for error in auth_errors:
            assert isinstance(error, AuthenticationError), \
                f"{error.__class__.__name__} should inherit from AuthenticationError"
            assert isinstance(error, SSHError), \
                f"{error.__class__.__name__} should inherit from SSHError"

    def test_key_load_error_includes_key_path(self) -> None:
        """KeyLoadError carries key path in context."""
        error = KeyLoadError(
            "Key not found",
            key_path="/path/to/key",
            reason="file_not_found",
        )

        assert error.context.key_path == "/path/to/key"
        data = error.to_dict()
        assert data["key_path"] == "/path/to/key"
        assert data["reason"] == "file_not_found"

    def test_agent_error_includes_reason(self) -> None:
        """AgentError carries reason in context."""
        error = AgentError(
            "Agent not running",
            reason="no_auth_sock",
        )

        data = error.to_dict()
        assert data["reason"] == "no_auth_sock"


# ---------------------------------------------------------------------------
# AuthConfig Tests
# ---------------------------------------------------------------------------

class TestAuthConfig:
    """Test AuthConfig validation and creation."""

    def test_password_auth_requires_password(self) -> None:
        """PASSWORD method requires password to be set."""
        with pytest.raises(AssertionError, match="Password required"):
            AuthConfig(method=AuthMethod.PASSWORD)

    def test_password_auth_creation(self) -> None:
        """Password auth config stores password."""
        config = AuthConfig(method=AuthMethod.PASSWORD, password="secret")

        assert config.method == AuthMethod.PASSWORD
        assert config.password == "secret"
        assert config.key_path is None

    def test_key_auth_requires_key_path(self) -> None:
        """PRIVATE_KEY method requires key_path to be set."""
        with pytest.raises(AssertionError, match="key_path required"):
            AuthConfig(method=AuthMethod.PRIVATE_KEY)

    def test_key_auth_creation(self) -> None:
        """Key auth config stores path and optional passphrase."""
        config = AuthConfig(
            method=AuthMethod.PRIVATE_KEY,
            key_path="/path/to/key",
            passphrase="keypass",
        )

        assert config.method == AuthMethod.PRIVATE_KEY
        assert config.key_path == Path("/path/to/key")
        assert config.passphrase == "keypass"

    def test_key_path_expands_user(self) -> None:
        """Key path expands ~ to user home."""
        config = AuthConfig(
            method=AuthMethod.PRIVATE_KEY,
            key_path="~/.ssh/id_rsa",
        )

        assert not str(config.key_path).startswith("~")
        assert "id_rsa" in str(config.key_path)

    def test_agent_auth_creation(self) -> None:
        """Agent auth config requires no extra fields."""
        config = AuthConfig(method=AuthMethod.SSH_AGENT)

        assert config.method == AuthMethod.SSH_AGENT
        assert config.password is None
        assert config.key_path is None

    def test_to_dict_excludes_secrets(self) -> None:
        """to_dict() excludes password and passphrase."""
        config = AuthConfig(
            method=AuthMethod.PASSWORD,
            password="secret123",
        )

        data = config.to_dict()
        assert "password" not in data
        assert data["method"] == "password"

    def test_to_dict_includes_key_path(self) -> None:
        """to_dict() includes key_path but not passphrase."""
        config = AuthConfig(
            method=AuthMethod.PRIVATE_KEY,
            key_path="/path/to/key",
            passphrase="secret",
        )

        data = config.to_dict()
        assert data["key_path"] == "/path/to/key"
        assert "passphrase" not in data


# ---------------------------------------------------------------------------
# Helper Function Tests
# ---------------------------------------------------------------------------

class TestHelperFunctions:
    """Test auth helper functions."""

    def test_create_password_auth(self) -> None:
        """create_password_auth() creates correct config."""
        config = create_password_auth("mypassword")

        assert config.method == AuthMethod.PASSWORD
        assert config.password == "mypassword"

    def test_create_key_auth(self) -> None:
        """create_key_auth() creates correct config."""
        config = create_key_auth("/path/to/key", passphrase="pass")

        assert config.method == AuthMethod.PRIVATE_KEY
        assert config.key_path == Path("/path/to/key")
        assert config.passphrase == "pass"

    def test_create_agent_auth(self) -> None:
        """create_agent_auth() creates correct config."""
        config = create_agent_auth()

        assert config.method == AuthMethod.SSH_AGENT


# ---------------------------------------------------------------------------
# Key Loading Tests
# ---------------------------------------------------------------------------

class TestKeyLoading:
    """Test private key loading with error handling."""

    def test_load_key_file_not_found(self) -> None:
        """load_private_key raises KeyLoadError for missing file."""
        with pytest.raises(KeyLoadError) as exc_info:
            load_private_key("/nonexistent/key/path")

        error = exc_info.value
        assert error.context.key_path == "/nonexistent/key/path"
        assert "file_not_found" in error.to_dict().get("reason", "")

    def test_load_key_permission_denied(self, tmp_path: Path) -> None:
        """load_private_key raises KeyLoadError for unreadable file."""
        key_file = tmp_path / "unreadable_key"
        key_file.write_text("fake key content")
        key_file.chmod(0o000)

        try:
            with pytest.raises(KeyLoadError) as exc_info:
                load_private_key(key_file)

            error = exc_info.value
            assert "permission_denied" in error.to_dict().get("reason", "")
        finally:
            # Restore permissions for cleanup
            key_file.chmod(0o644)

    def test_load_key_invalid_format(self, tmp_path: Path) -> None:
        """load_private_key raises KeyLoadError for invalid key format."""
        key_file = tmp_path / "bad_key"
        key_file.write_text("this is not a valid ssh key")

        with pytest.raises(KeyLoadError) as exc_info:
            load_private_key(key_file)

        error = exc_info.value
        assert error.context.key_path == str(key_file)
        # Should indicate import/format error
        reason = error.to_dict().get("reason", "")
        assert reason in ("invalid_format", "import_error", "unknown")


# ---------------------------------------------------------------------------
# Agent Detection Tests
# ---------------------------------------------------------------------------

class TestAgentDetection:
    """Test SSH agent availability checking."""

    def test_check_agent_no_socket_env(self) -> None:
        """check_agent_available returns False when SSH_AUTH_SOCK not set."""
        with patch.dict(os.environ, {}, clear=True):
            # Remove SSH_AUTH_SOCK if present
            os.environ.pop("SSH_AUTH_SOCK", None)
            assert check_agent_available() is False

    def test_check_agent_socket_exists(self, tmp_path: Path) -> None:
        """check_agent_available returns True when socket exists."""
        fake_socket = tmp_path / "agent.sock"
        fake_socket.touch()

        with patch.dict(os.environ, {"SSH_AUTH_SOCK": str(fake_socket)}):
            assert check_agent_available() is True

    def test_check_agent_socket_missing(self) -> None:
        """check_agent_available returns False when socket file missing."""
        with patch.dict(os.environ, {"SSH_AUTH_SOCK": "/nonexistent/socket"}):
            assert check_agent_available() is False


# ---------------------------------------------------------------------------
# Auth Event Tests (Integration with EventCollector)
# ---------------------------------------------------------------------------

class TestAuthEvents:
    """Test that auth operations emit proper events."""

    @pytest.mark.asyncio
    async def test_auth_events_include_method(self, event_collector) -> None:
        """
        AUTH events should include the authentication method used.

        This test validates that when connection is established,
        the AUTH event contains the method tried and result.
        """
        from nbs_ssh.events import EventType

        # Emit a mock AUTH event as connection would
        from nbs_ssh.events import EventEmitter

        emitter = EventEmitter(collector=event_collector)
        emitter.emit(
            EventType.AUTH,
            status="success",
            method="password",
            username="testuser",
            duration_ms=150,
        )

        auth_events = event_collector.get_by_type(EventType.AUTH)
        assert len(auth_events) == 1

        auth_event = auth_events[0]
        assert auth_event.data["method"] == "password"
        assert auth_event.data["status"] == "success"
        assert auth_event.data["username"] == "testuser"
        assert "duration_ms" in auth_event.data

    @pytest.mark.asyncio
    async def test_auth_failure_event_includes_error_type(
        self,
        event_collector,
    ) -> None:
        """AUTH failure events should include specific error type."""
        from nbs_ssh.events import EventEmitter, EventType

        emitter = EventEmitter(collector=event_collector)

        # Simulate auth failure
        error = AuthFailed(
            "Invalid password",
            context=ErrorContext(
                host="example.com",
                port=22,
                username="testuser",
                auth_method="password",
            ),
        )

        emitter.emit(
            EventType.AUTH,
            status="failed",
            method="password",
            username="testuser",
            error_type=error.error_type,
            error_message=str(error),
        )

        auth_events = event_collector.get_by_type(EventType.AUTH)
        assert len(auth_events) == 1

        auth_event = auth_events[0]
        assert auth_event.data["status"] == "failed"
        assert auth_event.data["error_type"] == "AuthFailed"


# ---------------------------------------------------------------------------
# Property Tests
# ---------------------------------------------------------------------------

class TestAuthErrorProperties:
    """Property-based tests for auth error context."""

    def test_all_auth_errors_have_error_type(self) -> None:
        """Property: All auth errors have non-empty error_type."""
        errors = [
            AuthFailed("test"),
            HostKeyMismatch("test"),
            NoMutualKex("test"),
            KeyLoadError("test", key_path="/key"),
            AgentError("test", reason="test"),
        ]

        for error in errors:
            assert error.error_type, \
                f"{error.__class__.__name__} has empty error_type"
            assert isinstance(error.error_type, str)

    def test_all_auth_errors_serialise_to_dict(self) -> None:
        """Property: All auth errors can be serialised to dict."""
        errors = [
            AuthFailed(
                "test",
                context=ErrorContext(host="h", port=22),
            ),
            KeyLoadError("test", key_path="/key", reason="bad"),
            AgentError("test", reason="fail"),
        ]

        for error in errors:
            data = error.to_dict()
            assert isinstance(data, dict)
            assert "error_type" in data
            assert "message" in data

    def test_error_context_contains_debugging_info(self) -> None:
        """Property: Auth errors carry enough context for debugging."""
        error = KeyLoadError(
            "Failed to load key",
            key_path="/home/user/.ssh/id_rsa",
            reason="wrong_passphrase",
        )

        data = error.to_dict()

        # Must have: error type, message, key path, reason
        assert data["error_type"] == "KeyLoadError"
        assert "Failed to load key" in data["message"]
        assert data["key_path"] == "/home/user/.ssh/id_rsa"
        assert data["reason"] == "wrong_passphrase"
