"""
Tests for SSHInteractionHandler — interactive auth callback interface.

TDD tests written BEFORE implementation. All tests should FAIL until
SSHInteractionHandler is added to nbs-ssh.

Tests cover:
- Safe defaults (reject keys, empty kbdint responses, no password)
- Auto-discovery includes kbdint when handler provides on_kbdint
- Auto-discovery excludes kbdint when no handler is set
- Explicit auth= overrides handler (caller controls the chain)
- Handler kbdint callback propagates to all auth attempts (multi-factor)
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from nbs_ssh.connection import SSHConnection
from nbs_ssh.auth import AuthConfig, AuthMethod, create_keyboard_interactive_auth


# ---------------------------------------------------------------------------
# SSHInteractionHandler import — will fail until implemented
# ---------------------------------------------------------------------------

from nbs_ssh import SSHInteractionHandler


# ---------------------------------------------------------------------------
# Test: Safe Defaults
# ---------------------------------------------------------------------------

class TestInteractionHandlerDefaults:
    """A bare SSHInteractionHandler must be safe by default."""

    def test_on_host_key_rejects_by_default(self):
        """Default on_host_key returns False — unknown hosts are rejected."""
        handler = SSHInteractionHandler()
        assert handler.on_host_key("example.com", 22, "ssh-ed25519 SHA256:abc") is False

    def test_on_kbdint_returns_empty_by_default(self):
        """Default on_kbdint returns [] — auth fails gracefully."""
        handler = SSHInteractionHandler()
        result = handler.on_kbdint("", "", [("Password: ", False)])
        assert result == []

    def test_on_password_needed_returns_none_by_default(self):
        """Default on_password_needed returns None — password auth is skipped."""
        handler = SSHInteractionHandler()
        assert handler.on_password_needed("example.com", "user") is None


# ---------------------------------------------------------------------------
# Test: Auto-discovery includes kbdint when handler is set
# ---------------------------------------------------------------------------

class TestBuildAuthWithHandler:
    """When interaction_handler is set, auto-discovery should include kbdint."""

    def test_auto_discovery_includes_kbdint_with_handler(self):
        """When handler is set, auto-discovery adds kbdint to the chain."""
        handler = SSHInteractionHandler()

        conn = SSHConnection(
            host="example.com",
            interaction_handler=handler,
        )
        configs = conn._build_auth_configs(auth=None, password=None, client_keys=None)

        methods = [c.method for c in configs]
        assert AuthMethod.KEYBOARD_INTERACTIVE in methods

    def test_auto_discovery_excludes_kbdint_without_handler(self):
        """When no handler is set, auto-discovery does NOT include kbdint."""
        conn = SSHConnection(host="example.com")
        configs = conn._build_auth_configs(auth=None, password=None, client_keys=None)

        methods = [c.method for c in configs]
        assert AuthMethod.KEYBOARD_INTERACTIVE not in methods


# ---------------------------------------------------------------------------
# Test: Explicit auth= overrides handler
# ---------------------------------------------------------------------------

class TestExplicitAuthOverridesHandler:
    """When auth= is explicitly provided, handler does not add to the chain."""

    def test_explicit_auth_not_augmented_by_handler(self):
        """Explicit auth= is used as-is — handler's kbdint is NOT appended."""
        handler = SSHInteractionHandler()
        handler.on_kbdint = lambda name, instr, prompts: ["response"]

        explicit_auth = create_keyboard_interactive_auth(password="test")

        conn = SSHConnection(
            host="example.com",
            interaction_handler=handler,
        )
        configs = conn._build_auth_configs(
            auth=[explicit_auth], password=None, client_keys=None,
        )

        # Should be exactly the explicit auth, nothing added
        assert len(configs) == 1
        assert configs[0] is explicit_auth


# ---------------------------------------------------------------------------
# Test: Handler kbdint callback propagates to all auth attempts
# ---------------------------------------------------------------------------

class TestKbdintCallbackPropagation:
    """The kbdint callback must be available during all auth attempts
    for multi-factor flows (publickey partial success → kbdint challenge)."""

    def test_handler_kbdint_callback_in_auth_config(self):
        """The kbdint AuthConfig created by the handler has the callback attached."""
        handler = SSHInteractionHandler()

        conn = SSHConnection(
            host="example.com",
            interaction_handler=handler,
        )
        configs = conn._build_auth_configs(auth=None, password=None, client_keys=None)

        kbdint_configs = [c for c in configs if c.method == AuthMethod.KEYBOARD_INTERACTIVE]
        assert len(kbdint_configs) == 1
        # The callback should be the handler's on_kbdint method
        assert kbdint_configs[0].kbdint_response_callback is handler.on_kbdint
