"""
Tests for keyboard-interactive authentication.

Tests cover:
- Single prompt (password-like)
- Multiple prompts (2FA style)
- Failed authentication
- Custom callback handling
- Integration with auto-discovery

These tests verify Issue #4: Keyboard-interactive authentication support.
"""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

from nbs_ssh.auth import (
    AuthConfig,
    AuthMethod,
    create_keyboard_interactive_auth,
)
from nbs_ssh.connection import SSHConnection
from nbs_ssh.testing.mock_server import MockServerConfig, MockSSHServer


# ---------------------------------------------------------------------------
# AuthConfig Tests for Keyboard-Interactive
# ---------------------------------------------------------------------------

class TestKeyboardInteractiveAuthConfig:
    """Test keyboard-interactive AuthConfig creation and validation."""

    def test_create_with_password(self) -> None:
        """Keyboard-interactive can be created with just a password."""
        config = create_keyboard_interactive_auth(password="secret")

        assert config.method == AuthMethod.KEYBOARD_INTERACTIVE
        assert config.password == "secret"
        assert config.kbdint_response_callback is None

    def test_create_with_callback(self) -> None:
        """Keyboard-interactive can be created with a callback."""
        def my_callback(name, instructions, prompts):
            return ["response1"]

        config = create_keyboard_interactive_auth(response_callback=my_callback)

        assert config.method == AuthMethod.KEYBOARD_INTERACTIVE
        assert config.password is None
        assert config.kbdint_response_callback is my_callback

    def test_create_with_both(self) -> None:
        """Keyboard-interactive can have both password and callback."""
        def my_callback(name, instructions, prompts):
            return ["response1"]

        config = create_keyboard_interactive_auth(
            password="secret",
            response_callback=my_callback,
        )

        assert config.method == AuthMethod.KEYBOARD_INTERACTIVE
        assert config.password == "secret"
        assert config.kbdint_response_callback is my_callback

    def test_requires_password_or_callback(self) -> None:
        """Keyboard-interactive requires either password or callback."""
        with pytest.raises(AssertionError, match="password or response_callback"):
            create_keyboard_interactive_auth()


# ---------------------------------------------------------------------------
# Mock Server Keyboard-Interactive Tests
# ---------------------------------------------------------------------------

class TestMockServerKeyboardInteractive:
    """Test MockSSHServer keyboard-interactive support."""

    @pytest.mark.asyncio
    async def test_single_password_prompt(self) -> None:
        """
        Hypothesis: Server with kbdint enabled and single password prompt
        accepts correct password via keyboard-interactive.
        """
        config = MockServerConfig(
            username="test",
            password="test",
            kbdint_enabled=True,
            kbdint_prompts=[("Password: ", False)],
            kbdint_expected_responses=["test"],
        )

        async with MockSSHServer(config) as server:
            # Connect with keyboard-interactive auth
            kbdint_config = create_keyboard_interactive_auth(password="test")

            async with SSHConnection(
                host="localhost",
                port=server.port,
                username="test",
                auth=kbdint_config,
                known_hosts=None,
            ) as conn:
                result = await conn.exec("echo hello")

                assert result.exit_code == 0
                assert "hello" in result.stdout

    @pytest.mark.asyncio
    async def test_multiple_prompts_2fa_style(self) -> None:
        """
        Hypothesis: Server with multiple prompts (password + OTP)
        accepts correct responses via callback.
        """
        config = MockServerConfig(
            username="test",
            password="test",
            kbdint_enabled=True,
            kbdint_name="Two-Factor Auth",
            kbdint_instructions="Enter password and verification code",
            kbdint_prompts=[
                ("Password: ", False),
                ("Verification code: ", True),
            ],
            kbdint_expected_responses=["test", "123456"],
        )

        # Track callback calls
        callback_calls = []

        def test_callback(name, instructions, prompts):
            callback_calls.append({
                "name": name,
                "instructions": instructions,
                "prompts": prompts,
            })
            # Return responses matching expected
            return ["test", "123456"]

        async with MockSSHServer(config) as server:
            kbdint_config = create_keyboard_interactive_auth(
                response_callback=test_callback
            )

            async with SSHConnection(
                host="localhost",
                port=server.port,
                username="test",
                auth=kbdint_config,
                known_hosts=None,
            ) as conn:
                result = await conn.exec("whoami")

                assert result.exit_code == 0
                assert "test" in result.stdout

        # Verify callback was called with correct arguments
        assert len(callback_calls) == 1
        assert callback_calls[0]["name"] == "Two-Factor Auth"
        assert callback_calls[0]["instructions"] == "Enter password and verification code"
        assert len(callback_calls[0]["prompts"]) == 2

    @pytest.mark.asyncio
    async def test_failed_authentication(self) -> None:
        """
        Hypothesis: Wrong responses cause authentication failure.
        """
        from nbs_ssh.errors import AuthFailed, SSHError

        config = MockServerConfig(
            username="test",
            password="test",
            kbdint_enabled=True,
            kbdint_prompts=[("Password: ", False)],
            kbdint_expected_responses=["correct_password"],
        )

        async with MockSSHServer(config) as server:
            # Try with wrong password
            kbdint_config = create_keyboard_interactive_auth(password="wrong")

            # Authentication failure may manifest as AuthFailed or SSHError
            # depending on how the server handles the rejection
            with pytest.raises(SSHError):
                async with SSHConnection(
                    host="localhost",
                    port=server.port,
                    username="test",
                    auth=kbdint_config,
                    known_hosts=None,
                    connect_timeout=5.0,  # Shorter timeout for failed auth
                ) as conn:
                    pass

    @pytest.mark.asyncio
    async def test_callback_takes_precedence_over_password(self) -> None:
        """
        Hypothesis: When both callback and password are provided,
        callback is used for responses.
        """
        config = MockServerConfig(
            username="test",
            password="test",
            kbdint_enabled=True,
            kbdint_prompts=[("Password: ", False)],
            kbdint_expected_responses=["from_callback"],
        )

        def callback(name, instructions, prompts):
            return ["from_callback"]

        async with MockSSHServer(config) as server:
            # Provide both password and callback - callback should be used
            kbdint_config = create_keyboard_interactive_auth(
                password="wrong_password",
                response_callback=callback,
            )

            async with SSHConnection(
                host="localhost",
                port=server.port,
                username="test",
                auth=kbdint_config,
                known_hosts=None,
            ) as conn:
                result = await conn.exec("echo success")

                assert result.exit_code == 0
                assert "success" in result.stdout


# ---------------------------------------------------------------------------
# Integration Tests
# ---------------------------------------------------------------------------

class TestKeyboardInteractiveIntegration:
    """Integration tests for keyboard-interactive auth."""

    @pytest.mark.asyncio
    async def test_kbdint_with_password_fallback(self) -> None:
        """
        Hypothesis: Can use keyboard-interactive as fallback when
        password uses keyboard-interactive prompts.
        """
        # Server only accepts keyboard-interactive, not password auth
        config = MockServerConfig(
            username="test",
            password="test",
            kbdint_enabled=True,
            kbdint_prompts=[("Password: ", False)],
            kbdint_expected_responses=["test"],
        )

        async with MockSSHServer(config) as server:
            # Use keyboard-interactive with password
            kbdint_config = create_keyboard_interactive_auth(password="test")

            async with SSHConnection(
                host="localhost",
                port=server.port,
                username="test",
                auth=kbdint_config,
                known_hosts=None,
            ) as conn:
                result = await conn.exec("echo integrated")

                assert result.exit_code == 0
                assert "integrated" in result.stdout

    @pytest.mark.asyncio
    async def test_auth_events_include_kbdint_method(self, event_collector) -> None:
        """
        Hypothesis: AUTH events should include keyboard-interactive
        as the method when used.
        """
        from nbs_ssh.events import EventType

        config = MockServerConfig(
            username="test",
            password="test",
            kbdint_enabled=True,
            kbdint_prompts=[("Password: ", False)],
            kbdint_expected_responses=["test"],
        )

        async with MockSSHServer(config) as server:
            kbdint_config = create_keyboard_interactive_auth(password="test")

            async with SSHConnection(
                host="localhost",
                port=server.port,
                username="test",
                auth=kbdint_config,
                known_hosts=None,
                event_collector=event_collector,
            ) as conn:
                await conn.exec("echo test")

        # Check that AUTH event was emitted
        auth_events = event_collector.get_by_type(EventType.AUTH)
        assert len(auth_events) >= 1

        # Find successful auth event
        success_events = [e for e in auth_events if e.data.get("status") == "success"]
        assert len(success_events) >= 1
        assert success_events[0].data["method"] == "keyboard_interactive"


# ---------------------------------------------------------------------------
# CLI Tests
# ---------------------------------------------------------------------------

class TestKeyboardInteractiveCLI:
    """Test CLI handling of keyboard-interactive prompts."""

    def test_cli_callback_handles_prompts(self) -> None:
        """
        Hypothesis: cli_kbdint_callback correctly handles prompts
        and returns responses.
        """
        from nbs_ssh.__main__ import cli_kbdint_callback

        # Mock input and getpass
        with patch("builtins.input", return_value="visible_input"):
            with patch("getpass.getpass", return_value="hidden_input"):
                prompts = [
                    ("Username: ", True),  # Echo enabled
                    ("Password: ", False),  # Echo disabled
                ]

                responses = cli_kbdint_callback("Test", "Instructions", prompts)

                assert len(responses) == 2
                assert responses[0] == "visible_input"  # From input()
                assert responses[1] == "hidden_input"  # From getpass()

    def test_cli_callback_displays_name_and_instructions(self, capsys) -> None:
        """
        Hypothesis: cli_kbdint_callback displays challenge name and
        instructions to stderr.
        """
        from nbs_ssh.__main__ import cli_kbdint_callback

        with patch("builtins.input", return_value="test"):
            with patch("getpass.getpass", return_value="test"):
                cli_kbdint_callback(
                    "Challenge Name",
                    "Please enter your credentials",
                    [("Enter: ", True)],
                )

        captured = capsys.readouterr()
        assert "Challenge Name" in captured.err
        assert "Please enter your credentials" in captured.err

    def test_cli_callback_handles_empty_name_instructions(self, capsys) -> None:
        """
        Hypothesis: cli_kbdint_callback works with empty name/instructions.
        """
        from nbs_ssh.__main__ import cli_kbdint_callback

        with patch("builtins.input", return_value="test"):
            responses = cli_kbdint_callback("", "", [("Input: ", True)])

        captured = capsys.readouterr()
        # Should not print empty strings
        assert responses == ["test"]
