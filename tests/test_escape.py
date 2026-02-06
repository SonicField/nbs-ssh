"""
Tests for OpenSSH-style escape sequence handler.

Tests:
- Escape detection at line start
- ~~ sends literal ~
- ~. triggers disconnect
- ~? shows help
- Escape not triggered mid-line
- -e none disables escapes
- Control character escape chars
"""
from __future__ import annotations

import io
import sys
from unittest.mock import MagicMock, patch

import pytest

from nbs_ssh.escape import (
    DisconnectRequested,
    EscapeHandler,
    SuspendRequested,
    parse_escape_char,
)


class TestEscapeHandlerBasics:
    """Basic escape handler functionality tests."""

    def test_default_escape_char_is_tilde(self) -> None:
        """Default escape character should be ~."""
        handler = EscapeHandler()
        assert handler.escape_char == "~"
        assert handler.enabled is True

    def test_disabled_with_none(self) -> None:
        """Escape sequences disabled when escape_char='none'."""
        handler = EscapeHandler(escape_char="none")
        assert handler.enabled is False
        assert handler.escape_char == "none"

    def test_disabled_with_empty_string(self) -> None:
        """Escape sequences disabled when escape_char=''."""
        handler = EscapeHandler(escape_char="")
        assert handler.enabled is False

    def test_custom_escape_char(self) -> None:
        """Custom escape character is accepted."""
        handler = EscapeHandler(escape_char="^")
        assert handler.escape_char == "^"
        assert handler.enabled is True

    def test_control_char_notation(self) -> None:
        """Control character notation (^A) is parsed correctly."""
        handler = EscapeHandler(escape_char="^A")
        # ^A is Ctrl-A = 0x01
        assert handler._escape_char == b"\x01"
        assert handler.enabled is True


class TestEscapeDetection:
    """Tests for escape sequence detection."""

    def test_escape_at_line_start(self) -> None:
        """Escape at line start is detected."""
        handler = EscapeHandler()

        # At line start (initial state), ~ should be pending
        result = handler.process_input(b"~")
        assert result is None  # Pending

    def test_escape_not_detected_mid_line(self) -> None:
        """Escape is not detected in the middle of a line."""
        handler = EscapeHandler()

        # First, type some characters (no longer at line start)
        result = handler.process_input(b"a")
        assert result == b"a"

        # Now ~ should be passed through, not an escape
        result = handler.process_input(b"~")
        assert result == b"~"

    def test_newline_resets_line_start(self) -> None:
        """After newline, we're back at line start."""
        handler = EscapeHandler()

        # Type some text
        result = handler.process_input(b"hello")
        assert result == b"hello"

        # Press Enter
        result = handler.process_input(b"\n")
        assert result == b"\n"

        # Now ~ should be an escape again
        result = handler.process_input(b"~")
        assert result is None  # Pending

    def test_carriage_return_resets_line_start(self) -> None:
        """After CR, we're back at line start."""
        handler = EscapeHandler()

        # Type some text
        handler.process_input(b"hello")

        # Press CR
        result = handler.process_input(b"\r")
        assert result == b"\r"

        # Now ~ should be an escape
        result = handler.process_input(b"~")
        assert result is None  # Pending


class TestEscapeSequences:
    """Tests for specific escape sequences."""

    def test_double_tilde_sends_literal(self) -> None:
        """~~ sends a literal ~ character."""
        handler = EscapeHandler()

        # Type ~
        result = handler.process_input(b"~")
        assert result is None  # Pending

        # Type ~ again
        result = handler.process_input(b"~")
        assert result == b"~"  # Literal ~

    def test_tilde_dot_triggers_disconnect(self) -> None:
        """~. triggers DisconnectRequested exception."""
        handler = EscapeHandler()

        # Type ~
        result = handler.process_input(b"~")
        assert result is None

        # Type .
        with pytest.raises(DisconnectRequested):
            handler.process_input(b".")

    def test_tilde_ctrl_z_triggers_suspend(self) -> None:
        """~^Z triggers SuspendRequested exception."""
        handler = EscapeHandler()

        # Type ~
        result = handler.process_input(b"~")
        assert result is None

        # Type Ctrl-Z (0x1a)
        with pytest.raises(SuspendRequested):
            handler.process_input(b"\x1a")

    def test_tilde_question_shows_help(self) -> None:
        """~? shows help message."""
        output = io.StringIO()
        handler = EscapeHandler(output_stream=output)

        # Type ~
        result = handler.process_input(b"~")
        assert result is None

        # Type ?
        result = handler.process_input(b"?")
        assert result is None  # Handled locally

        # Check help was printed
        help_text = output.getvalue()
        assert "disconnect" in help_text.lower()
        assert "~." in help_text

    def test_tilde_hash_lists_forwards(self) -> None:
        """~# lists forwarded connections."""
        output = io.StringIO()

        # With a callback that returns forwarding info
        def list_forwards() -> str:
            return "  #1 local:8080 -> remote:80"

        handler = EscapeHandler(
            output_stream=output,
            on_list_forwards=list_forwards,
        )

        # Type ~#
        handler.process_input(b"~")
        result = handler.process_input(b"#")
        assert result is None

        # Check output
        output_text = output.getvalue()
        assert "local:8080" in output_text

    def test_tilde_hash_empty_forwards(self) -> None:
        """~# with no forwards shows 'no connections'."""
        output = io.StringIO()
        handler = EscapeHandler(output_stream=output)

        # Type ~#
        handler.process_input(b"~")
        result = handler.process_input(b"#")
        assert result is None

        # Check output
        output_text = output.getvalue()
        assert "No connections open" in output_text

    def test_unrecognised_escape_sends_both_chars(self) -> None:
        """Unrecognised escape sequence sends both characters."""
        handler = EscapeHandler()

        # Type ~
        result = handler.process_input(b"~")
        assert result is None

        # Type something unrecognised
        result = handler.process_input(b"x")
        assert result == b"~x"


class TestDisabledEscapes:
    """Tests for disabled escape sequences."""

    def test_none_passes_through_tilde(self) -> None:
        """When disabled, ~ passes through."""
        handler = EscapeHandler(escape_char="none")

        # ~ at line start should pass through
        result = handler.process_input(b"~")
        assert result == b"~"

    def test_none_passes_through_tilde_dot(self) -> None:
        """When disabled, ~. passes through."""
        handler = EscapeHandler(escape_char="none")

        result = handler.process_input(b"~")
        assert result == b"~"

        result = handler.process_input(b".")
        assert result == b"."


class TestCustomEscapeChar:
    """Tests with custom escape characters."""

    def test_caret_as_escape(self) -> None:
        """^ can be used as escape character."""
        handler = EscapeHandler(escape_char="^")

        # ^ at line start
        result = handler.process_input(b"^")
        assert result is None  # Pending

        # ^. should disconnect
        with pytest.raises(DisconnectRequested):
            handler.process_input(b".")

    def test_tilde_ignored_with_caret_escape(self) -> None:
        """When escape is ^, ~ is just a normal character."""
        handler = EscapeHandler(escape_char="^")

        # ~ at line start should pass through
        result = handler.process_input(b"~")
        assert result == b"~"


class TestReset:
    """Tests for handler reset."""

    def test_reset_clears_pending(self) -> None:
        """reset() clears pending escape state."""
        handler = EscapeHandler()

        # Start an escape sequence
        result = handler.process_input(b"~")
        assert result is None

        # Reset
        handler.reset()

        # Now ~ should start a new pending escape, not continue
        result = handler.process_input(b"~")
        assert result is None  # New pending

    def test_reset_restores_line_start(self) -> None:
        """reset() restores to line start state."""
        handler = EscapeHandler()

        # Type some text
        handler.process_input(b"hello")

        # Reset
        handler.reset()

        # Now ~ should be escape again
        result = handler.process_input(b"~")
        assert result is None


class TestParseEscapeChar:
    """Tests for parse_escape_char function."""

    def test_parse_single_char(self) -> None:
        """Single character is accepted."""
        assert parse_escape_char("~") == "~"
        assert parse_escape_char("^") == "^"
        assert parse_escape_char("@") == "@"

    def test_parse_none(self) -> None:
        """'none' disables escapes."""
        assert parse_escape_char("none") == "none"
        assert parse_escape_char("NONE") == "none"
        assert parse_escape_char("None") == "none"

    def test_parse_control_char(self) -> None:
        """Control character notation is accepted."""
        assert parse_escape_char("^A") == "^A"
        assert parse_escape_char("^Z") == "^Z"
        assert parse_escape_char("^a") == "^a"

    def test_parse_invalid_control_char(self) -> None:
        """Invalid control char raises ValueError."""
        with pytest.raises(ValueError, match="Invalid control character"):
            parse_escape_char("^1")

    def test_parse_invalid_multi_char(self) -> None:
        """Multi-character string (not control) raises ValueError."""
        with pytest.raises(ValueError, match="Invalid escape character"):
            parse_escape_char("abc")


class TestIntegrationWithCLI:
    """Tests for CLI integration."""

    def test_argparse_escape_char_default(self) -> None:
        """CLI defaults to ~ for escape char."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["user@host"])
        assert args.escape_char == "~"

    def test_argparse_escape_char_custom(self) -> None:
        """CLI accepts -e option."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["-e", "^", "user@host"])
        assert args.escape_char == "^"

    def test_argparse_escape_char_none(self) -> None:
        """CLI accepts -e none."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["-e", "none", "user@host"])
        assert args.escape_char == "none"
