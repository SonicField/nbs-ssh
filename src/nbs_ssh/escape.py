"""
OpenSSH-style escape sequence handler for interactive sessions.

Implements escape sequences that trigger when `~` is typed at the start of a line:

| Sequence | Action                              |
|----------|-------------------------------------|
| `~.`     | Disconnect from the session         |
| `~?`     | Show help for escape sequences      |
| `~#`     | List forwarded connections          |
| `~C`     | Open command line (runtime forward) |
| `~^Z`    | Suspend (background) the client     |
| `~~`     | Send a literal `~` character        |

Usage:
    handler = EscapeHandler(escape_char="~")

    # In your input loop:
    result = handler.process_input(data)
    if result is not None:
        # Send result to remote
        send_to_remote(result)
    # If result is None, escape was handled locally
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Callable


class DisconnectRequested(Exception):
    """
    User requested disconnection via escape sequence (~.).

    This exception should be caught by the shell session loop to
    cleanly disconnect from the remote host.
    """
    pass


class SuspendRequested(Exception):
    """
    User requested suspension via escape sequence (~^Z).

    This exception should be caught by the shell session loop to
    suspend the client process (SIGTSTP).
    """
    pass


@dataclass
class EscapeAction:
    """Result of escape sequence processing."""
    # Data to send to remote (None if handled locally)
    send_data: bytes | None = None
    # Whether to disconnect
    disconnect: bool = False
    # Whether to suspend
    suspend: bool = False
    # Message to display locally
    message: str | None = None


# Help text for escape sequences
ESCAPE_HELP = """
Supported escape sequences:
 ~.   - disconnect
 ~?   - this message
 ~#   - list forwarded connections
 ~C   - open command line (not implemented)
 ~^Z  - suspend (background) ssh
 ~~   - send the escape character
"""


class EscapeHandler:
    """
    Handler for OpenSSH-style escape sequences.

    Escape sequences are only triggered when the escape character (default ~)
    is the first character typed after a newline (Enter/Return).

    Example:
        handler = EscapeHandler()

        # Process each byte of user input
        result = handler.process_input(b'~')
        if result is None:
            # Escape pending, don't send yet
            pass
        else:
            send_to_remote(result)
    """

    def __init__(
        self,
        escape_char: str = "~",
        on_list_forwards: Callable[[], str] | None = None,
        output_stream: object | None = None,
    ) -> None:
        """
        Initialise escape handler.

        Args:
            escape_char: The escape character (default: ~). Set to empty string
                         or 'none' to disable escape sequences.
            on_list_forwards: Callback that returns a string listing forwarded
                              connections. Called when ~# is typed.
            output_stream: Stream for local output (default: sys.stderr).
        """
        # Precondition: escape_char must be a str
        assert isinstance(escape_char, str), (
            f"escape_char must be a str, got {type(escape_char).__name__}. "
            f"Check the caller is not passing bytes or another type."
        )

        # Normalise escape char
        if escape_char.lower() == "none" or escape_char == "":
            self._escape_char: bytes = b""  # Disabled
        elif escape_char.startswith("^") and len(escape_char) == 2:
            # Control character notation (e.g., ^A = 0x01)
            ctrl_letter = escape_char[1].upper()
            assert "A" <= ctrl_letter <= "Z", (
                f"Control character letter must be A-Z, got {ctrl_letter!r}. "
                f"Valid range is ^A (0x01) through ^Z (0x1a)."
            )
            ctrl_char = ord(ctrl_letter) - ord("A") + 1
            self._escape_char = bytes([ctrl_char])
        else:
            self._escape_char = escape_char.encode("utf-8")[:1]

        self._at_line_start = True
        self._escape_pending = False
        self._on_list_forwards = on_list_forwards
        self._output = output_stream or sys.stderr

    @property
    def enabled(self) -> bool:
        """Return True if escape sequences are enabled."""
        return len(self._escape_char) > 0

    @property
    def escape_char(self) -> str:
        """Return the escape character as a string."""
        if not self._escape_char:
            return "none"
        return self._escape_char.decode("utf-8", errors="replace")

    def process_input(self, data: bytes) -> bytes | None:
        """
        Process input data, handling escape sequences.

        Call this with each chunk of user input. Returns the data to send
        to the remote host, or None if the input was consumed locally
        (pending escape or local action like showing help).

        Args:
            data: Input bytes from the user

        Returns:
            bytes to send to remote, or None if escape handled locally

        Raises:
            DisconnectRequested: When ~. is entered
            SuspendRequested: When ~^Z is entered
        """
        # Precondition: data must be non-empty bytes
        assert isinstance(data, bytes) and len(data) > 0, (
            f"data must be non-empty bytes, got {type(data).__name__}"
            f"{f' of length {len(data)}' if isinstance(data, bytes) else ''}. "
            f"Empty input should be filtered before reaching the escape handler."
        )

        if not self.enabled:
            # Escape sequences disabled - pass through everything
            return data

        # Handle pending escape from previous call
        if self._escape_pending:
            self._escape_pending = False
            return self._handle_escape(data)

        # Check for escape at line start
        if self._at_line_start and data == self._escape_char:
            self._escape_pending = True
            return None  # Don't send yet, wait for next char

        # Track line position
        # Reset to line start after CR or LF
        self._at_line_start = data.endswith(b"\n") or data.endswith(b"\r")

        return data

    def _handle_escape(self, char: bytes) -> bytes | None:
        """
        Handle the character after the escape character.

        Args:
            char: The character typed after ~

        Returns:
            bytes to send to remote, or None if handled locally

        Raises:
            DisconnectRequested: When ~. is entered
            SuspendRequested: When ~^Z is entered
        """
        # Precondition: char must be exactly one byte
        assert isinstance(char, bytes) and len(char) == 1, (
            f"char must be a single byte, got {type(char).__name__}"
            f"{f' of length {len(char)}' if isinstance(char, bytes) else ''}. "
            f"Escape handler expects byte-at-a-time input after escape character."
        )

        # After handling, we're no longer at line start (unless this was newline)
        self._at_line_start = char in (b"\n", b"\r")

        if char == b".":
            # Disconnect
            raise DisconnectRequested()

        elif char == b"?":
            # Show help
            self._show_help()
            return None

        elif char == b"#":
            # List forwards
            self._list_forwards()
            return None

        elif char == b"C":
            # Command line (not implemented)
            self._print("\r\nCommand line not implemented.\r\n")
            return None

        elif char == b"\x1a":  # Ctrl-Z (0x1a)
            # Suspend
            raise SuspendRequested()

        elif char == self._escape_char:
            # Send literal escape char
            return self._escape_char

        else:
            # Not a recognised escape - send escape char + this char
            return self._escape_char + char

    def _show_help(self) -> None:
        """Display escape sequence help."""
        escape_str = self.escape_char
        help_text = ESCAPE_HELP.replace("~", escape_str)
        self._print(f"\r\n{help_text}")

    def _list_forwards(self) -> None:
        """Display list of forwarded connections."""
        if self._on_list_forwards:
            forwards = self._on_list_forwards()
            if forwards:
                self._print(f"\r\nThe following connections are open:\r\n{forwards}\r\n")
            else:
                self._print("\r\nNo connections open.\r\n")
        else:
            self._print("\r\nNo connections open.\r\n")

    def _print(self, message: str) -> None:
        """Print message to output stream."""
        try:
            self._output.write(message)
            self._output.flush()
        except (OSError, AttributeError):
            # Best-effort output: escape handler messages (help text, forward
            # listings) are informational only. If the output stream is broken
            # (OSError — e.g. stderr closed/redirected) or missing the write/
            # flush interface (AttributeError — e.g. a mock or None that
            # slipped past __init__), suppressing the error is correct because:
            # 1. The escape action itself (disconnect, suspend, passthrough)
            #    still takes effect regardless of display failure.
            # 2. Raising here would abort the SSH session over a cosmetic
            #    failure, which is worse than a missing help message.
            pass

    def reset(self) -> None:
        """Reset handler state (call when starting a new session)."""
        self._at_line_start = True
        self._escape_pending = False


def parse_escape_char(value: str) -> str:
    """
    Parse escape character from CLI argument.

    Accepts:
        - Single character: "~", "^", etc.
        - Control notation: "^A" for Ctrl-A
        - "none" to disable

    Args:
        value: The escape character specification

    Returns:
        Normalised escape character string

    Raises:
        ValueError: If value is invalid
    """
    # Precondition: value must be a str
    assert isinstance(value, str), (
        f"value must be a str, got {type(value).__name__}. "
        f"This function parses CLI string arguments, not {type(value).__name__}."
    )

    if value.lower() == "none":
        return "none"

    if len(value) == 1:
        return value

    if len(value) == 2 and value.startswith("^"):
        # Control character notation
        ctrl_letter = value[1].upper()
        if "A" <= ctrl_letter <= "Z":
            return value
        raise ValueError(
            f"Invalid control character: {value!r}. "
            "Use ^A through ^Z for control characters."
        )

    raise ValueError(
        f"Invalid escape character: {value!r}. "
        "Expected single character, ^X notation, or 'none'."
    )
