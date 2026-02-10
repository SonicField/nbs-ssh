"""
Input validation for SSH connection parameters.

Addresses security audit findings HIGH-4, MED-2, and MED-8 by validating
hostnames, usernames, and ports to prevent shell metacharacter injection,
newlines, null bytes, and invalid values.
"""

import re
from typing import Final

# Maximum lengths per RFC and POSIX standards
MAX_HOSTNAME_LENGTH: Final[int] = 253
MAX_LABEL_LENGTH: Final[int] = 63
MAX_USERNAME_LENGTH: Final[int] = 32

# Characters that must never appear in SSH parameters
# Includes shell metacharacters, control characters, and null bytes
DANGEROUS_CHARS: Final[frozenset[str]] = frozenset(
    "\x00"  # null byte
    "\n\r"  # newlines
    "`$(){}[]|;&<>\\'\""  # shell metacharacters
    "\t"  # tab (often shell-interpreted)
)

# Valid hostname label pattern: alphanumeric and hyphens, no leading/trailing hyphen
# Must start and end with alphanumeric
_LABEL_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$|^[a-zA-Z0-9]$"
)

# Valid username pattern: POSIX-style
# Must start with letter or underscore, followed by alphanumeric, underscore, or hyphen
_USERNAME_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[a-zA-Z_][a-zA-Z0-9_-]*$"
)


def _check_dangerous_chars(value: str, field_name: str) -> None:
    """
    Check for dangerous characters in a value.

    Args:
        value: The value to check
        field_name: Name of the field for error messages

    Raises:
        ValueError: If dangerous characters are found
    """
    assert isinstance(value, str), \
        f"Precondition: value must be str, got {type(value).__name__}"
    assert isinstance(field_name, str) and field_name, \
        f"Precondition: field_name must be non-empty str, got {field_name!r}"

    for char in value:
        if char in DANGEROUS_CHARS:
            # Provide readable name for control characters
            if char == "\x00":
                char_desc = "null byte"
            elif char == "\n":
                char_desc = "newline"
            elif char == "\r":
                char_desc = "carriage return"
            elif char == "\t":
                char_desc = "tab"
            else:
                char_desc = repr(char)
            raise ValueError(
                f"{field_name} contains forbidden character: {char_desc}"
            )


def validate_hostname(hostname: str) -> str:
    """
    Validate and normalise a hostname per RFC 952/1123.

    Validates:
    - Maximum 253 characters total
    - Labels (dot-separated segments) max 63 characters each
    - Labels contain only alphanumeric characters and hyphens
    - Labels do not start or end with hyphens
    - No shell metacharacters, newlines, or null bytes

    Args:
        hostname: The hostname to validate

    Returns:
        The normalised hostname (lowercase)

    Raises:
        ValueError: If the hostname is invalid, with a clear message
    """
    # Check type first (before emptiness, so None gets the right error)
    if not isinstance(hostname, str):
        raise ValueError(f"hostname must be a string, got {type(hostname).__name__}")

    # Check for empty
    if not hostname:
        raise ValueError("hostname must not be empty")

    # Check for dangerous characters first (before any processing)
    _check_dangerous_chars(hostname, "hostname")

    # Check total length
    if len(hostname) > MAX_HOSTNAME_LENGTH:
        raise ValueError(
            f"hostname exceeds maximum length of {MAX_HOSTNAME_LENGTH} characters "
            f"(got {len(hostname)})"
        )

    # Split into labels and validate each
    labels = hostname.split(".")

    # Must have at least one label
    if not labels or all(not label for label in labels):
        raise ValueError("hostname must contain at least one valid label")

    for i, label in enumerate(labels):
        # Empty labels indicate consecutive dots or leading/trailing dots
        if not label:
            if i == 0:
                raise ValueError("hostname must not start with a dot")
            elif i == len(labels) - 1:
                raise ValueError("hostname must not end with a dot")
            else:
                raise ValueError("hostname must not contain consecutive dots")

        # Check label length
        if len(label) > MAX_LABEL_LENGTH:
            raise ValueError(
                f"hostname label '{label}' exceeds maximum length of "
                f"{MAX_LABEL_LENGTH} characters (got {len(label)})"
            )

        # Check label format
        if not _LABEL_PATTERN.match(label):
            if label.startswith("-"):
                raise ValueError(
                    f"hostname label '{label}' must not start with a hyphen"
                )
            elif label.endswith("-"):
                raise ValueError(
                    f"hostname label '{label}' must not end with a hyphen"
                )
            else:
                raise ValueError(
                    f"hostname label '{label}' contains invalid characters "
                    "(only alphanumeric and hyphens allowed)"
                )

    # Postcondition: result is normalised lowercase
    result = hostname.lower()
    assert 0 < len(result) <= MAX_HOSTNAME_LENGTH, \
        f"Postcondition: normalised hostname length {len(result)} out of range"
    return result


def validate_username(username: str) -> str:
    """
    Validate a username per POSIX standards.

    Validates:
    - Maximum 32 characters
    - Starts with a letter or underscore
    - Contains only alphanumeric characters, underscores, and hyphens
    - No shell metacharacters, newlines, or null bytes

    Args:
        username: The username to validate

    Returns:
        The username unchanged

    Raises:
        ValueError: If the username is invalid, with a clear message
    """
    # Check type first (before emptiness, so None gets the right error)
    if not isinstance(username, str):
        raise ValueError(f"username must be a string, got {type(username).__name__}")

    # Check for empty
    if not username:
        raise ValueError("username must not be empty")

    # Check for dangerous characters first
    _check_dangerous_chars(username, "username")

    # Check length
    if len(username) > MAX_USERNAME_LENGTH:
        raise ValueError(
            f"username exceeds maximum length of {MAX_USERNAME_LENGTH} characters "
            f"(got {len(username)})"
        )

    # Check format
    if not _USERNAME_PATTERN.match(username):
        first_char = username[0]
        if not (first_char.isalpha() or first_char == "_"):
            raise ValueError(
                f"username must start with a letter or underscore, "
                f"got '{first_char}'"
            )
        else:
            # Find the offending character
            for char in username:
                if not (char.isalnum() or char in "_-"):
                    raise ValueError(
                        f"username contains invalid character: {repr(char)}"
                    )
            # Fallback message if we can't identify the specific issue
            raise ValueError(
                "username contains invalid characters "
                "(only alphanumeric, underscore, and hyphen allowed)"
            )

    assert _USERNAME_PATTERN.match(username), \
        f"Postcondition: validated username does not match pattern: {username!r}"
    return username


def validate_port(port: int) -> int:
    """
    Validate a port number per RFC 793.

    Validates:
    - Is an integer
    - In range 1-65535

    Args:
        port: The port number to validate

    Returns:
        The port number unchanged

    Raises:
        ValueError: If the port is invalid, with a clear message
    """
    # Reject bool first (bool is a subclass of int in Python)
    if isinstance(port, bool):
        raise ValueError("port must be an integer, got bool")

    # Check type
    if not isinstance(port, int):
        raise ValueError(f"port must be an integer, got {type(port).__name__}")

    # Check range
    if port < 1:
        raise ValueError(f"port must be at least 1, got {port}")

    if port > 65535:
        raise ValueError(f"port must be at most 65535, got {port}")

    assert 1 <= port <= 65535, \
        f"Postcondition: port {port} outside valid range 1-65535"
    return port
