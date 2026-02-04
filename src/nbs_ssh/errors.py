"""
SSH error taxonomy with structured data for JSONL logging.

Provides specific error types for different failure modes, enabling:
- Programmatic error handling with specific exception types
- Rich context for debugging and AI inspection
- Structured data for JSONL event logging

Error hierarchy:
- SSHError (base)
  - ConnectionError
    - ConnectionRefused
    - ConnectionTimeout
    - HostUnreachable
  - AuthenticationError
    - AuthFailed (invalid credentials)
    - HostKeyMismatch (known hosts verification failed)
    - NoMutualKex (key exchange algorithm mismatch)
    - KeyLoadError (private key file issues)
    - AgentError (SSH agent communication failed)
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class ErrorContext:
    """
    Structured context for SSH errors.

    Carries all information needed for:
    - Debugging the root cause
    - JSONL event logging
    - AI-assisted diagnosis
    """
    host: str | None = None
    port: int | None = None
    username: str | None = None
    auth_method: str | None = None
    key_path: str | None = None
    original_error: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary, excluding None values."""
        result = {}
        for key, value in asdict(self).items():
            if value is not None:
                if key == "extra" and isinstance(value, dict):
                    result.update(value)
                else:
                    result[key] = value
        return result


class SSHError(Exception):
    """
    Base exception for all SSH-related errors.

    All SSH errors carry structured context for logging and debugging.
    """

    def __init__(self, message: str, context: ErrorContext | None = None) -> None:
        super().__init__(message)
        self.context = context or ErrorContext()

    @property
    def error_type(self) -> str:
        """Return the error type name for logging."""
        return self.__class__.__name__

    def to_dict(self) -> dict[str, Any]:
        """Convert error to dictionary for JSONL logging."""
        return {
            "error_type": self.error_type,
            "message": str(self),
            **self.context.to_dict(),
        }


# ---------------------------------------------------------------------------
# Connection Errors
# ---------------------------------------------------------------------------

class SSHConnectionError(SSHError):
    """Base class for connection-related errors."""
    pass


class ConnectionRefused(SSHConnectionError):
    """Server actively refused the connection."""
    pass


class ConnectionTimeout(SSHConnectionError):
    """Connection attempt timed out."""
    pass


class HostUnreachable(SSHConnectionError):
    """Host could not be reached (network error)."""
    pass


# ---------------------------------------------------------------------------
# Authentication Errors
# ---------------------------------------------------------------------------

class AuthenticationError(SSHError):
    """Base class for authentication-related errors."""
    pass


class AuthFailed(AuthenticationError):
    """
    Authentication failed due to invalid credentials.

    This is raised when:
    - Password is incorrect
    - Private key is not accepted by server
    - All attempted auth methods failed
    """
    pass


class HostKeyMismatch(AuthenticationError):
    """
    Host key verification failed.

    The server's host key does not match the known_hosts file.
    This could indicate a man-in-the-middle attack or server reconfiguration.
    """
    pass


class NoMutualKex(AuthenticationError):
    """
    No mutual key exchange algorithm.

    Client and server could not agree on a key exchange algorithm.
    This typically indicates server configuration issues or outdated client.
    """
    pass


class KeyLoadError(AuthenticationError):
    """
    Failed to load private key.

    This is raised when:
    - Key file does not exist
    - Key file is not readable
    - Key file format is invalid
    - Passphrase is incorrect for encrypted key
    """

    def __init__(
        self,
        message: str,
        key_path: str | None = None,
        reason: str | None = None,
        context: ErrorContext | None = None,
    ) -> None:
        if context is None:
            context = ErrorContext()
        context.key_path = key_path
        if reason:
            context.extra["reason"] = reason
        super().__init__(message, context)


class AgentError(AuthenticationError):
    """
    SSH agent communication failed.

    This is raised when:
    - SSH agent is not running
    - Agent socket is not accessible
    - Agent returned an error
    """

    def __init__(
        self,
        message: str,
        reason: str | None = None,
        context: ErrorContext | None = None,
    ) -> None:
        if context is None:
            context = ErrorContext()
        if reason:
            context.extra["reason"] = reason
        super().__init__(message, context)
