"""
SSH authentication configuration and helpers.

Provides:
- AuthMethod enum: PASSWORD, PRIVATE_KEY, SSH_AGENT
- AuthConfig dataclass: Configuration for authentication
- Helper functions for loading keys with proper error handling
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Sequence

import asyncssh

from nbs_ssh.errors import AgentError, ErrorContext, KeyLoadError
from nbs_ssh.platform import expand_path, get_agent_available, get_openssh_agent_available


class AuthMethod(str, Enum):
    """Supported SSH authentication methods."""
    PASSWORD = "password"
    PRIVATE_KEY = "private_key"
    SSH_AGENT = "ssh_agent"


@dataclass
class AuthConfig:
    """
    SSH authentication configuration.

    Supports multiple authentication methods that can be tried in order:
    - Password authentication
    - Private key authentication (with optional passphrase)
    - SSH agent authentication

    Usage:
        # Password auth
        config = AuthConfig(method=AuthMethod.PASSWORD, password="secret")

        # Key auth
        config = AuthConfig(
            method=AuthMethod.PRIVATE_KEY,
            key_path=Path("~/.ssh/id_rsa"),
        )

        # Agent auth
        config = AuthConfig(method=AuthMethod.SSH_AGENT)

        # Multiple methods (fallback)
        configs = [
            AuthConfig(method=AuthMethod.SSH_AGENT),
            AuthConfig(method=AuthMethod.PRIVATE_KEY, key_path=...),
            AuthConfig(method=AuthMethod.PASSWORD, password=...),
        ]
    """
    method: AuthMethod
    password: str | None = None
    key_path: Path | str | None = None
    passphrase: str | None = None

    def __post_init__(self) -> None:
        """Validate configuration."""
        if self.method == AuthMethod.PASSWORD:
            assert self.password is not None, \
                "Password required for PASSWORD auth method"

        if self.method == AuthMethod.PRIVATE_KEY:
            assert self.key_path is not None, \
                "key_path required for PRIVATE_KEY auth method"

        # Normalise key_path to Path using platform-aware expansion
        if self.key_path is not None:
            self.key_path = expand_path(self.key_path)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for logging (excludes secrets)."""
        result = {"method": self.method.value}
        if self.key_path:
            result["key_path"] = str(self.key_path)
        return result


def load_private_key(
    key_path: Path | str,
    passphrase: str | None = None,
) -> asyncssh.SSHKey:
    """
    Load a private key from file.

    Args:
        key_path: Path to the private key file
        passphrase: Optional passphrase for encrypted keys

    Returns:
        Loaded SSH key

    Raises:
        KeyLoadError: If key cannot be loaded (file not found, bad format, wrong passphrase)
    """
    key_path = expand_path(key_path)

    # Check file exists
    if not key_path.exists():
        raise KeyLoadError(
            f"Private key file not found: {key_path}",
            key_path=str(key_path),
            reason="file_not_found",
        )

    # Check file is readable
    if not os.access(key_path, os.R_OK):
        raise KeyLoadError(
            f"Private key file not readable: {key_path}",
            key_path=str(key_path),
            reason="permission_denied",
        )

    try:
        return asyncssh.read_private_key(str(key_path), passphrase=passphrase)
    except asyncssh.KeyImportError as e:
        error_msg = str(e).lower()
        if "passphrase" in error_msg or "decrypt" in error_msg:
            reason = "wrong_passphrase"
        elif "format" in error_msg or "invalid" in error_msg:
            reason = "invalid_format"
        else:
            reason = "import_error"

        raise KeyLoadError(
            f"Failed to load private key {key_path}: {e}",
            key_path=str(key_path),
            reason=reason,
        ) from e
    except Exception as e:
        raise KeyLoadError(
            f"Unexpected error loading private key {key_path}: {e}",
            key_path=str(key_path),
            reason="unknown",
        ) from e


def check_agent_available() -> bool:
    """
    Check if SSH agent is available.

    On Unix: checks SSH_AUTH_SOCK environment variable
    On Windows: checks for Pageant and OpenSSH Authentication Agent service

    Returns:
        True if any SSH agent is available
    """
    return get_agent_available()


async def get_agent_keys() -> list[asyncssh.SSHKey]:
    """
    Get keys from SSH agent.

    Returns:
        List of keys available from the agent

    Raises:
        AgentError: If agent is not available or communication fails
    """
    auth_sock = os.environ.get("SSH_AUTH_SOCK")
    if not auth_sock:
        raise AgentError(
            "SSH agent not available: SSH_AUTH_SOCK not set",
            reason="no_auth_sock",
        )

    if not Path(auth_sock).exists():
        raise AgentError(
            f"SSH agent socket not found: {auth_sock}",
            reason="socket_not_found",
        )

    try:
        async with asyncssh.connect_agent() as agent:
            keys = await agent.get_keys()
            return list(keys)
    except asyncssh.ChannelOpenError as e:
        raise AgentError(
            f"Failed to connect to SSH agent: {e}",
            reason="connection_failed",
        ) from e
    except Exception as e:
        raise AgentError(
            f"SSH agent communication failed: {e}",
            reason="communication_error",
        ) from e


def create_password_auth(password: str) -> AuthConfig:
    """Create password authentication config."""
    return AuthConfig(method=AuthMethod.PASSWORD, password=password)


def create_key_auth(
    key_path: Path | str,
    passphrase: str | None = None,
) -> AuthConfig:
    """Create private key authentication config."""
    return AuthConfig(
        method=AuthMethod.PRIVATE_KEY,
        key_path=key_path,
        passphrase=passphrase,
    )


def create_agent_auth() -> AuthConfig:
    """Create SSH agent authentication config."""
    return AuthConfig(method=AuthMethod.SSH_AGENT)
