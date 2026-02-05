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
from typing import Any, Callable, Sequence

import asyncssh

from nbs_ssh.errors import AgentError, ErrorContext, KeyLoadError
from nbs_ssh.platform import expand_path, get_agent_available, get_openssh_agent_available


class AuthMethod(str, Enum):
    """Supported SSH authentication methods."""
    PASSWORD = "password"
    PRIVATE_KEY = "private_key"
    SSH_AGENT = "ssh_agent"
    GSSAPI = "gssapi"
    KEYBOARD_INTERACTIVE = "keyboard_interactive"
    PKCS11 = "pkcs11"


@dataclass
class AuthConfig:
    """
    SSH authentication configuration.

    Supports multiple authentication methods that can be tried in order:
    - Password authentication
    - Private key authentication (with optional passphrase)
    - SSH agent authentication
    - GSSAPI/Kerberos authentication
    - Keyboard-interactive authentication (2FA, challenge-response)
    - PKCS#11 smart card/hardware token authentication

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

        # Keyboard-interactive auth (with password for auto-response)
        config = AuthConfig(
            method=AuthMethod.KEYBOARD_INTERACTIVE,
            password="secret",  # Used for auto-response
        )

        # Keyboard-interactive auth (with callback for prompts)
        config = AuthConfig(
            method=AuthMethod.KEYBOARD_INTERACTIVE,
            kbdint_response_callback=my_prompt_callback,
        )

        # PKCS#11 smart card/hardware token auth
        config = AuthConfig(
            method=AuthMethod.PKCS11,
            pkcs11_provider="/usr/lib/opensc-pkcs11.so",
            pkcs11_pin="123456",  # Optional
        )

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
    # Callback for keyboard-interactive: (name, instructions, prompts) -> responses
    # prompts is list of (prompt_text, echo_enabled) tuples
    # Should return list of responses matching prompts
    kbdint_response_callback: Callable[
        [str, str, list[tuple[str, bool]]], list[str]
    ] | None = None
    # PKCS#11 options
    pkcs11_provider: str | None = None  # Path to PKCS#11 shared library
    pkcs11_pin: str | None = None  # PIN for token access
    pkcs11_token_label: str | None = None  # Optional token label filter
    pkcs11_token_serial: str | bytes | None = None  # Optional token serial filter
    pkcs11_key_label: str | None = None  # Optional key label filter
    pkcs11_key_id: str | bytes | None = None  # Optional key ID filter

    def __post_init__(self) -> None:
        """Validate configuration."""
        if self.method == AuthMethod.PASSWORD:
            assert self.password is not None, \
                "Password required for PASSWORD auth method"

        if self.method == AuthMethod.PRIVATE_KEY:
            assert self.key_path is not None, \
                "key_path required for PRIVATE_KEY auth method"

        if self.method == AuthMethod.PKCS11:
            assert self.pkcs11_provider is not None, \
                "pkcs11_provider required for PKCS11 auth method"

        # Normalise key_path to Path using platform-aware expansion
        if self.key_path is not None:
            self.key_path = expand_path(self.key_path)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for logging (excludes secrets)."""
        result = {"method": self.method.value}
        if self.key_path:
            result["key_path"] = str(self.key_path)
        if self.pkcs11_provider:
            result["pkcs11_provider"] = self.pkcs11_provider
        if self.pkcs11_token_label:
            result["pkcs11_token_label"] = self.pkcs11_token_label
        if self.pkcs11_key_label:
            result["pkcs11_key_label"] = self.pkcs11_key_label
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


def create_gssapi_auth() -> AuthConfig:
    """Create GSSAPI/Kerberos authentication config."""
    return AuthConfig(method=AuthMethod.GSSAPI)


def create_keyboard_interactive_auth(
    password: str | None = None,
    response_callback: Callable[
        [str, str, list[tuple[str, bool]]], list[str]
    ] | None = None,
) -> AuthConfig:
    """
    Create keyboard-interactive authentication config.

    Keyboard-interactive auth is used for:
    - Two-factor authentication (2FA/MFA)
    - Password change prompts
    - Custom challenge-response authentication

    Args:
        password: Password to use for auto-responding to password prompts.
                  If provided, all prompts will receive this password.
        response_callback: Callback function for custom prompt handling.
                          Signature: (name, instructions, prompts) -> responses
                          where prompts is list of (prompt_text, echo_enabled) tuples.
                          If provided, takes precedence over password.

    Returns:
        AuthConfig for keyboard-interactive authentication.

    Raises:
        AssertionError: If neither password nor callback is provided.

    Example:
        # Auto-respond with password
        config = create_keyboard_interactive_auth(password="secret")

        # Custom callback for 2FA
        def my_callback(name, instructions, prompts):
            responses = []
            for prompt_text, echo in prompts:
                if "password" in prompt_text.lower():
                    responses.append("secret")
                elif "code" in prompt_text.lower():
                    responses.append(input(prompt_text))
                else:
                    responses.append(input(prompt_text))
            return responses

        config = create_keyboard_interactive_auth(response_callback=my_callback)
    """
    assert password is not None or response_callback is not None, \
        "Either password or response_callback required for keyboard-interactive auth"

    return AuthConfig(
        method=AuthMethod.KEYBOARD_INTERACTIVE,
        password=password,
        kbdint_response_callback=response_callback,
    )


def check_gssapi_available() -> bool:
    """
    Check if GSSAPI/Kerberos authentication is available.

    Checks:
    1. AsyncSSH has GSSAPI support (gssapi package installed)
    2. Valid Kerberos credentials exist

    Returns:
        True if GSSAPI authentication is likely to work
    """
    # Check if AsyncSSH has GSSAPI support
    try:
        from asyncssh.gss import gss_available
        if not gss_available:
            return False
    except ImportError:
        return False

    # Check for valid Kerberos credentials via klist
    import subprocess
    try:
        result = subprocess.run(
            ["klist", "-s"],  # -s = silent, just check status
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        # klist not available, try gssapi module directly
        try:
            import gssapi
            # Try to acquire default credentials
            creds = gssapi.Credentials(usage="initiate")
            return creds.lifetime > 0
        except Exception:
            return False


def check_pkcs11_available() -> bool:
    """
    Check if PKCS#11 support is available.

    Returns True if the python-pkcs11 package is installed and
    asyncssh PKCS#11 support is enabled.

    Returns:
        True if PKCS#11 authentication is available
    """
    try:
        from asyncssh.pkcs11 import pkcs11_available
        return pkcs11_available
    except ImportError:
        return False


def load_pkcs11_keys(
    provider: str,
    pin: str | None = None,
    *,
    token_label: str | None = None,
    token_serial: str | bytes | None = None,
    key_label: str | None = None,
    key_id: str | bytes | None = None,
) -> Sequence[asyncssh.SSHKeyPair]:
    """
    Load SSH key pairs from a PKCS#11 token/smart card.

    This wraps asyncssh.load_pkcs11_keys() with additional error handling.

    Args:
        provider: Path to the PKCS#11 provider shared library
                  (e.g., /usr/lib/opensc-pkcs11.so, /usr/lib/libyubico-pkcs11.so)
        pin: Optional PIN for accessing the token
        token_label: Filter by token label
        token_serial: Filter by token serial number
        key_label: Filter by key label
        key_id: Filter by key ID (hex string or bytes)

    Returns:
        List of SSHKeyPair objects from the token

    Raises:
        ValueError: If PKCS#11 support is not available
        KeyLoadError: If keys cannot be loaded from the token
    """
    if not check_pkcs11_available():
        raise ValueError(
            "PKCS#11 support not available. Install python-pkcs11: "
            "pip install python-pkcs11"
        )

    try:
        return asyncssh.load_pkcs11_keys(
            provider=provider,
            pin=pin,
            token_label=token_label,
            token_serial=token_serial,
            key_label=key_label,
            key_id=key_id,
        )
    except Exception as e:
        raise KeyLoadError(
            f"Failed to load keys from PKCS#11 provider {provider}: {e}",
            key_path=provider,
            reason="pkcs11_error",
        ) from e


def create_pkcs11_auth(
    provider: str,
    pin: str | None = None,
    *,
    token_label: str | None = None,
    token_serial: str | bytes | None = None,
    key_label: str | None = None,
    key_id: str | bytes | None = None,
) -> AuthConfig:
    """
    Create PKCS#11 smart card/hardware token authentication config.

    PKCS#11 allows using keys stored on hardware security modules (HSMs),
    smart cards, or tokens like YubiKey for SSH authentication.

    Common PKCS#11 provider paths:
    - OpenSC: /usr/lib/opensc-pkcs11.so
    - YubiKey (piv): /usr/lib/libykcs11.so
    - SoftHSM (testing): /usr/lib/softhsm/libsofthsm2.so

    Args:
        provider: Path to the PKCS#11 shared library
        pin: Optional PIN for token access (prompted if not provided)
        token_label: Filter by token label (useful with multiple tokens)
        token_serial: Filter by token serial number
        key_label: Filter by key label on the token
        key_id: Filter by key ID (hex string or bytes)

    Returns:
        AuthConfig for PKCS#11 authentication

    Example:
        # YubiKey PIV authentication
        config = create_pkcs11_auth(
            provider="/usr/lib/libykcs11.so",
            pin="123456",
        )

        # OpenSC smart card with specific key
        config = create_pkcs11_auth(
            provider="/usr/lib/opensc-pkcs11.so",
            key_label="SSH Key",
        )
    """
    return AuthConfig(
        method=AuthMethod.PKCS11,
        pkcs11_provider=provider,
        pkcs11_pin=pin,
        pkcs11_token_label=token_label,
        pkcs11_token_serial=token_serial,
        pkcs11_key_label=key_label,
        pkcs11_key_id=key_id,
    )

