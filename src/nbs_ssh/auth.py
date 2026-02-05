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

from nbs_ssh.errors import AgentError, CertificateError, ErrorContext, KeyLoadError
from nbs_ssh.platform import expand_path, get_agent_available, get_openssh_agent_available


class AuthMethod(str, Enum):
    """Supported SSH authentication methods."""
    PASSWORD = "password"
    PRIVATE_KEY = "private_key"
    SSH_AGENT = "ssh_agent"
    GSSAPI = "gssapi"
    KEYBOARD_INTERACTIVE = "keyboard_interactive"


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
    # Certificate authentication (pairs with key_path for PRIVATE_KEY method)
    certificate_path: Path | str | None = None  # Path to SSH certificate file

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

        # Normalise certificate_path to Path using platform-aware expansion
        if self.certificate_path is not None:
            self.certificate_path = expand_path(self.certificate_path)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for logging (excludes secrets)."""
        result = {"method": self.method.value}
        if self.key_path:
            result["key_path"] = str(self.key_path)
        if self.certificate_path:
            result["certificate_path"] = str(self.certificate_path)
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


def load_certificate(
    cert_path: Path | str,
) -> asyncssh.SSHCertificate:
    """
    Load an SSH certificate from file.

    SSH certificates are signed by a Certificate Authority (CA) and provide
    an alternative to distributing public keys via authorized_keys files.
    They are commonly used in enterprise environments for centralized
    key management.

    Args:
        cert_path: Path to the certificate file (typically ending in -cert.pub)

    Returns:
        Loaded SSH certificate

    Raises:
        CertificateError: If certificate cannot be loaded (file not found,
                         bad format, expired)
    """
    cert_path = expand_path(cert_path)

    # Check file exists
    if not cert_path.exists():
        raise CertificateError(
            f"Certificate file not found: {cert_path}",
            cert_path=str(cert_path),
            reason="file_not_found",
        )

    # Check file is readable
    if not os.access(cert_path, os.R_OK):
        raise CertificateError(
            f"Certificate file not readable: {cert_path}",
            cert_path=str(cert_path),
            reason="permission_denied",
        )

    try:
        return asyncssh.read_certificate(str(cert_path))
    except asyncssh.KeyImportError as e:
        error_msg = str(e).lower()
        if "expired" in error_msg:
            reason = "expired"
        elif "format" in error_msg or "invalid" in error_msg:
            reason = "invalid_format"
        else:
            reason = "import_error"

        raise CertificateError(
            f"Failed to load certificate {cert_path}: {e}",
            cert_path=str(cert_path),
            reason=reason,
        ) from e
    except Exception as e:
        raise CertificateError(
            f"Unexpected error loading certificate {cert_path}: {e}",
            cert_path=str(cert_path),
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
    certificate_path: Path | str | None = None,
) -> AuthConfig:
    """
    Create private key authentication config.

    Args:
        key_path: Path to the private key file
        passphrase: Optional passphrase for encrypted keys
        certificate_path: Optional path to SSH certificate file.
                          This matches OpenSSH's CertificateFile option.

    Returns:
        AuthConfig for private key authentication

    Example:
        # Key auth without certificate
        config = create_key_auth("~/.ssh/id_rsa")

        # Key auth with certificate (enterprise CA-signed)
        config = create_key_auth(
            key_path="~/.ssh/id_rsa",
            certificate_path="~/.ssh/id_rsa-cert.pub",
        )
    """
    return AuthConfig(
        method=AuthMethod.PRIVATE_KEY,
        key_path=key_path,
        passphrase=passphrase,
        certificate_path=certificate_path,
    )


def create_cert_auth(
    key_path: Path | str,
    certificate_path: Path | str,
    passphrase: str | None = None,
) -> AuthConfig:
    """
    Create certificate-based authentication config.

    This is a convenience function for certificate authentication,
    which requires both a private key and its associated certificate
    signed by a trusted Certificate Authority (CA).

    SSH certificates are commonly used in enterprise environments
    for centralized key management. The CA signs user certificates,
    and servers trust the CA rather than individual public keys.

    Args:
        key_path: Path to the private key file
        certificate_path: Path to the SSH certificate file
                          (typically key_path + "-cert.pub")
        passphrase: Optional passphrase for encrypted keys

    Returns:
        AuthConfig for certificate authentication

    Example:
        # Standard certificate auth
        config = create_cert_auth(
            key_path="~/.ssh/id_rsa",
            certificate_path="~/.ssh/id_rsa-cert.pub",
        )
    """
    return AuthConfig(
        method=AuthMethod.PRIVATE_KEY,
        key_path=key_path,
        passphrase=passphrase,
        certificate_path=certificate_path,
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

