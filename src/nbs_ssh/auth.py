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
from nbs_ssh.secure_string import SecureString


class AuthMethod(str, Enum):
    """Supported SSH authentication methods."""
    PASSWORD = "password"
    PRIVATE_KEY = "private_key"
    SSH_AGENT = "ssh_agent"
    GSSAPI = "gssapi"
    KEYBOARD_INTERACTIVE = "keyboard_interactive"
    PKCS11 = "pkcs11"
    SECURITY_KEY = "security_key"  # FIDO2/U2F hardware security keys


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
    - FIDO2/U2F security key authentication (YubiKey, etc.)

    SecureString Support:
        For enhanced security, password and passphrase fields accept SecureString
        objects. SecureString stores secrets in ctypes-controlled memory that can
        be explicitly eradicated (overwritten with random bytes) when no longer
        needed.

    Usage:
        # Password auth
        config = AuthConfig(method=AuthMethod.PASSWORD, password="secret")

        # Password auth with SecureString (recommended for sensitive environments)
        from nbs_ssh import SecureString
        password = SecureString(getpass.getpass())
        config = AuthConfig(method=AuthMethod.PASSWORD, password=password)
        # ... after use ...
        password.eradicate()  # Overwrites memory with random bytes

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

        # FIDO2/U2F security key auth (resident keys)
        config = AuthConfig(
            method=AuthMethod.SECURITY_KEY,
            security_key_pin="123456",  # Required for FIDO2 resident keys
        )

        # FIDO2/U2F security key auth (sk-* key file)
        config = AuthConfig(
            method=AuthMethod.SECURITY_KEY,
            key_path=Path("~/.ssh/id_ed25519_sk"),
        )

        # Multiple methods (fallback)
        configs = [
            AuthConfig(method=AuthMethod.SSH_AGENT),
            AuthConfig(method=AuthMethod.PRIVATE_KEY, key_path=...),
            AuthConfig(method=AuthMethod.PASSWORD, password=...),
        ]
    """
    method: AuthMethod
    password: str | SecureString | None = None
    key_path: Path | str | None = None
    passphrase: str | SecureString | None = None
    # Callback for keyboard-interactive: (name, instructions, prompts) -> responses
    # prompts is list of (prompt_text, echo_enabled) tuples
    # Should return list of responses matching prompts
    kbdint_response_callback: Callable[
        [str, str, list[tuple[str, bool]]], list[str]
    ] | None = None
    # PKCS#11 options
    pkcs11_provider: str | None = None  # Path to PKCS#11 shared library
    pkcs11_pin: str | SecureString | None = None  # PIN for token access
    pkcs11_token_label: str | None = None  # Optional token label filter
    pkcs11_token_serial: str | bytes | None = None  # Optional token serial filter
    pkcs11_key_label: str | None = None  # Optional key label filter
    pkcs11_key_id: str | bytes | None = None  # Optional key ID filter
    # Lazy password callback: called only when password is actually needed
    # This avoids prompting for a password when earlier auth methods succeed
    password_callback: Callable[[], str | SecureString] | None = None
    # Certificate authentication (pairs with key_path for PRIVATE_KEY method)
    certificate_path: Path | str | None = None  # Path to SSH certificate file
    # FIDO2/U2F security key options
    security_key_pin: str | SecureString | None = None  # PIN for FIDO2 resident key access
    security_key_application: str = "ssh:"  # Application name (usually "ssh:")
    security_key_user: str | None = None  # Optional user filter for resident keys
    security_key_touch_required: bool = True  # Require user touch for each auth

    def __post_init__(self) -> None:
        """Validate configuration."""
        if self.method == AuthMethod.PASSWORD:
            assert self.password is not None or self.password_callback is not None, \
                "Password or password_callback required for PASSWORD auth method"

        if self.method == AuthMethod.PRIVATE_KEY:
            assert self.key_path is not None, \
                "key_path required for PRIVATE_KEY auth method"

        if self.method == AuthMethod.PKCS11:
            assert self.pkcs11_provider is not None, \
                "pkcs11_provider required for PKCS11 auth method"

        if self.method == AuthMethod.SECURITY_KEY:
            # Either key_path (for sk-* key file) or security_key_pin (for resident keys)
            # must be provided
            assert self.key_path is not None or self.security_key_pin is not None, \
                "Either key_path (for sk-* key file) or security_key_pin " \
                "(for resident keys) required for SECURITY_KEY auth method"

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
        if self.pkcs11_provider:
            result["pkcs11_provider"] = self.pkcs11_provider
        if self.pkcs11_token_label:
            result["pkcs11_token_label"] = self.pkcs11_token_label
        if self.pkcs11_key_label:
            result["pkcs11_key_label"] = self.pkcs11_key_label
        if self.certificate_path:
            result["certificate_path"] = str(self.certificate_path)
        # Security key fields (excluding PIN which is secret)
        if self.method == AuthMethod.SECURITY_KEY:
            result["security_key_application"] = self.security_key_application
            result["security_key_touch_required"] = self.security_key_touch_required
            if self.security_key_user:
                result["security_key_user"] = self.security_key_user
        return result


def load_private_key(
    key_path: Path | str,
    passphrase: str | SecureString | None = None,
) -> asyncssh.SSHKey:
    """
    Load a private key from file.

    Args:
        key_path: Path to the private key file
        passphrase: Optional passphrase for encrypted keys (str or SecureString)

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

    # Convert SecureString to str for asyncssh
    passphrase_str: str | None = None
    if passphrase is not None:
        passphrase_str = passphrase.reveal() if isinstance(passphrase, SecureString) else passphrase

    try:
        return asyncssh.read_private_key(str(key_path), passphrase=passphrase_str)
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


async def get_agent_cert_key_pair(
    cert_path: Path | str,
    agent_path: str | None = None,
) -> asyncssh.SSHKeyPair | None:
    """
    Create a key pair from a certificate identity file.

    When an SSH config IdentityFile points to a certificate (-cert.pub),
    the corresponding private key is at the same path with -cert.pub
    stripped.  This matches OpenSSH's behaviour: given identity file
    ``~/.ssh/id_rsa-cert.pub``, OpenSSH loads the private key from
    ``~/.ssh/id_rsa`` and the certificate from the -cert.pub file.

    If no private key file is found, attempts to create an agent-backed
    key pair using the certificate's public key.  The agent_path
    parameter specifies which agent socket to use (from IdentityAgent
    in SSH config).

    Args:
        cert_path: Path to the SSH certificate file (-cert.pub)
        agent_path: Path to the SSH agent socket (from IdentityAgent).
                    If None, uses SSH_AUTH_SOCK.

    Returns:
        SSHKeyPair with certificate, or None if neither private key
        file nor agent is available.

    Raises:
        CertificateError: If the certificate cannot be loaded
    """
    from asyncssh.agent import SSHAgentKeyPair

    cert_path = expand_path(cert_path)

    if not cert_path.exists():
        raise CertificateError(
            f"Certificate file not found: {cert_path}",
            cert_path=str(cert_path),
            reason="file_not_found",
        )

    # Load the certificate
    cert = load_certificate(cert_path)

    # Look for the corresponding private key file.
    # OpenSSH convention: strip -cert.pub to get the private key path.
    cert_str = str(cert_path)
    if cert_str.endswith("-cert.pub"):
        private_key_path = Path(cert_str[:-len("-cert.pub")])
        if private_key_path.exists() and os.access(private_key_path, os.R_OK):
            try:
                key = load_private_key(private_key_path)
                # Create key pair with certificate
                key_pair = asyncssh.load_keypairs(key)[0]
                key_pair.set_certificate(cert)
                return key_pair
            except (KeyLoadError, Exception):
                pass  # Fall through to agent-based approach

    # Fallback: try agent-based signing with the cert's public key
    subject_key = cert.key
    # Determine agent socket: explicit agent_path > SSH_AUTH_SOCK
    sock_path = agent_path or os.environ.get("SSH_AUTH_SOCK")
    if not sock_path or not Path(sock_path).exists():
        return None

    try:
        agent = await asyncssh.connect_agent(sock_path)
        # Try with raw public key (standard agent protocol)
        key_pair = SSHAgentKeyPair(
            agent, subject_key.algorithm, subject_key.public_data,
            b"cert-identity",
        )
        key_pair.set_certificate(cert)
        return key_pair
    except Exception:
        return None


def create_password_auth(password: str) -> AuthConfig:
    """Create password authentication config."""
    return AuthConfig(method=AuthMethod.PASSWORD, password=password)


def create_lazy_password_auth(
    callback: Callable[[], str | SecureString],
) -> AuthConfig:
    """
    Create lazy password authentication config.

    The callback is only invoked when password auth is actually attempted,
    avoiding unnecessary prompting when earlier auth methods (agent, keys,
    keyboard-interactive) succeed.

    Args:
        callback: Callable that returns a password (str or SecureString)
                  when invoked. Called at most once, only if password
                  auth is actually attempted.

    Returns:
        AuthConfig for lazy password authentication

    Example:
        config = create_lazy_password_auth(
            lambda: SecureString(getpass.getpass("Password: "))
        )
    """
    return AuthConfig(method=AuthMethod.PASSWORD, password_callback=callback)


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
    pin: str | SecureString | None = None,
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
        pin: Optional PIN for accessing the token (str or SecureString)
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

    # Convert SecureString to str for asyncssh
    pin_str: str | None = None
    if pin is not None:
        pin_str = pin.reveal() if isinstance(pin, SecureString) else pin

    try:
        return asyncssh.load_pkcs11_keys(
            provider=provider,
            pin=pin_str,
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


def check_security_key_available() -> bool:
    """
    Check if FIDO2/U2F security key support is available.

    Returns True if the fido2 package is installed and asyncssh
    security key support is enabled.

    Note: This checks if the library support is available, not whether
    a security key is physically connected.

    Returns:
        True if FIDO2/U2F security key authentication is available
    """
    try:
        from asyncssh.sk import sk_available
        return sk_available
    except ImportError:
        return False


def load_security_key_keys(
    pin: str | SecureString,
    *,
    application: str = "ssh:",
    user: str | None = None,
    touch_required: bool = True,
) -> Sequence[asyncssh.SSHKey]:
    """
    Load resident keys from attached FIDO2 security keys.

    This function discovers and loads SSH keys that are stored on
    FIDO2 security keys (YubiKey 5 series, etc.) as "resident keys"
    (also called "discoverable credentials").

    The user must have previously generated a resident key using:
        ssh-keygen -t ed25519-sk -O resident -O application=ssh:

    Args:
        pin: The PIN to access the security key (required for FIDO2, str or SecureString)
        application: The application name associated with the keys,
                     defaults to "ssh:" (the standard for SSH)
        user: Optional user name to filter keys by
        touch_required: Whether to require user touch when using the key,
                        defaults to True (recommended for security)

    Returns:
        List of SSHKey objects loaded from the security keys.
        The user name is stored in each key's comment field.

    Raises:
        ValueError: If security key support is not available
        KeyLoadError: If keys cannot be loaded from the security key

    Example:
        # Load all resident SSH keys
        keys = load_security_key_keys(pin="123456")

        # Load keys for a specific user
        keys = load_security_key_keys(pin="123456", user="alice")
    """
    if not check_security_key_available():
        raise ValueError(
            "Security key support not available. Install fido2: "
            "pip install fido2"
        )

    # Convert SecureString to str for asyncssh
    pin_str = pin.reveal() if isinstance(pin, SecureString) else pin

    try:
        return asyncssh.load_resident_keys(
            pin=pin_str,
            application=application,
            user=user,
            touch_required=touch_required,
        )
    except Exception as e:
        raise KeyLoadError(
            f"Failed to load keys from security key: {e}",
            key_path="security_key:resident",
            reason="security_key_error",
        ) from e


def load_security_key_file(
    key_path: Path | str,
    passphrase: str | SecureString | None = None,
) -> asyncssh.SSHKey:
    """
    Load an sk-* (security key) private key from file.

    This function loads sk-ssh-ed25519 or sk-ecdsa-sha2-nistp256 keys
    from disk. These key files were generated using:
        ssh-keygen -t ed25519-sk  # or -t ecdsa-sk

    Note: The key file only contains the public key and a "key handle".
    The actual signing is performed by the security key hardware.
    When using this key for authentication:
    - The security key must be physically connected
    - The user must touch the key (if touch_required was set during key generation)
    - The fido2 library must be installed

    Args:
        key_path: Path to the sk-* private key file
        passphrase: Optional passphrase if the key file is encrypted (str or SecureString)

    Returns:
        Loaded SSH key

    Raises:
        ValueError: If security key support is not available
        KeyLoadError: If key cannot be loaded

    Example:
        key = load_security_key_file("~/.ssh/id_ed25519_sk")
    """
    if not check_security_key_available():
        raise ValueError(
            "Security key support not available. Install fido2: "
            "pip install fido2"
        )

    key_path = expand_path(key_path)

    if not key_path.exists():
        raise KeyLoadError(
            f"Security key file not found: {key_path}",
            key_path=str(key_path),
            reason="file_not_found",
        )

    if not os.access(key_path, os.R_OK):
        raise KeyLoadError(
            f"Security key file not readable: {key_path}",
            key_path=str(key_path),
            reason="permission_denied",
        )

    # Convert SecureString to str for asyncssh
    passphrase_str: str | None = None
    if passphrase is not None:
        passphrase_str = passphrase.reveal() if isinstance(passphrase, SecureString) else passphrase

    try:
        return asyncssh.read_private_key(str(key_path), passphrase=passphrase_str)
    except asyncssh.KeyImportError as e:
        error_msg = str(e).lower()
        if "passphrase" in error_msg or "decrypt" in error_msg:
            reason = "wrong_passphrase"
        elif "format" in error_msg or "invalid" in error_msg:
            reason = "invalid_format"
        elif "security key" in error_msg:
            reason = "security_key_error"
        else:
            reason = "import_error"

        raise KeyLoadError(
            f"Failed to load security key file {key_path}: {e}",
            key_path=str(key_path),
            reason=reason,
        ) from e


def create_security_key_auth(
    *,
    pin: str | None = None,
    key_path: Path | str | None = None,
    passphrase: str | None = None,
    application: str = "ssh:",
    user: str | None = None,
    touch_required: bool = True,
) -> AuthConfig:
    """
    Create FIDO2/U2F security key authentication config.

    Security keys (YubiKey, SoloKey, etc.) provide hardware-backed SSH
    authentication using the FIDO2/U2F protocols. There are two modes:

    1. **Resident keys**: Keys stored on the security key itself.
       Requires PIN to access. Use the `pin` parameter.

    2. **File-based keys**: sk-* key files generated with ssh-keygen.
       The file contains the public key and key handle; the security
       key is needed for signing. Use the `key_path` parameter.

    Hardware requirements:
    - FIDO2 security key (YubiKey 5, SoloKey v2, etc.)
    - For resident keys: FIDO2 device with credential management
    - USB HID access to the security key

    Software requirements:
    - fido2 library: pip install fido2
    - May require udev rules on Linux for USB access

    Args:
        pin: PIN for accessing FIDO2 resident keys
        key_path: Path to sk-* key file (alternative to resident keys)
        passphrase: Passphrase if the sk-* key file is encrypted
        application: Application name for resident keys (default "ssh:")
        user: User name filter for resident keys
        touch_required: Require user touch for authentication (default True)

    Returns:
        AuthConfig for security key authentication

    Raises:
        AssertionError: If neither pin nor key_path is provided

    Example:
        # Resident key auth (keys stored on device)
        config = create_security_key_auth(pin="123456")

        # File-based sk key auth
        config = create_security_key_auth(
            key_path="~/.ssh/id_ed25519_sk"
        )

        # Resident key for specific user
        config = create_security_key_auth(
            pin="123456",
            user="alice",
        )
    """
    return AuthConfig(
        method=AuthMethod.SECURITY_KEY,
        key_path=key_path,
        passphrase=passphrase,
        security_key_pin=pin,
        security_key_application=application,
        security_key_user=user,
        security_key_touch_required=touch_required,
    )

