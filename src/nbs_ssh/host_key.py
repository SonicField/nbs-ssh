"""
Host key verification with OpenSSH-compatible learning.

Provides:
- HostKeyPolicy: Verification behaviour (strict, ask, accept-new, insecure)
- HostKeyResult: Verification outcome (trusted, unknown, changed, revoked)
- HostKeyVerifier: Loads known_hosts, checks keys, saves new entries
- HostKeyCapturingClient: AsyncSSH client for callback-based verification

OpenSSH-compatible known_hosts format:
- hostname key (for port 22)
- [hostname]:port key (for non-standard ports)
- Hashed hosts supported for reading (not writing)
"""
from __future__ import annotations

import hashlib
import hmac
import base64
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Any

import asyncssh


class HostKeyPolicy(str, Enum):
    """
    Host key verification policy.

    Controls how unknown and changed host keys are handled.
    """
    STRICT = "strict"       # Reject unknown, reject changed (for scripts)
    ASK = "ask"             # Prompt for unknown, reject changed (CLI default)
    ACCEPT_NEW = "accept_new"  # Accept unknown silently, reject changed
    INSECURE = "insecure"   # Accept all (testing only, like --no-host-check)


class HostKeyResult(str, Enum):
    """
    Result of host key verification.
    """
    TRUSTED = "trusted"     # Key matches known_hosts entry
    UNKNOWN = "unknown"     # Host not in known_hosts
    CHANGED = "changed"     # Key differs from known_hosts
    REVOKED = "revoked"     # Key is in revoked list (starts with @revoked)


@dataclass
class HostKeyEntry:
    """
    Parsed entry from a known_hosts file.

    Attributes:
        hostnames: List of hostnames/patterns this entry matches
        key_type: SSH key type (ssh-rsa, ssh-ed25519, etc.)
        key_data: Base64-encoded public key
        is_revoked: Whether this key is revoked (@revoked marker)
        is_hashed: Whether hostnames are hashed
        raw_line: Original line from file (for debugging)
    """
    hostnames: list[str]
    key_type: str
    key_data: str
    is_revoked: bool = False
    is_hashed: bool = False
    raw_line: str = ""


def _hash_hostname(hostname: str, salt: bytes) -> str:
    """
    Hash a hostname using OpenSSH's known_hosts hashing scheme.

    OpenSSH uses HMAC-SHA1 with a random salt, stored as:
    |1|<base64-salt>|<base64-hash>

    Args:
        hostname: The hostname to hash
        salt: 20-byte salt

    Returns:
        Hashed hostname in OpenSSH format
    """
    mac = hmac.new(salt, hostname.encode('utf-8'), hashlib.sha1)
    hash_bytes = mac.digest()
    salt_b64 = base64.b64encode(salt).decode('ascii')
    hash_b64 = base64.b64encode(hash_bytes).decode('ascii')
    return f"|1|{salt_b64}|{hash_b64}"


def _check_hashed_hostname(pattern: str, hostname: str) -> bool:
    """
    Check if a hostname matches a hashed known_hosts pattern.

    Args:
        pattern: Hashed pattern (|1|<salt>|<hash>)
        hostname: Hostname to check

    Returns:
        True if hostname matches the hashed pattern
    """
    if not pattern.startswith("|1|"):
        return False

    parts = pattern.split("|")
    if len(parts) != 4:
        return False

    try:
        salt = base64.b64decode(parts[2])
        stored_hash = base64.b64decode(parts[3])
    except (ValueError, base64.binascii.Error):
        return False

    # Compute hash with stored salt
    mac = hmac.new(salt, hostname.encode('utf-8'), hashlib.sha1)
    computed_hash = mac.digest()

    return hmac.compare_digest(stored_hash, computed_hash)


def _format_host_for_known_hosts(host: str, port: int) -> str:
    """
    Format host/port for known_hosts entry.

    OpenSSH uses:
    - hostname for port 22
    - [hostname]:port for other ports

    Args:
        host: Hostname or IP
        port: SSH port

    Returns:
        Formatted hostname string for known_hosts
    """
    if port == 22:
        return host
    else:
        return f"[{host}]:{port}"


def _hostname_matches_pattern(hostname: str, port: int, pattern: str) -> bool:
    """
    Check if hostname:port matches a known_hosts pattern.

    Patterns can be:
    - Simple hostname: example.com
    - Bracketed with port: [example.com]:2222
    - Hashed: |1|salt|hash
    - Wildcards: *.example.com (not yet implemented)

    Args:
        hostname: Hostname to check
        port: Port to check
        pattern: Pattern from known_hosts

    Returns:
        True if matches
    """
    # Check hashed hostname
    if pattern.startswith("|1|"):
        # For hashed, we need to check both hostname and [hostname]:port
        if _check_hashed_hostname(pattern, hostname):
            return port == 22
        bracketed = f"[{hostname}]:{port}"
        return _check_hashed_hostname(pattern, bracketed)

    # Check bracketed format [host]:port
    bracket_match = re.match(r'^\[([^\]]+)\]:(\d+)$', pattern)
    if bracket_match:
        pattern_host = bracket_match.group(1)
        pattern_port = int(bracket_match.group(2))
        return hostname.lower() == pattern_host.lower() and port == pattern_port

    # Simple hostname (port 22)
    return hostname.lower() == pattern.lower() and port == 22


def get_key_fingerprint(key: asyncssh.SSHKey, hash_algo: str = "sha256") -> str:
    """
    Get the fingerprint of an SSH key.

    Args:
        key: AsyncSSH key object
        hash_algo: Hash algorithm (sha256 or md5)

    Returns:
        Fingerprint string (e.g., "SHA256:...")
    """
    # asyncssh keys use public_data for the raw SSH public key blob
    public_data = key.public_data
    if hash_algo == "sha256":
        digest = hashlib.sha256(public_data).digest()
        b64 = base64.b64encode(digest).decode('ascii').rstrip('=')
        return f"SHA256:{b64}"
    elif hash_algo == "md5":
        digest = hashlib.md5(public_data).digest()
        hex_str = ':'.join(f'{b:02x}' for b in digest)
        return f"MD5:{hex_str}"
    else:
        raise ValueError(f"Unknown hash algorithm: {hash_algo}")


class HostKeyVerifier:
    """
    Verifies SSH host keys against known_hosts files.

    Loads and parses known_hosts files, checks server keys against them,
    and can save new entries (for ACCEPT_NEW or ASK policies).

    Usage:
        verifier = HostKeyVerifier(
            known_hosts_paths=[Path("~/.ssh/known_hosts")],
            write_path=Path("~/.ssh/known_hosts"),
            policy=HostKeyPolicy.ASK,
        )

        result = verifier.check_host_key(host, port, server_key)
        if result == HostKeyResult.UNKNOWN and user_approves:
            verifier.save_host_key(host, port, server_key)
    """

    def __init__(
        self,
        known_hosts_paths: list[Path],
        write_path: Path | None,
        policy: HostKeyPolicy,
        hash_known_hosts: bool = False,
    ) -> None:
        """
        Initialise the host key verifier.

        Args:
            known_hosts_paths: List of known_hosts files to read (existing files)
            write_path: Path to write new entries (usually user's known_hosts)
            policy: Verification policy (STRICT, ASK, ACCEPT_NEW, INSECURE)
            hash_known_hosts: If True, hash hostnames when saving to known_hosts
        """
        self._known_hosts_paths = known_hosts_paths
        self._write_path = write_path
        self._policy = policy
        self._hash_known_hosts = hash_known_hosts

        # Parsed entries indexed by key type + key data for fast lookup
        self._entries: list[HostKeyEntry] = []

        # Load known_hosts
        self._load_known_hosts()

    def _load_known_hosts(self) -> None:
        """Load and parse all known_hosts files."""
        for path in self._known_hosts_paths:
            if path.exists():
                self._parse_known_hosts_file(path)

    def _parse_known_hosts_file(self, path: Path) -> None:
        """
        Parse a known_hosts file.

        Known_hosts format:
        hostname[,hostname2] key_type key_data [comment]
        @revoked hostname key_type key_data [comment]
        |1|salt|hash key_type key_data [comment]

        Args:
            path: Path to known_hosts file
        """
        try:
            with open(path, 'r') as f:
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue

                    entry = self._parse_known_hosts_line(line)
                    if entry:
                        self._entries.append(entry)
        except (OSError, IOError):
            # File not readable, skip silently
            pass

    def _parse_known_hosts_line(self, line: str) -> HostKeyEntry | None:
        """
        Parse a single known_hosts line.

        Args:
            line: Line from known_hosts file

        Returns:
            HostKeyEntry or None if parse fails
        """
        is_revoked = False
        if line.startswith("@revoked "):
            is_revoked = True
            line = line[9:]  # Remove "@revoked "

        # Split into parts: hostnames, key_type, key_data, [comment]
        parts = line.split()
        if len(parts) < 3:
            return None

        hostnames_str = parts[0]
        key_type = parts[1]
        key_data = parts[2]

        # Parse comma-separated hostnames
        hostnames = [h.strip() for h in hostnames_str.split(',')]

        # Check if hostnames are hashed
        is_hashed = any(h.startswith("|1|") for h in hostnames)

        return HostKeyEntry(
            hostnames=hostnames,
            key_type=key_type,
            key_data=key_data,
            is_revoked=is_revoked,
            is_hashed=is_hashed,
            raw_line=line,
        )

    def check_host_key(
        self,
        host: str,
        port: int,
        key: asyncssh.SSHKey,
    ) -> HostKeyResult:
        """
        Check a server's host key against known_hosts.

        Args:
            host: Server hostname
            port: Server port
            key: Server's public key

        Returns:
            HostKeyResult indicating verification outcome
        """
        # Get key type - asyncssh returns bytes, decode to str
        key_type_raw = key.algorithm
        key_type = key_type_raw.decode('ascii') if isinstance(key_type_raw, bytes) else key_type_raw
        # Get key data from public_data
        key_data = base64.b64encode(key.public_data).decode('ascii')

        # Search for matching hostname entries
        matching_entries: list[HostKeyEntry] = []

        for entry in self._entries:
            for pattern in entry.hostnames:
                if _hostname_matches_pattern(host, port, pattern):
                    matching_entries.append(entry)
                    break

        if not matching_entries:
            return HostKeyResult.UNKNOWN

        # Check if any matching entry has the exact key
        for entry in matching_entries:
            # Compare key type and key data
            if entry.key_type == key_type:
                # Normalise key data for comparison (remove whitespace)
                stored_key = entry.key_data.replace(' ', '')
                server_key = key_data.replace(' ', '')

                if stored_key == server_key:
                    if entry.is_revoked:
                        return HostKeyResult.REVOKED
                    return HostKeyResult.TRUSTED

        # Host found but key doesn't match - either different key type or different key
        # This is a key CHANGE
        return HostKeyResult.CHANGED

    def save_host_key(
        self,
        host: str,
        port: int,
        key: asyncssh.SSHKey,
    ) -> None:
        """
        Save a host key to the write_path known_hosts file.

        Args:
            host: Server hostname
            port: Server port
            key: Server's public key

        Raises:
            RuntimeError: If write_path is None or not writable
        """
        if self._write_path is None:
            raise RuntimeError("No write path configured for host key saving")

        # Export key in OpenSSH format
        key_line = key.export_public_key('openssh').decode('utf-8').strip()

        # Format hostname (with optional hashing)
        host_entry = _format_host_for_known_hosts(host, port)

        if self._hash_known_hosts:
            # Hash the hostname using OpenSSH's scheme
            import secrets
            salt = secrets.token_bytes(20)  # 20-byte random salt
            host_entry = _hash_hostname(host_entry, salt)
            is_hashed = True
        else:
            is_hashed = False

        # Build the full line
        # key_line is "key_type key_data", so we just prepend the host
        full_line = f"{host_entry} {key_line}\n"

        # Ensure parent directory exists
        self._write_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

        # Append to file
        with open(self._write_path, 'a') as f:
            f.write(full_line)

        # Also add to in-memory entries
        parts = key_line.split(None, 2)
        if len(parts) >= 2:
            self._entries.append(HostKeyEntry(
                hostnames=[host_entry],
                key_type=parts[0],
                key_data=parts[1],
                is_revoked=False,
                is_hashed=is_hashed,
                raw_line=full_line.strip(),
            ))

    def get_stored_fingerprints(
        self,
        host: str,
        port: int,
    ) -> list[tuple[str, str]]:
        """
        Get fingerprints of stored keys for a host.

        Used for error messages when key has changed.

        Args:
            host: Server hostname
            port: Server port

        Returns:
            List of (key_type, fingerprint) tuples
        """
        fingerprints: list[tuple[str, str]] = []

        for entry in self._entries:
            for pattern in entry.hostnames:
                if _hostname_matches_pattern(host, port, pattern):
                    # Reconstruct key to get fingerprint
                    try:
                        key_bytes = base64.b64decode(entry.key_data)
                        digest = hashlib.sha256(key_bytes).digest()
                        b64 = base64.b64encode(digest).decode('ascii').rstrip('=')
                        fingerprints.append((entry.key_type, f"SHA256:{b64}"))
                    except (ValueError, base64.binascii.Error):
                        pass
                    break

        return fingerprints


class HostKeyCapturingClient(asyncssh.SSHClient):
    """
    AsyncSSH client that handles host key verification via callbacks.

    This client integrates with HostKeyVerifier to implement the
    verification policy.

    Usage:
        verifier = HostKeyVerifier(...)
        def on_unknown(host, port, key):
            # prompt user
            return user_approved

        client = HostKeyCapturingClient(verifier, on_unknown)
        conn = await asyncssh.connect(..., client_factory=lambda: client)
    """

    def __init__(
        self,
        verifier: HostKeyVerifier,
        on_unknown: Callable[[str, int, asyncssh.SSHKey], bool] | None = None,
        on_changed: Callable[[str, int, asyncssh.SSHKey, list[tuple[str, str]]], None] | None = None,
    ) -> None:
        """
        Initialise the host key client.

        Args:
            verifier: HostKeyVerifier for checking keys
            on_unknown: Callback for unknown hosts. Returns True to accept.
            on_changed: Callback for changed keys (for error reporting).
        """
        super().__init__()
        self._verifier = verifier
        self._on_unknown = on_unknown
        self._on_changed = on_changed
        self._host: str = ""
        self._port: int = 22
        self._result: HostKeyResult | None = None
        self._server_key: asyncssh.SSHKey | None = None

    def set_connection_info(self, host: str, port: int) -> None:
        """Set the host/port for this connection."""
        self._host = host
        self._port = port

    @property
    def verification_result(self) -> HostKeyResult | None:
        """Get the result of host key verification."""
        return self._result

    @property
    def server_key(self) -> asyncssh.SSHKey | None:
        """Get the server's host key."""
        return self._server_key

    def validate_host_public_key(
        self,
        host: str,
        addr: tuple[str, int],
        port: int,
        key: asyncssh.SSHKey,
    ) -> bool:
        """
        Validate the server's host public key.

        Called by AsyncSSH during connection. Returns True to accept.

        Args:
            host: Target hostname (may be empty)
            addr: (ip_address, port) tuple
            port: Target port
            key: Server's public key

        Returns:
            True to accept the key, False to reject
        """
        # Store the key for later use
        self._server_key = key

        # Use stored host/port if provided, otherwise use callback args
        check_host = self._host or host or addr[0]
        check_port = self._port or port

        result = self._verifier.check_host_key(check_host, check_port, key)
        self._result = result

        if result == HostKeyResult.TRUSTED:
            return True

        elif result == HostKeyResult.REVOKED:
            # Always reject revoked keys
            return False

        elif result == HostKeyResult.CHANGED:
            # Key mismatch - reject and report
            if self._on_changed:
                stored = self._verifier.get_stored_fingerprints(check_host, check_port)
                self._on_changed(check_host, check_port, key, stored)
            return False

        elif result == HostKeyResult.UNKNOWN:
            # Handle based on policy
            policy = self._verifier._policy

            if policy == HostKeyPolicy.INSECURE:
                return True
            elif policy == HostKeyPolicy.ACCEPT_NEW:
                return True
            elif policy == HostKeyPolicy.STRICT:
                return False
            elif policy == HostKeyPolicy.ASK:
                if self._on_unknown:
                    return self._on_unknown(check_host, check_port, key)
                return False

        return False


class HostKeyChangedError(Exception):
    """
    Raised when server's host key has changed.

    This is a security-critical error that should not be silently ignored.
    Contains details about the mismatch for user notification.
    """

    def __init__(
        self,
        host: str,
        port: int,
        server_fingerprint: str,
        stored_fingerprints: list[tuple[str, str]],
        message: str | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.server_fingerprint = server_fingerprint
        self.stored_fingerprints = stored_fingerprints

        if message is None:
            message = self._format_message()

        super().__init__(message)

    def _format_message(self) -> str:
        """Format the error message like OpenSSH does."""
        lines = [
            "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@",
            "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @",
            "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@",
            "IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!",
            "Someone could be eavesdropping on you right now (man-in-the-middle attack)!",
            f"The host key for {self.host} has changed.",
            f"",
            f"Server's current key fingerprint:",
            f"  {self.server_fingerprint}",
            f"",
            f"Expected fingerprint(s) from known_hosts:",
        ]
        for key_type, fp in self.stored_fingerprints:
            lines.append(f"  {key_type}: {fp}")

        lines.extend([
            "",
            "If you trust this host key, remove the old entry from known_hosts",
            "and try again, or use --strict-host-key-checking=no (INSECURE).",
        ])

        return "\n".join(lines)


class HostKeyUnknownError(Exception):
    """
    Raised when host key is unknown and policy is STRICT.

    Contains fingerprint information for logging/debugging.
    """

    def __init__(
        self,
        host: str,
        port: int,
        fingerprint: str,
        message: str | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.fingerprint = fingerprint

        if message is None:
            message = (
                f"Host key for {host}:{port} is not trusted.\n"
                f"Server fingerprint: {fingerprint}\n"
                f"Use --strict-host-key-checking=ask to be prompted, "
                f"or --strict-host-key-checking=accept-new to auto-accept."
            )

        super().__init__(message)
