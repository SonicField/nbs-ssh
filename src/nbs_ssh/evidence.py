"""
Evidence bundle system for AI-inspectable SSH diagnostics.

Provides:
- EvidenceBundle: Self-contained diagnostic package for debugging
- Secret redaction: Safely remove passwords and key contents
- Export/import: JSONL and dict serialisation

Evidence bundles capture everything needed to understand a connection failure:
- All JSONL events from the session
- Automation transcript (if any expect/respond was used)
- Negotiated SSH algorithms
- Disconnect reason
- Connection timing
- Host info (redacted)
- Structured error context
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from nbs_ssh.automation import Transcript
from nbs_ssh.errors import DisconnectReason
from nbs_ssh.events import Event


# Patterns for secret redaction
SECRET_PATTERNS = [
    # Password patterns in various formats
    (re.compile(r'"password"\s*:\s*"[^"]*"', re.IGNORECASE), '"password": "[REDACTED]"'),
    (re.compile(r"'password'\s*:\s*'[^']*'", re.IGNORECASE), "'password': '[REDACTED]'"),
    (re.compile(r"password\s*=\s*[^\s,\}]+", re.IGNORECASE), "password=[REDACTED]"),
    # Private key contents (PEM format)
    (
        re.compile(
            r"-----BEGIN[^-]+PRIVATE KEY-----.*?-----END[^-]+PRIVATE KEY-----",
            re.DOTALL,
        ),
        "[REDACTED PRIVATE KEY]",
    ),
    # OpenSSH private key format
    (
        re.compile(
            r"-----BEGIN OPENSSH PRIVATE KEY-----.*?-----END OPENSSH PRIVATE KEY-----",
            re.DOTALL,
        ),
        "[REDACTED PRIVATE KEY]",
    ),
    # Base64 encoded key-like content (long base64 strings)
    (re.compile(r"[A-Za-z0-9+/]{100,}={0,2}"), "[REDACTED BASE64]"),
]

# Keys that should have their values redacted in dicts
REDACT_KEYS = frozenset({
    "password",
    "passphrase",
    "private_key",
    "key_content",
    "secret",
    "token",
    "credential",
})


@dataclass
class AlgorithmInfo:
    """
    Negotiated SSH algorithms for the connection.

    Captures what encryption, MAC, and key exchange was actually used,
    which is essential for debugging compatibility issues.
    """
    kex: str | None = None  # Key exchange algorithm
    cipher_cs: str | None = None  # Cipher client-to-server
    cipher_sc: str | None = None  # Cipher server-to-client
    mac_cs: str | None = None  # MAC client-to-server
    mac_sc: str | None = None  # MAC server-to-client
    compression_cs: str | None = None  # Compression client-to-server
    compression_sc: str | None = None  # Compression server-to-client

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary, excluding None values."""
        return {k: v for k, v in asdict(self).items() if v is not None}

    @classmethod
    def from_asyncssh_conn(cls, conn) -> "AlgorithmInfo":
        """
        Extract algorithm info from an AsyncSSH connection.

        Args:
            conn: asyncssh.SSHClientConnection

        Returns:
            AlgorithmInfo with negotiated algorithms
        """
        if conn is None:
            return cls()

        try:
            # Get algorithm info from AsyncSSH connection
            info = cls()

            # Key exchange algorithm
            if hasattr(conn, 'get_extra_info'):
                extra = conn.get_extra_info('kex_alg')
                if extra:
                    info.kex = extra

            # Cipher algorithms
            if hasattr(conn, '_enc_alg_cs'):
                info.cipher_cs = conn._enc_alg_cs
            if hasattr(conn, '_enc_alg_sc'):
                info.cipher_sc = conn._enc_alg_sc

            # MAC algorithms
            if hasattr(conn, '_mac_alg_cs'):
                info.mac_cs = conn._mac_alg_cs
            if hasattr(conn, '_mac_alg_sc'):
                info.mac_sc = conn._mac_alg_sc

            # Compression
            if hasattr(conn, '_cmp_alg_cs'):
                info.compression_cs = conn._cmp_alg_cs
            if hasattr(conn, '_cmp_alg_sc'):
                info.compression_sc = conn._cmp_alg_sc

            return info
        except Exception:
            # If extraction fails, return empty info
            return cls()


@dataclass
class TimingInfo:
    """
    Connection timing information.

    Captures when key events occurred for performance debugging.
    """
    connect_start_ms: float | None = None
    connect_end_ms: float | None = None
    auth_start_ms: float | None = None
    auth_end_ms: float | None = None
    disconnect_ms: float | None = None
    bundle_created_ms: float = field(default_factory=lambda: time.time() * 1000)

    @property
    def connect_duration_ms(self) -> float | None:
        """Calculate connection duration in milliseconds."""
        if self.connect_start_ms and self.connect_end_ms:
            return self.connect_end_ms - self.connect_start_ms
        return None

    @property
    def auth_duration_ms(self) -> float | None:
        """Calculate authentication duration in milliseconds."""
        if self.auth_start_ms and self.auth_end_ms:
            return self.auth_end_ms - self.auth_start_ms
        return None

    @property
    def total_duration_ms(self) -> float | None:
        """Calculate total session duration from connect to disconnect."""
        if self.connect_start_ms and self.disconnect_ms:
            return self.disconnect_ms - self.connect_start_ms
        return None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary with computed durations."""
        result = {
            "connect_start_ms": self.connect_start_ms,
            "connect_end_ms": self.connect_end_ms,
            "auth_start_ms": self.auth_start_ms,
            "auth_end_ms": self.auth_end_ms,
            "disconnect_ms": self.disconnect_ms,
            "bundle_created_ms": self.bundle_created_ms,
        }
        # Add computed durations
        if self.connect_duration_ms is not None:
            result["connect_duration_ms"] = self.connect_duration_ms
        if self.auth_duration_ms is not None:
            result["auth_duration_ms"] = self.auth_duration_ms
        if self.total_duration_ms is not None:
            result["total_duration_ms"] = self.total_duration_ms

        return {k: v for k, v in result.items() if v is not None}


@dataclass
class HostInfo:
    """
    Host information for the connection.

    IP addresses are optionally redacted for privacy.
    """
    host: str
    port: int
    username: str | None = None
    redacted: bool = False

    def to_dict(self, redact: bool = True) -> dict[str, Any]:
        """
        Convert to dictionary, optionally redacting host.

        Args:
            redact: If True, replace host with redacted version

        Returns:
            Dictionary with host info
        """
        host = self.host
        if redact:
            # Redact IP addresses, keep hostnames partially visible
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
                # IPv4 - show only first octet
                host = host.split(".")[0] + ".xxx.xxx.xxx"
            elif ":" in host:
                # IPv6 - redact most of it
                host = "[REDACTED IPv6]"
            else:
                # Hostname - keep first part, redact rest
                parts = host.split(".")
                if len(parts) > 1:
                    host = parts[0] + ".[REDACTED]"

        return {
            "host": host,
            "port": self.port,
            "username": self.username,
            "redacted": redact,
        }


@dataclass
class EvidenceBundle:
    """
    Self-contained diagnostic package for SSH connection debugging.

    Contains everything needed to understand what happened during
    an SSH session, with secrets redacted for safe sharing.

    Usage:
        # Get bundle from connection
        bundle = await conn.get_evidence_bundle()

        # Export for analysis
        bundle.to_file(Path("debug.json"))

        # Or as JSONL for streaming
        jsonl = bundle.to_jsonl()
    """
    # Core diagnostic data
    events: list[Event] = field(default_factory=list)
    transcript: Transcript | None = None
    algorithms: AlgorithmInfo = field(default_factory=AlgorithmInfo)
    disconnect_reason: DisconnectReason = DisconnectReason.NORMAL
    timing: TimingInfo = field(default_factory=TimingInfo)
    host_info: HostInfo | None = None
    error_context: dict[str, Any] = field(default_factory=dict)

    # Metadata
    version: str = "1.0"
    created_ms: float = field(default_factory=lambda: time.time() * 1000)

    def to_dict(self, redact: bool = True) -> dict[str, Any]:
        """
        Convert bundle to dictionary.

        Args:
            redact: If True, redact secrets from the output

        Returns:
            Dictionary representation of the bundle
        """
        result: dict[str, Any] = {
            "version": self.version,
            "created_ms": self.created_ms,
            "events": [asdict(e) for e in self.events],
            "algorithms": self.algorithms.to_dict(),
            "disconnect_reason": self.disconnect_reason.value,
            "timing": self.timing.to_dict(),
            "error_context": self.error_context,
        }

        if self.transcript:
            result["transcript"] = self.transcript.to_dict()

        if self.host_info:
            result["host_info"] = self.host_info.to_dict(redact=redact)

        if redact:
            result = redact_secrets(result)

        return result

    def to_jsonl(self, redact: bool = True) -> str:
        """
        Export bundle as JSONL format.

        Each line contains one logical unit:
        1. Bundle metadata
        2. Each event as a separate line
        3. Transcript entries (if any)

        Args:
            redact: If True, redact secrets from output

        Returns:
            JSONL string
        """
        lines: list[str] = []

        # Bundle header
        header = {
            "type": "bundle_header",
            "version": self.version,
            "created_ms": self.created_ms,
            "algorithms": self.algorithms.to_dict(),
            "disconnect_reason": self.disconnect_reason.value,
            "timing": self.timing.to_dict(),
            "error_context": self.error_context,
        }
        if self.host_info:
            header["host_info"] = self.host_info.to_dict(redact=redact)

        if redact:
            header = redact_secrets(header)
        lines.append(json.dumps(header, default=str))

        # Events
        for event in self.events:
            event_dict = asdict(event)
            event_dict["type"] = "event"
            if redact:
                event_dict = redact_secrets(event_dict)
            lines.append(json.dumps(event_dict, default=str))

        # Transcript entries
        if self.transcript:
            for entry in self.transcript.entries:
                entry_dict = entry.to_dict()
                # Save the interaction type before overwriting with line marker
                entry_dict["interaction_type"] = entry_dict["type"]
                entry_dict["type"] = "transcript_entry"
                if redact:
                    entry_dict = redact_secrets(entry_dict)
                lines.append(json.dumps(entry_dict, default=str))

        return "\n".join(lines)

    def to_file(self, path: Path | str, format: str = "json", redact: bool = True) -> None:
        """
        Write bundle to file.

        Args:
            path: Output file path
            format: Output format - 'json' or 'jsonl'
            redact: If True, redact secrets from output
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        if format == "jsonl":
            content = self.to_jsonl(redact=redact)
        else:
            content = json.dumps(self.to_dict(redact=redact), indent=2, default=str)

        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

    @classmethod
    def from_file(cls, path: Path | str) -> "EvidenceBundle":
        """
        Load bundle from file.

        Supports both JSON and JSONL formats.

        Args:
            path: Path to bundle file

        Returns:
            Reconstructed EvidenceBundle
        """
        path = Path(path)
        assert path.exists(), f"Bundle file not found: {path}"

        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        # Detect format by checking if first line is valid JSON object
        first_line = content.split("\n")[0].strip()

        if first_line.startswith("{") and "type" in first_line:
            # JSONL format
            return cls._from_jsonl(content)
        else:
            # JSON format
            data = json.loads(content)
            return cls._from_dict(data)

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> "EvidenceBundle":
        """Reconstruct bundle from dictionary."""
        bundle = cls()
        bundle.version = data.get("version", "1.0")
        bundle.created_ms = data.get("created_ms", time.time() * 1000)

        # Reconstruct events
        for event_data in data.get("events", []):
            bundle.events.append(Event(
                event_type=event_data["event_type"],
                timestamp=event_data["timestamp"],
                data=event_data.get("data", {}),
            ))

        # Reconstruct algorithms
        if "algorithms" in data:
            alg = data["algorithms"]
            bundle.algorithms = AlgorithmInfo(
                kex=alg.get("kex"),
                cipher_cs=alg.get("cipher_cs"),
                cipher_sc=alg.get("cipher_sc"),
                mac_cs=alg.get("mac_cs"),
                mac_sc=alg.get("mac_sc"),
                compression_cs=alg.get("compression_cs"),
                compression_sc=alg.get("compression_sc"),
            )

        # Disconnect reason
        reason_str = data.get("disconnect_reason", "normal")
        try:
            bundle.disconnect_reason = DisconnectReason(reason_str)
        except ValueError:
            bundle.disconnect_reason = DisconnectReason.NORMAL

        # Timing
        if "timing" in data:
            t = data["timing"]
            bundle.timing = TimingInfo(
                connect_start_ms=t.get("connect_start_ms"),
                connect_end_ms=t.get("connect_end_ms"),
                auth_start_ms=t.get("auth_start_ms"),
                auth_end_ms=t.get("auth_end_ms"),
                disconnect_ms=t.get("disconnect_ms"),
                bundle_created_ms=t.get("bundle_created_ms", time.time() * 1000),
            )

        # Host info
        if "host_info" in data:
            h = data["host_info"]
            bundle.host_info = HostInfo(
                host=h["host"],
                port=h["port"],
                username=h.get("username"),
                redacted=h.get("redacted", False),
            )

        bundle.error_context = data.get("error_context", {})

        return bundle

    @classmethod
    def _from_jsonl(cls, content: str) -> "EvidenceBundle":
        """Reconstruct bundle from JSONL content."""
        bundle = cls()
        transcript_entries: list[dict] = []

        for line in content.strip().split("\n"):
            if not line.strip():
                continue

            data = json.loads(line)
            line_type = data.get("type")

            if line_type == "bundle_header":
                bundle.version = data.get("version", "1.0")
                bundle.created_ms = data.get("created_ms", time.time() * 1000)

                if "algorithms" in data:
                    alg = data["algorithms"]
                    bundle.algorithms = AlgorithmInfo(
                        kex=alg.get("kex"),
                        cipher_cs=alg.get("cipher_cs"),
                        cipher_sc=alg.get("cipher_sc"),
                        mac_cs=alg.get("mac_cs"),
                        mac_sc=alg.get("mac_sc"),
                        compression_cs=alg.get("compression_cs"),
                        compression_sc=alg.get("compression_sc"),
                    )

                reason_str = data.get("disconnect_reason", "normal")
                try:
                    bundle.disconnect_reason = DisconnectReason(reason_str)
                except ValueError:
                    bundle.disconnect_reason = DisconnectReason.NORMAL

                if "timing" in data:
                    t = data["timing"]
                    bundle.timing = TimingInfo(
                        connect_start_ms=t.get("connect_start_ms"),
                        connect_end_ms=t.get("connect_end_ms"),
                        auth_start_ms=t.get("auth_start_ms"),
                        auth_end_ms=t.get("auth_end_ms"),
                        disconnect_ms=t.get("disconnect_ms"),
                        bundle_created_ms=t.get("bundle_created_ms", time.time() * 1000),
                    )

                if "host_info" in data:
                    h = data["host_info"]
                    bundle.host_info = HostInfo(
                        host=h["host"],
                        port=h["port"],
                        username=h.get("username"),
                        redacted=h.get("redacted", False),
                    )

                bundle.error_context = data.get("error_context", {})

            elif line_type == "event":
                bundle.events.append(Event(
                    event_type=data["event_type"],
                    timestamp=data["timestamp"],
                    data=data.get("data", {}),
                ))

            elif line_type == "transcript_entry":
                # Store the whole entry - "type" field here is interaction_type
                transcript_entries.append(data)

        # Reconstruct transcript if we had entries
        if transcript_entries:
            from nbs_ssh.automation import InteractionType, TranscriptEntry
            bundle.transcript = Transcript()
            for entry_data in transcript_entries:
                # We saved interaction_type separately when serializing
                interaction_type_str = entry_data.get("interaction_type", "output")

                entry = TranscriptEntry(
                    timestamp_ms=entry_data["timestamp_ms"],
                    interaction_type=InteractionType(interaction_type_str),
                    content=entry_data["content"],
                    duration_ms=entry_data.get("duration_ms", 0.0),
                    metadata=entry_data.get("metadata", {}),
                )
                bundle.transcript._entries.append(entry)

        return bundle


def redact_secrets(data: Any) -> Any:
    """
    Redact secrets from data structure.

    Handles nested dicts, lists, and strings. Replaces:
    - Passwords with [REDACTED]
    - Private key contents with [REDACTED PRIVATE KEY]
    - Long base64 strings with [REDACTED BASE64]

    Args:
        data: Data structure to redact

    Returns:
        Redacted copy of the data
    """
    if isinstance(data, dict):
        result = {}
        for key, value in data.items():
            # Check if key suggests sensitive data
            key_lower = key.lower()
            if any(secret_key in key_lower for secret_key in REDACT_KEYS):
                if isinstance(value, str) and value:
                    result[key] = "[REDACTED]"
                else:
                    result[key] = value
            else:
                result[key] = redact_secrets(value)
        return result

    elif isinstance(data, list):
        return [redact_secrets(item) for item in data]

    elif isinstance(data, str):
        result = data
        for pattern, replacement in SECRET_PATTERNS:
            result = pattern.sub(replacement, result)
        return result

    else:
        return data


def redact_string(text: str) -> str:
    """
    Redact secrets from a string.

    Args:
        text: String to redact

    Returns:
        Redacted string
    """
    result = text
    for pattern, replacement in SECRET_PATTERNS:
        result = pattern.sub(replacement, result)
    return result
