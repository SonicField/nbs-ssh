"""
Tests for host key verification with learning.

Tests:
- HostKeyVerifier loading and parsing known_hosts
- HostKeyResult for TRUSTED, UNKNOWN, CHANGED, REVOKED
- Saving host keys to known_hosts
- Policy handling (STRICT, ASK, ACCEPT_NEW, INSECURE)
- Integration with SSHConnection
"""
from __future__ import annotations

import base64
import tempfile
from pathlib import Path

import pytest

from nbs_ssh.host_key import (
    HostKeyChangedError,
    HostKeyPolicy,
    HostKeyResult,
    HostKeyUnknownError,
    HostKeyVerifier,
    _check_hashed_hostname,
    _format_host_for_known_hosts,
    _hash_hostname,
    _hostname_matches_pattern,
    get_key_fingerprint,
)


class TestHostnameFormatting:
    """Tests for hostname formatting in known_hosts format."""

    def test_format_port_22(self) -> None:
        """Port 22 uses plain hostname."""
        result = _format_host_for_known_hosts("example.com", 22)
        assert result == "example.com"

    def test_format_non_standard_port(self) -> None:
        """Non-standard ports use [hostname]:port format."""
        result = _format_host_for_known_hosts("example.com", 2222)
        assert result == "[example.com]:2222"

    def test_format_ip_address_port_22(self) -> None:
        """IP address with port 22."""
        result = _format_host_for_known_hosts("192.168.1.1", 22)
        assert result == "192.168.1.1"

    def test_format_ip_address_non_standard_port(self) -> None:
        """IP address with non-standard port."""
        result = _format_host_for_known_hosts("192.168.1.1", 2222)
        assert result == "[192.168.1.1]:2222"


class TestHostnameMatching:
    """Tests for hostname pattern matching."""

    def test_simple_hostname_match_port_22(self) -> None:
        """Simple hostname matches with port 22."""
        assert _hostname_matches_pattern("example.com", 22, "example.com")

    def test_simple_hostname_case_insensitive(self) -> None:
        """Hostname matching is case-insensitive."""
        assert _hostname_matches_pattern("Example.COM", 22, "example.com")
        assert _hostname_matches_pattern("example.com", 22, "EXAMPLE.COM")

    def test_simple_hostname_wrong_port(self) -> None:
        """Simple hostname doesn't match with non-22 port."""
        assert not _hostname_matches_pattern("example.com", 2222, "example.com")

    def test_bracketed_format_matches(self) -> None:
        """[hostname]:port format matches."""
        assert _hostname_matches_pattern("example.com", 2222, "[example.com]:2222")

    def test_bracketed_format_wrong_port(self) -> None:
        """[hostname]:port format doesn't match wrong port."""
        assert not _hostname_matches_pattern("example.com", 3333, "[example.com]:2222")

    def test_bracketed_format_wrong_host(self) -> None:
        """[hostname]:port format doesn't match wrong host."""
        assert not _hostname_matches_pattern("other.com", 2222, "[example.com]:2222")


class TestHashedHostnames:
    """Tests for hashed hostname support."""

    def test_hash_hostname_produces_valid_format(self) -> None:
        """Hashed hostname has correct format."""
        salt = b"x" * 20  # 20 bytes
        result = _hash_hostname("example.com", salt)
        assert result.startswith("|1|")
        parts = result.split("|")
        assert len(parts) == 4

    def test_check_hashed_hostname_matches(self) -> None:
        """Hashed hostname matches original."""
        salt = b"testsalt01234567890a"  # 20 bytes
        hashed = _hash_hostname("example.com", salt)
        assert _check_hashed_hostname(hashed, "example.com")

    def test_check_hashed_hostname_no_match(self) -> None:
        """Hashed hostname doesn't match different host."""
        salt = b"testsalt01234567890a"
        hashed = _hash_hostname("example.com", salt)
        assert not _check_hashed_hostname(hashed, "other.com")

    def test_hashed_hostname_pattern_matching(self) -> None:
        """_hostname_matches_pattern works with hashed patterns."""
        salt = b"testsalt01234567890a"
        hashed = _hash_hostname("example.com", salt)
        assert _hostname_matches_pattern("example.com", 22, hashed)
        assert not _hostname_matches_pattern("example.com", 2222, hashed)

    def test_hashed_hostname_with_port(self) -> None:
        """Hashed hostname with port works correctly."""
        salt = b"testsalt01234567890a"
        hashed = _hash_hostname("[example.com]:2222", salt)
        assert _hostname_matches_pattern("example.com", 2222, hashed)


class TestHostKeyVerifierParsing:
    """Tests for HostKeyVerifier known_hosts parsing."""

    def test_parse_simple_entry(self) -> None:
        """Parse simple known_hosts entry."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".known_hosts", delete=False) as f:
            f.write("example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey\n")
            f.flush()
            path = Path(f.name)

        try:
            verifier = HostKeyVerifier(
                known_hosts_paths=[path],
                write_path=None,
                policy=HostKeyPolicy.STRICT,
            )
            assert len(verifier._entries) == 1
            entry = verifier._entries[0]
            assert entry.hostnames == ["example.com"]
            assert entry.key_type == "ssh-ed25519"
            assert entry.key_data == "AAAAC3NzaC1lZDI1NTE5AAAAITestKey"
            assert not entry.is_revoked
        finally:
            path.unlink()

    def test_parse_multiple_hostnames(self) -> None:
        """Parse entry with multiple hostnames."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".known_hosts", delete=False) as f:
            f.write("example.com,www.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey\n")
            f.flush()
            path = Path(f.name)

        try:
            verifier = HostKeyVerifier(
                known_hosts_paths=[path],
                write_path=None,
                policy=HostKeyPolicy.STRICT,
            )
            assert len(verifier._entries) == 1
            entry = verifier._entries[0]
            assert entry.hostnames == ["example.com", "www.example.com"]
        finally:
            path.unlink()

    def test_parse_revoked_entry(self) -> None:
        """Parse @revoked entry."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".known_hosts", delete=False) as f:
            f.write("@revoked example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey\n")
            f.flush()
            path = Path(f.name)

        try:
            verifier = HostKeyVerifier(
                known_hosts_paths=[path],
                write_path=None,
                policy=HostKeyPolicy.STRICT,
            )
            assert len(verifier._entries) == 1
            entry = verifier._entries[0]
            assert entry.is_revoked
        finally:
            path.unlink()

    def test_parse_bracketed_port(self) -> None:
        """Parse entry with [host]:port format."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".known_hosts", delete=False) as f:
            f.write("[example.com]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey\n")
            f.flush()
            path = Path(f.name)

        try:
            verifier = HostKeyVerifier(
                known_hosts_paths=[path],
                write_path=None,
                policy=HostKeyPolicy.STRICT,
            )
            assert len(verifier._entries) == 1
            entry = verifier._entries[0]
            assert entry.hostnames == ["[example.com]:2222"]
        finally:
            path.unlink()

    def test_skip_comments_and_empty_lines(self) -> None:
        """Comments and empty lines are skipped."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".known_hosts", delete=False) as f:
            f.write("# This is a comment\n")
            f.write("\n")
            f.write("example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey\n")
            f.write("   \n")
            f.flush()
            path = Path(f.name)

        try:
            verifier = HostKeyVerifier(
                known_hosts_paths=[path],
                write_path=None,
                policy=HostKeyPolicy.STRICT,
            )
            assert len(verifier._entries) == 1
        finally:
            path.unlink()

    def test_load_multiple_files(self) -> None:
        """Load entries from multiple known_hosts files."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".known_hosts1", delete=False) as f1:
            f1.write("host1.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKey1\n")
            f1.flush()
            path1 = Path(f1.name)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".known_hosts2", delete=False) as f2:
            f2.write("host2.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKey2\n")
            f2.flush()
            path2 = Path(f2.name)

        try:
            verifier = HostKeyVerifier(
                known_hosts_paths=[path1, path2],
                write_path=None,
                policy=HostKeyPolicy.STRICT,
            )
            assert len(verifier._entries) == 2
        finally:
            path1.unlink()
            path2.unlink()

    def test_missing_file_skipped(self) -> None:
        """Non-existent known_hosts file is skipped silently."""
        verifier = HostKeyVerifier(
            known_hosts_paths=[Path("/nonexistent/path")],
            write_path=None,
            policy=HostKeyPolicy.STRICT,
        )
        assert len(verifier._entries) == 0


class TestHostKeyVerifierChecking:
    """Tests for HostKeyVerifier.check_host_key()."""

    def _make_mock_key(self, key_type: str, key_data: str):
        """Create a mock SSH key for testing."""

        class MockSSHKey:
            def __init__(self, key_type: str, key_data: str) -> None:
                self._key_type = key_type
                self._key_data = key_data

            @property
            def algorithm(self) -> bytes:
                return self._key_type.encode('ascii')

            @property
            def public_data(self) -> bytes:
                return base64.b64decode(self._key_data)

            def export_public_key(self, format: str) -> bytes:
                return f"{self._key_type} {self._key_data}".encode()

        return MockSSHKey(key_type, key_data)

    def test_check_trusted_key(self) -> None:
        """Matching key returns TRUSTED."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".known_hosts", delete=False) as f:
            f.write("example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey\n")
            f.flush()
            path = Path(f.name)

        try:
            verifier = HostKeyVerifier(
                known_hosts_paths=[path],
                write_path=None,
                policy=HostKeyPolicy.STRICT,
            )
            key = self._make_mock_key("ssh-ed25519", "AAAAC3NzaC1lZDI1NTE5AAAAITestKey")
            result = verifier.check_host_key("example.com", 22, key)
            assert result == HostKeyResult.TRUSTED
        finally:
            path.unlink()

    def test_check_unknown_host(self) -> None:
        """Unknown host returns UNKNOWN."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".known_hosts", delete=False) as f:
            f.write("example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey\n")
            f.flush()
            path = Path(f.name)

        try:
            verifier = HostKeyVerifier(
                known_hosts_paths=[path],
                write_path=None,
                policy=HostKeyPolicy.STRICT,
            )
            key = self._make_mock_key("ssh-ed25519", "AAAAC3NzaC1lZDI1NTE5AAAAITestKey")
            result = verifier.check_host_key("unknown.com", 22, key)
            assert result == HostKeyResult.UNKNOWN
        finally:
            path.unlink()

    def test_check_changed_key(self) -> None:
        """Different key for known host returns CHANGED."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".known_hosts", delete=False) as f:
            f.write("example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyA\n")
            f.flush()
            path = Path(f.name)

        try:
            verifier = HostKeyVerifier(
                known_hosts_paths=[path],
                write_path=None,
                policy=HostKeyPolicy.STRICT,
            )
            # Different key data (with valid base64 padding)
            key = self._make_mock_key("ssh-ed25519", "AAAAC3NzaC1lZDI1NTE5AAAAIOtherAB")
            result = verifier.check_host_key("example.com", 22, key)
            assert result == HostKeyResult.CHANGED
        finally:
            path.unlink()

    def test_check_revoked_key(self) -> None:
        """Revoked key returns REVOKED."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".known_hosts", delete=False) as f:
            f.write("@revoked example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey\n")
            f.flush()
            path = Path(f.name)

        try:
            verifier = HostKeyVerifier(
                known_hosts_paths=[path],
                write_path=None,
                policy=HostKeyPolicy.STRICT,
            )
            key = self._make_mock_key("ssh-ed25519", "AAAAC3NzaC1lZDI1NTE5AAAAITestKey")
            result = verifier.check_host_key("example.com", 22, key)
            assert result == HostKeyResult.REVOKED
        finally:
            path.unlink()

    def test_check_with_non_standard_port(self) -> None:
        """Correct port matching for non-standard ports."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".known_hosts", delete=False) as f:
            f.write("[example.com]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey\n")
            f.flush()
            path = Path(f.name)

        try:
            verifier = HostKeyVerifier(
                known_hosts_paths=[path],
                write_path=None,
                policy=HostKeyPolicy.STRICT,
            )
            key = self._make_mock_key("ssh-ed25519", "AAAAC3NzaC1lZDI1NTE5AAAAITestKey")

            # Matching port
            result = verifier.check_host_key("example.com", 2222, key)
            assert result == HostKeyResult.TRUSTED

            # Wrong port - should be unknown
            result = verifier.check_host_key("example.com", 22, key)
            assert result == HostKeyResult.UNKNOWN
        finally:
            path.unlink()


class TestHostKeyVerifierSaving:
    """Tests for HostKeyVerifier.save_host_key()."""

    def _make_mock_key(self, key_type: str, key_data: str):
        """Create a mock SSH key for testing."""

        class MockSSHKey:
            def __init__(self, key_type: str, key_data: str) -> None:
                self._key_type = key_type
                self._key_data = key_data

            @property
            def algorithm(self) -> bytes:
                return self._key_type.encode('ascii')

            @property
            def public_data(self) -> bytes:
                return base64.b64decode(self._key_data)

            def export_public_key(self, format: str) -> bytes:
                return f"{self._key_type} {self._key_data}".encode()

        return MockSSHKey(key_type, key_data)

    def test_save_host_key_creates_file(self) -> None:
        """Saving host key creates known_hosts file if missing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            write_path = Path(tmpdir) / ".ssh" / "known_hosts"

            verifier = HostKeyVerifier(
                known_hosts_paths=[],
                write_path=write_path,
                policy=HostKeyPolicy.ACCEPT_NEW,
            )

            key = self._make_mock_key("ssh-ed25519", "AAAAC3NzaC1lZDI1NTE5AAAAITestKey")
            verifier.save_host_key("example.com", 22, key)

            assert write_path.exists()
            content = write_path.read_text()
            assert "example.com" in content
            assert "ssh-ed25519" in content

    def test_save_host_key_appends(self) -> None:
        """Saving host key appends to existing file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            write_path = Path(tmpdir) / "known_hosts"
            write_path.write_text("existing.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExisting\n")

            verifier = HostKeyVerifier(
                known_hosts_paths=[write_path],
                write_path=write_path,
                policy=HostKeyPolicy.ACCEPT_NEW,
            )

            key = self._make_mock_key("ssh-ed25519", "AAAAC3NzaC1lZDI1NTE5AAAAINewKey")
            verifier.save_host_key("new.com", 22, key)

            content = write_path.read_text()
            assert "existing.com" in content
            assert "new.com" in content

    def test_save_host_key_non_standard_port(self) -> None:
        """Saving host key with non-standard port uses bracketed format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            write_path = Path(tmpdir) / "known_hosts"

            verifier = HostKeyVerifier(
                known_hosts_paths=[],
                write_path=write_path,
                policy=HostKeyPolicy.ACCEPT_NEW,
            )

            key = self._make_mock_key("ssh-ed25519", "AAAAC3NzaC1lZDI1NTE5AAAAITestKey")
            verifier.save_host_key("example.com", 2222, key)

            content = write_path.read_text()
            assert "[example.com]:2222" in content

    def test_save_host_key_updates_internal_state(self) -> None:
        """After saving, the host key should be trusted."""
        with tempfile.TemporaryDirectory() as tmpdir:
            write_path = Path(tmpdir) / "known_hosts"

            verifier = HostKeyVerifier(
                known_hosts_paths=[],
                write_path=write_path,
                policy=HostKeyPolicy.ACCEPT_NEW,
            )

            key = self._make_mock_key("ssh-ed25519", "AAAAC3NzaC1lZDI1NTE5AAAAITestKey")

            # Before saving - unknown
            result = verifier.check_host_key("example.com", 22, key)
            assert result == HostKeyResult.UNKNOWN

            # Save
            verifier.save_host_key("example.com", 22, key)

            # After saving - trusted
            result = verifier.check_host_key("example.com", 22, key)
            assert result == HostKeyResult.TRUSTED

    def test_save_host_key_no_write_path_raises(self) -> None:
        """Saving without write_path raises RuntimeError."""
        verifier = HostKeyVerifier(
            known_hosts_paths=[],
            write_path=None,
            policy=HostKeyPolicy.ACCEPT_NEW,
        )

        key = self._make_mock_key("ssh-ed25519", "AAAAC3NzaC1lZDI1NTE5AAAAITestKey")

        with pytest.raises(RuntimeError, match="No write path"):
            verifier.save_host_key("example.com", 22, key)


class TestHostKeyPolicy:
    """Tests for HostKeyPolicy enum values."""

    def test_policy_values(self) -> None:
        """HostKeyPolicy has expected values."""
        assert HostKeyPolicy.STRICT.value == "strict"
        assert HostKeyPolicy.ASK.value == "ask"
        assert HostKeyPolicy.ACCEPT_NEW.value == "accept_new"
        assert HostKeyPolicy.INSECURE.value == "insecure"


class TestHostKeyErrors:
    """Tests for host key error classes."""

    def test_changed_error_message(self) -> None:
        """HostKeyChangedError has OpenSSH-like message."""
        error = HostKeyChangedError(
            host="example.com",
            port=22,
            server_fingerprint="SHA256:abc123",
            stored_fingerprints=[("ssh-ed25519", "SHA256:oldkey")],
        )

        message = str(error)
        assert "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED" in message
        assert "example.com" in message
        assert "SHA256:abc123" in message
        assert "SHA256:oldkey" in message

    def test_unknown_error_message(self) -> None:
        """HostKeyUnknownError has descriptive message."""
        error = HostKeyUnknownError(
            host="example.com",
            port=22,
            fingerprint="SHA256:abc123",
        )

        message = str(error)
        assert "example.com" in message
        assert "SHA256:abc123" in message


class TestGetKeyFingerprint:
    """Tests for get_key_fingerprint function."""

    def test_sha256_fingerprint(self) -> None:
        """SHA256 fingerprint has correct format."""

        class MockKey:
            @property
            def public_data(self) -> bytes:
                return b"test key data"

        key = MockKey()
        fp = get_key_fingerprint(key, "sha256")  # type: ignore
        assert fp.startswith("SHA256:")

    def test_md5_fingerprint(self) -> None:
        """MD5 fingerprint has correct format."""

        class MockKey:
            @property
            def public_data(self) -> bytes:
                return b"test key data"

        key = MockKey()
        fp = get_key_fingerprint(key, "md5")  # type: ignore
        assert fp.startswith("MD5:")
        # MD5 uses colon-separated hex
        assert ":" in fp[4:]


@pytest.mark.asyncio
async def test_connection_with_insecure_policy() -> None:
    """Test SSHConnection with INSECURE policy accepts any key."""
    from nbs_ssh.connection import SSHConnection
    from nbs_ssh.testing.mock_server import MockServerConfig, MockSSHServer

    config = MockServerConfig(username="test", password="test")

    async with MockSSHServer(config) as server:
        async with SSHConnection(
            host="localhost",
            port=server.port,
            username="test",
            password="test",
            host_key_policy=HostKeyPolicy.INSECURE,
        ) as conn:
            result = await conn.exec("echo hello")
            assert result.exit_code == 0
            assert result.stdout.strip() == "hello"


@pytest.mark.asyncio
async def test_connection_with_accept_new_policy() -> None:
    """Test SSHConnection with ACCEPT_NEW policy accepts and saves keys."""
    from nbs_ssh.connection import SSHConnection
    from nbs_ssh.testing.mock_server import MockServerConfig, MockSSHServer

    config = MockServerConfig(username="test", password="test")

    with tempfile.TemporaryDirectory() as tmpdir:
        known_hosts_path = Path(tmpdir) / "known_hosts"

        async with MockSSHServer(config) as server:
            async with SSHConnection(
                host="localhost",
                port=server.port,
                username="test",
                password="test",
                known_hosts=[known_hosts_path],
                host_key_policy=HostKeyPolicy.ACCEPT_NEW,
            ) as conn:
                result = await conn.exec("echo hello")
                assert result.exit_code == 0

        # Check that key was saved
        assert known_hosts_path.exists()
        content = known_hosts_path.read_text()
        assert "localhost" in content or f"[localhost]:{server.port}" in content


@pytest.mark.asyncio
async def test_connection_with_strict_policy_unknown() -> None:
    """Test SSHConnection with STRICT policy rejects unknown hosts."""
    from nbs_ssh.connection import SSHConnection
    from nbs_ssh.testing.mock_server import MockServerConfig, MockSSHServer

    config = MockServerConfig(username="test", password="test")

    with tempfile.TemporaryDirectory() as tmpdir:
        # Empty known_hosts file
        known_hosts_path = Path(tmpdir) / "known_hosts"
        known_hosts_path.write_text("")

        async with MockSSHServer(config) as server:
            with pytest.raises((HostKeyUnknownError, Exception)):
                async with SSHConnection(
                    host="localhost",
                    port=server.port,
                    username="test",
                    password="test",
                    known_hosts=[known_hosts_path],
                    host_key_policy=HostKeyPolicy.STRICT,
                ) as conn:
                    await conn.exec("echo hello")


@pytest.mark.asyncio
async def test_connection_with_ask_policy_callback() -> None:
    """Test SSHConnection with ASK policy uses callback."""
    from nbs_ssh.connection import SSHConnection
    from nbs_ssh.testing.mock_server import MockServerConfig, MockSSHServer

    config = MockServerConfig(username="test", password="test")

    callback_called = False
    received_host: str = ""
    received_port: int = 0

    def on_unknown(host: str, port: int, key) -> bool:
        nonlocal callback_called, received_host, received_port
        callback_called = True
        received_host = host
        received_port = port
        return True  # Accept the key

    with tempfile.TemporaryDirectory() as tmpdir:
        known_hosts_path = Path(tmpdir) / "known_hosts"
        known_hosts_path.write_text("")

        async with MockSSHServer(config) as server:
            async with SSHConnection(
                host="localhost",
                port=server.port,
                username="test",
                password="test",
                known_hosts=[known_hosts_path],
                host_key_policy=HostKeyPolicy.ASK,
                on_unknown_host_key=on_unknown,
            ) as conn:
                result = await conn.exec("echo hello")
                assert result.exit_code == 0

    assert callback_called
    assert received_host == "localhost"
