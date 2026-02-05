"""
Tests for evidence bundle functionality.

Verifies:
- Bundle contains all required fields
- Secrets are properly redacted
- JSONL roundtrip preserves data
- Timing information is accurate
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from nbs_ssh.automation import Transcript
from nbs_ssh.errors import DisconnectReason
from nbs_ssh.events import Event, EventType
from nbs_ssh.evidence import (
    AlgorithmInfo,
    EvidenceBundle,
    HostInfo,
    TimingInfo,
    redact_secrets,
    redact_string,
)


class TestEvidenceBundle:
    """Test EvidenceBundle dataclass and methods."""

    def test_bundle_contains_all_required_fields(self) -> None:
        """Bundle should have all diagnostic fields."""
        bundle = EvidenceBundle()

        # Core fields exist
        assert hasattr(bundle, "events")
        assert hasattr(bundle, "transcript")
        assert hasattr(bundle, "algorithms")
        assert hasattr(bundle, "disconnect_reason")
        assert hasattr(bundle, "timing")
        assert hasattr(bundle, "host_info")
        assert hasattr(bundle, "error_context")

        # Metadata
        assert hasattr(bundle, "version")
        assert hasattr(bundle, "created_ms")

    def test_bundle_to_dict_includes_all_fields(self) -> None:
        """to_dict should include all bundle data."""
        events = [
            Event(event_type=EventType.CONNECT.value, data={"status": "initiating"}),
            Event(event_type=EventType.AUTH.value, data={"method": "password"}),
        ]
        bundle = EvidenceBundle(
            events=events,
            algorithms=AlgorithmInfo(kex="curve25519-sha256", cipher_cs="aes256-gcm"),
            disconnect_reason=DisconnectReason.NORMAL,
            timing=TimingInfo(connect_start_ms=1000, connect_end_ms=2000),
            host_info=HostInfo(host="example.com", port=22, username="user"),
            error_context={"test": "value"},
        )

        result = bundle.to_dict(redact=False)

        assert "events" in result
        assert len(result["events"]) == 2
        assert "algorithms" in result
        assert result["algorithms"]["kex"] == "curve25519-sha256"
        assert "disconnect_reason" in result
        assert result["disconnect_reason"] == "normal"
        assert "timing" in result
        assert "host_info" in result
        assert "error_context" in result

    def test_bundle_with_transcript(self) -> None:
        """Bundle should include transcript when provided."""
        transcript = Transcript()
        transcript.add_send("test command")

        bundle = EvidenceBundle(transcript=transcript)
        result = bundle.to_dict(redact=False)

        assert "transcript" in result
        assert result["transcript"]["entry_count"] == 1

    def test_bundle_to_jsonl_format(self) -> None:
        """to_jsonl should produce valid JSONL."""
        events = [
            Event(event_type=EventType.CONNECT.value),
            Event(event_type=EventType.AUTH.value),
        ]
        bundle = EvidenceBundle(
            events=events,
            host_info=HostInfo(host="test.com", port=22),
        )

        jsonl = bundle.to_jsonl(redact=False)
        lines = jsonl.strip().split("\n")

        # First line is header
        header = json.loads(lines[0])
        assert header["type"] == "bundle_header"

        # Following lines are events
        for line in lines[1:]:
            data = json.loads(line)
            assert data["type"] == "event"
            assert "event_type" in data


class TestSecretRedaction:
    """Test secret redaction functionality."""

    def test_redact_password_in_dict(self) -> None:
        """Password fields should be redacted."""
        data = {"password": "secret123", "other": "value"}
        result = redact_secrets(data)

        assert result["password"] == "[REDACTED]"
        assert result["other"] == "value"

    def test_redact_password_in_nested_dict(self) -> None:
        """Nested password fields should be redacted."""
        data = {
            "auth": {
                "password": "secret123",
                "username": "user",
            }
        }
        result = redact_secrets(data)

        assert result["auth"]["password"] == "[REDACTED]"
        assert result["auth"]["username"] == "user"

    def test_redact_private_key_pem(self) -> None:
        """PEM private keys should be redacted."""
        key = """-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyf8R6vZn8H9Q3
-----END RSA PRIVATE KEY-----"""
        result = redact_string(key)

        assert "[REDACTED PRIVATE KEY]" in result
        assert "MIIEpQIBAAKCAQEA" not in result

    def test_redact_openssh_private_key(self) -> None:
        """OpenSSH private keys should be redacted."""
        key = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
-----END OPENSSH PRIVATE KEY-----"""
        result = redact_string(key)

        assert "[REDACTED PRIVATE KEY]" in result

    def test_redact_password_in_json_string(self) -> None:
        """Password patterns in strings should be redacted."""
        text = '{"password": "secret123"}'
        result = redact_string(text)

        assert '"password": "[REDACTED]"' in result
        assert "secret123" not in result

    def test_redact_in_list(self) -> None:
        """Secrets in lists should be redacted."""
        data = [{"password": "secret"}, {"other": "value"}]
        result = redact_secrets(data)

        assert result[0]["password"] == "[REDACTED]"
        assert result[1]["other"] == "value"

    def test_redact_preserves_structure(self) -> None:
        """Redaction should preserve data structure."""
        data = {
            "level1": {
                "level2": {
                    "password": "secret",
                    "list": [1, 2, 3],
                }
            }
        }
        result = redact_secrets(data)

        assert result["level1"]["level2"]["password"] == "[REDACTED]"
        assert result["level1"]["level2"]["list"] == [1, 2, 3]

    def test_host_info_ip_redaction(self) -> None:
        """IP addresses should be partially redacted."""
        host_info = HostInfo(host="192.168.1.100", port=22)
        result = host_info.to_dict(redact=True)

        assert result["host"] == "192.xxx.xxx.xxx"

    def test_host_info_hostname_redaction(self) -> None:
        """Hostnames should be partially redacted."""
        host_info = HostInfo(host="server.example.com", port=22)
        result = host_info.to_dict(redact=True)

        assert result["host"] == "server.[REDACTED]"

    def test_host_info_no_redaction(self) -> None:
        """Can disable host redaction."""
        host_info = HostInfo(host="192.168.1.100", port=22)
        result = host_info.to_dict(redact=False)

        assert result["host"] == "192.168.1.100"

    def test_redact_pin_in_dict(self) -> None:
        """PIN fields should be redacted."""
        data = {"pin": "1234", "other": "value"}
        result = redact_secrets(data)

        assert result["pin"] == "[REDACTED]"
        assert result["other"] == "value"

    def test_redact_pin_in_string(self) -> None:
        """PIN patterns in strings should be redacted."""
        # JSON format
        text = '{"pin": "5678"}'
        result = redact_string(text)
        assert '"pin": "[REDACTED]"' in result
        assert "5678" not in result

        # Key=value format
        text2 = "pin=9012"
        result2 = redact_string(text2)
        assert "pin=[REDACTED]" in result2
        assert "9012" not in result2

        # Colon format (common in logs)
        text3 = "PIN: 3456"
        result3 = redact_string(text3)
        assert "[REDACTED]" in result3
        assert "3456" not in result3

    def test_redact_token_in_dict(self) -> None:
        """Token fields should be redacted."""
        data = {"token": "abc123xyz", "access_token": "secret_token"}
        result = redact_secrets(data)

        assert result["token"] == "[REDACTED]"
        assert result["access_token"] == "[REDACTED]"

    def test_redact_token_in_string(self) -> None:
        """Token patterns in strings should be redacted."""
        # JSON format
        text = '{"token": "my_secret_token"}'
        result = redact_string(text)
        assert '"token": "[REDACTED]"' in result
        assert "my_secret_token" not in result

        # Access token
        text2 = '{"access_token": "bearer_xyz"}'
        result2 = redact_string(text2)
        assert '"access_token": "[REDACTED]"' in result2

    def test_redact_api_key_in_dict(self) -> None:
        """API key fields should be redacted."""
        data = {"api_key": "key_12345", "other": "value"}
        result = redact_secrets(data)

        assert result["api_key"] == "[REDACTED]"
        assert result["other"] == "value"

    def test_redact_passphrase_in_string(self) -> None:
        """Passphrase patterns in strings should be redacted."""
        text = '{"passphrase": "my_secret_passphrase"}'
        result = redact_string(text)

        assert '"passphrase": "[REDACTED]"' in result
        assert "my_secret_passphrase" not in result

    def test_redact_authorization_header(self) -> None:
        """Authorization headers should be redacted."""
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9"
        result = redact_string(text)

        assert "Authorization: Bearer [REDACTED]" in result
        assert "eyJhbGciOiJIUzI1NiJ9" not in result

        text2 = "Authorization: Basic dXNlcjpwYXNz"
        result2 = redact_string(text2)

        assert "Authorization: Basic [REDACTED]" in result2
        assert "dXNlcjpwYXNz" not in result2

    def test_key_path_preserved_content_redacted(self) -> None:
        """Key file paths should be preserved but key content redacted."""
        # Error message with path should keep the path
        error_msg = "Failed to load key from /home/user/.ssh/id_rsa: invalid format"
        result = redact_string(error_msg)
        assert "/home/user/.ssh/id_rsa" in result

        # But actual key content in the message should be redacted
        error_with_key = """Failed to parse key:
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyf8R6vZn8H9Q3
-----END RSA PRIVATE KEY-----"""
        result2 = redact_string(error_with_key)
        assert "[REDACTED PRIVATE KEY]" in result2
        assert "MIIEpQIBAAKCAQEA" not in result2

    def test_redact_client_secret(self) -> None:
        """Client secrets should be redacted."""
        data = {"client_secret": "oauth_secret_xyz"}
        result = redact_secrets(data)

        assert result["client_secret"] == "[REDACTED]"

    def test_redact_secret_key(self) -> None:
        """Secret key fields should be redacted."""
        data = {"secret_key": "django_secret"}
        result = redact_secrets(data)

        assert result["secret_key"] == "[REDACTED]"

    def test_bundle_redacts_by_default(self) -> None:
        """Bundle export should redact by default."""
        bundle = EvidenceBundle(
            host_info=HostInfo(host="192.168.1.100", port=22),
        )
        result = bundle.to_dict()

        assert result["host_info"]["host"] == "192.xxx.xxx.xxx"


class TestBundleRoundtrip:
    """Test bundle serialisation and deserialisation."""

    def test_json_roundtrip(self, tmp_path: Path) -> None:
        """Bundle should survive JSON roundtrip."""
        events = [
            Event(event_type=EventType.CONNECT.value, data={"status": "connected"}),
        ]
        original = EvidenceBundle(
            events=events,
            algorithms=AlgorithmInfo(kex="curve25519-sha256"),
            disconnect_reason=DisconnectReason.KEEPALIVE_TIMEOUT,
            timing=TimingInfo(connect_start_ms=1000, connect_end_ms=2000),
            host_info=HostInfo(host="test.com", port=22, username="user"),
            error_context={"reason": "test"},
        )

        # Save and load
        path = tmp_path / "bundle.json"
        original.to_file(path, format="json", redact=False)
        loaded = EvidenceBundle.from_file(path)

        # Verify fields
        assert len(loaded.events) == 1
        assert loaded.events[0].event_type == EventType.CONNECT.value
        assert loaded.algorithms.kex == "curve25519-sha256"
        assert loaded.disconnect_reason == DisconnectReason.KEEPALIVE_TIMEOUT
        assert loaded.timing.connect_start_ms == 1000
        assert loaded.host_info.host == "test.com"
        assert loaded.error_context["reason"] == "test"

    def test_jsonl_roundtrip(self, tmp_path: Path) -> None:
        """Bundle should survive JSONL roundtrip."""
        events = [
            Event(event_type=EventType.CONNECT.value),
            Event(event_type=EventType.AUTH.value, data={"method": "key"}),
        ]
        original = EvidenceBundle(
            events=events,
            host_info=HostInfo(host="server.local", port=2222),
        )

        # Save and load
        path = tmp_path / "bundle.jsonl"
        original.to_file(path, format="jsonl", redact=False)
        loaded = EvidenceBundle.from_file(path)

        # Verify
        assert len(loaded.events) == 2
        assert loaded.events[0].event_type == EventType.CONNECT.value
        assert loaded.events[1].data["method"] == "key"

    def test_roundtrip_with_transcript(self, tmp_path: Path) -> None:
        """Transcript should survive roundtrip."""
        transcript = Transcript()
        transcript.add_send("command1")
        transcript.add_output("output1")

        original = EvidenceBundle(transcript=transcript)

        path = tmp_path / "bundle.jsonl"
        original.to_file(path, format="jsonl", redact=False)
        loaded = EvidenceBundle.from_file(path)

        assert loaded.transcript is not None
        assert len(loaded.transcript.entries) == 2

    def test_creates_parent_directories(self, tmp_path: Path) -> None:
        """to_file should create parent directories."""
        bundle = EvidenceBundle()
        path = tmp_path / "nested" / "dirs" / "bundle.json"

        bundle.to_file(path)

        assert path.exists()


class TestTimingInfo:
    """Test timing information tracking."""

    def test_timing_duration_calculation(self) -> None:
        """Timing should calculate durations correctly."""
        timing = TimingInfo(
            connect_start_ms=1000,
            connect_end_ms=1500,
            auth_start_ms=1500,
            auth_end_ms=2000,
            disconnect_ms=5000,
        )

        assert timing.connect_duration_ms == 500
        assert timing.auth_duration_ms == 500
        assert timing.total_duration_ms == 4000

    def test_timing_none_duration(self) -> None:
        """Duration should be None if missing timestamps."""
        timing = TimingInfo(connect_start_ms=1000)

        assert timing.connect_duration_ms is None
        assert timing.auth_duration_ms is None
        assert timing.total_duration_ms is None

    def test_timing_to_dict_includes_computed(self) -> None:
        """to_dict should include computed durations."""
        timing = TimingInfo(
            connect_start_ms=1000,
            connect_end_ms=2000,
        )
        result = timing.to_dict()

        assert result["connect_duration_ms"] == 1000


class TestAlgorithmInfo:
    """Test SSH algorithm information extraction."""

    def test_algorithm_info_to_dict(self) -> None:
        """to_dict should exclude None values."""
        info = AlgorithmInfo(
            kex="curve25519-sha256",
            cipher_cs="aes256-gcm",
        )
        result = info.to_dict()

        assert result["kex"] == "curve25519-sha256"
        assert result["cipher_cs"] == "aes256-gcm"
        assert "cipher_sc" not in result
        assert "mac_cs" not in result

    def test_from_none_connection(self) -> None:
        """Should handle None connection gracefully."""
        info = AlgorithmInfo.from_asyncssh_conn(None)

        assert info.kex is None
        assert info.cipher_cs is None


class TestIntegration:
    """Integration tests requiring Docker SSH server."""

    @pytest.mark.asyncio
    async def test_connection_evidence_bundle(
        self,
        ssh_server,
        event_collector,
    ) -> None:
        """Evidence bundle from real connection contains expected data."""
        if ssh_server is None:
            pytest.skip("Docker SSH server not available")

        from nbs_ssh import SSHConnection, create_password_auth

        auth = create_password_auth(ssh_server.password)

        async with SSHConnection(
            host=ssh_server.host,
            port=ssh_server.port,
            username=ssh_server.username,
            auth=auth,
            known_hosts=ssh_server.known_hosts_path,
            event_collector=event_collector,
        ) as conn:
            # Run a command to generate events
            await conn.exec("echo hello")

            # Get bundle
            bundle = conn.get_evidence_bundle()

        # Verify bundle has expected content
        assert len(bundle.events) > 0
        assert bundle.host_info is not None
        assert bundle.host_info.port == ssh_server.port
        assert bundle.timing.connect_start_ms is not None
        assert bundle.timing.connect_end_ms is not None

        # Check events include connection and exec
        event_types = [e.event_type for e in bundle.events]
        assert EventType.CONNECT.value in event_types
        assert EventType.EXEC.value in event_types

    @pytest.mark.asyncio
    async def test_supervisor_evidence_bundle(
        self,
        ssh_server,
        event_collector,
    ) -> None:
        """Evidence bundle from supervisor includes supervisor state."""
        if ssh_server is None:
            pytest.skip("Docker SSH server not available")

        from nbs_ssh import SSHSupervisor, create_password_auth

        auth = create_password_auth(ssh_server.password)

        async with SSHSupervisor(
            host=ssh_server.host,
            port=ssh_server.port,
            username=ssh_server.username,
            auth=auth,
            known_hosts=ssh_server.known_hosts_path,
            event_collector=event_collector,
        ) as supervisor:
            bundle = supervisor.get_evidence_bundle()

        # Supervisor-specific info
        assert "supervisor_state" in bundle.error_context
        assert "reconnection_count" in bundle.error_context

    @pytest.mark.asyncio
    async def test_bundle_export_after_failure(
        self,
        event_collector,
    ) -> None:
        """Can get evidence bundle even after connection failure."""
        from nbs_ssh import SSHConnection, create_password_auth

        auth = create_password_auth("wrong_password")

        try:
            async with SSHConnection(
                host="localhost",
                port=9999,  # No server here
                username="test",
                auth=auth,
                known_hosts=None,
                event_collector=event_collector,
                connect_timeout=2.0,
            ):
                pass
        except Exception:
            pass

        # We can still check events in collector
        assert len(event_collector.events) > 0
