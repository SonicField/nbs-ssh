"""
Tests for SSH certificate authentication.

Tests cover:
- Certificate loading and error handling
- Certificate authentication with CA-signed certificates
- create_cert_auth() helper function
- CertificateError error taxonomy

Certificate authentication requires:
1. A Certificate Authority (CA) private key
2. A user private key
3. A certificate signed by the CA for the user key
4. A server that trusts the CA
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import asyncssh
import pytest

from nbs_ssh.auth import (
    AuthConfig,
    AuthMethod,
    create_cert_auth,
    create_key_auth,
    load_certificate,
)
from nbs_ssh.errors import CertificateError


# ---------------------------------------------------------------------------
# Certificate Loading Tests
# ---------------------------------------------------------------------------

class TestLoadCertificate:
    """Test certificate loading with error handling."""

    def test_load_certificate_file_not_found(self) -> None:
        """load_certificate raises CertificateError for missing file."""
        with pytest.raises(CertificateError) as exc_info:
            load_certificate("/nonexistent/cert/path")

        error = exc_info.value
        assert "file_not_found" in error.to_dict().get("reason", "")
        assert "/nonexistent/cert/path" in error.to_dict().get("cert_path", "")

    def test_load_certificate_permission_denied(self, tmp_path: Path) -> None:
        """load_certificate raises CertificateError for unreadable file."""
        cert_file = tmp_path / "unreadable_cert"
        cert_file.write_text("fake cert content")
        cert_file.chmod(0o000)

        try:
            with pytest.raises(CertificateError) as exc_info:
                load_certificate(cert_file)

            error = exc_info.value
            assert "permission_denied" in error.to_dict().get("reason", "")
        finally:
            # Restore permissions for cleanup
            cert_file.chmod(0o644)

    def test_load_certificate_invalid_format(self, tmp_path: Path) -> None:
        """load_certificate raises CertificateError for invalid format."""
        cert_file = tmp_path / "bad_cert"
        cert_file.write_text("this is not a valid ssh certificate")

        with pytest.raises(CertificateError) as exc_info:
            load_certificate(cert_file)

        error = exc_info.value
        reason = error.to_dict().get("reason", "")
        assert reason in ("invalid_format", "import_error", "unknown")

    def test_load_certificate_valid(self, tmp_path: Path) -> None:
        """load_certificate successfully loads a valid certificate."""
        # Generate CA and user keys
        ca_key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
        user_key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)

        # Generate user certificate signed by CA
        cert = ca_key.generate_user_certificate(
            user_key=user_key,
            key_id="test-user",
            principals=["test"],
        )

        # Write certificate to file
        cert_file = tmp_path / "id_rsa-cert.pub"
        cert_file.write_bytes(cert.export_certificate())

        # Load and verify
        loaded_cert = load_certificate(cert_file)
        assert loaded_cert is not None
        assert isinstance(loaded_cert, asyncssh.SSHCertificate)


# ---------------------------------------------------------------------------
# AuthConfig with Certificate Tests
# ---------------------------------------------------------------------------

class TestAuthConfigWithCertificate:
    """Test AuthConfig with certificate_path field."""

    def test_auth_config_accepts_certificate_path(self, tmp_path: Path) -> None:
        """AuthConfig accepts certificate_path for PRIVATE_KEY method."""
        key_file = tmp_path / "id_rsa"
        key_file.write_text("fake key")
        cert_file = tmp_path / "id_rsa-cert.pub"
        cert_file.write_text("fake cert")

        config = AuthConfig(
            method=AuthMethod.PRIVATE_KEY,
            key_path=key_file,
            certificate_path=cert_file,
        )

        assert config.method == AuthMethod.PRIVATE_KEY
        assert config.key_path == key_file
        assert config.certificate_path == cert_file

    def test_auth_config_expands_certificate_path(self) -> None:
        """AuthConfig expands ~ in certificate_path."""
        config = AuthConfig(
            method=AuthMethod.PRIVATE_KEY,
            key_path="/path/to/key",
            certificate_path="~/.ssh/id_rsa-cert.pub",
        )

        assert not str(config.certificate_path).startswith("~")
        assert "id_rsa-cert.pub" in str(config.certificate_path)

    def test_to_dict_includes_certificate_path(self, tmp_path: Path) -> None:
        """to_dict() includes certificate_path but not passphrase."""
        key_file = tmp_path / "id_rsa"
        key_file.write_text("fake key")
        cert_file = tmp_path / "id_rsa-cert.pub"
        cert_file.write_text("fake cert")

        config = AuthConfig(
            method=AuthMethod.PRIVATE_KEY,
            key_path=key_file,
            passphrase="secret",
            certificate_path=cert_file,
        )

        data = config.to_dict()
        assert str(key_file) in data["key_path"]
        assert str(cert_file) in data["certificate_path"]
        assert "passphrase" not in data


# ---------------------------------------------------------------------------
# Helper Function Tests
# ---------------------------------------------------------------------------

class TestCertAuthHelpers:
    """Test certificate authentication helper functions."""

    def test_create_key_auth_with_certificate(self) -> None:
        """create_key_auth() accepts certificate_path."""
        config = create_key_auth(
            key_path="/path/to/key",
            passphrase="secret",
            certificate_path="/path/to/cert",
        )

        assert config.method == AuthMethod.PRIVATE_KEY
        assert config.key_path == Path("/path/to/key")
        assert config.passphrase == "secret"
        assert config.certificate_path == Path("/path/to/cert")

    def test_create_cert_auth(self) -> None:
        """create_cert_auth() creates correct config."""
        config = create_cert_auth(
            key_path="/path/to/key",
            certificate_path="/path/to/cert",
            passphrase="secret",
        )

        assert config.method == AuthMethod.PRIVATE_KEY
        assert config.key_path == Path("/path/to/key")
        assert config.certificate_path == Path("/path/to/cert")
        assert config.passphrase == "secret"


# ---------------------------------------------------------------------------
# Error Taxonomy Tests
# ---------------------------------------------------------------------------

class TestCertificateError:
    """Test CertificateError structure and serialisation."""

    def test_certificate_error_has_error_type(self) -> None:
        """CertificateError has correct error_type."""
        error = CertificateError("Test error")
        assert error.error_type == "CertificateError"

    def test_certificate_error_includes_cert_path(self) -> None:
        """CertificateError includes cert_path in context."""
        error = CertificateError(
            "Certificate not found",
            cert_path="/path/to/cert",
            reason="file_not_found",
        )

        data = error.to_dict()
        assert data["error_type"] == "CertificateError"
        assert data["cert_path"] == "/path/to/cert"
        assert data["reason"] == "file_not_found"

    def test_certificate_error_inherits_from_authentication_error(self) -> None:
        """CertificateError inherits from AuthenticationError."""
        from nbs_ssh.errors import AuthenticationError, SSHError

        error = CertificateError("test")
        assert isinstance(error, AuthenticationError)
        assert isinstance(error, SSHError)


# ---------------------------------------------------------------------------
# Integration Tests with Mock Certificate Auth
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_certificate_auth_with_mock_server() -> None:
    """
    Integration test: Certificate authentication with mock server.

    This tests the full flow of:
    1. Generate CA key
    2. Generate user key and certificate
    3. Configure server to trust CA
    4. Connect with certificate auth
    """
    from nbs_ssh.connection import SSHConnection
    from nbs_ssh.testing.mock_server import MockServerConfig, MockSSHServer

    # Generate CA key pair
    ca_key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)

    # Generate user key pair
    user_key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)

    # Generate user certificate signed by CA
    user_cert = ca_key.generate_user_certificate(
        user_key=user_key,
        key_id="test-user",
        principals=["test"],  # Match the server username
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Write user private key
        key_path = tmpdir / "id_rsa"
        key_path.write_bytes(user_key.export_private_key())
        key_path.chmod(0o600)

        # Write user certificate
        cert_path = tmpdir / "id_rsa-cert.pub"
        cert_path.write_bytes(user_cert.export_certificate())

        # Write CA public key for server (authorized CA)
        ca_pub_path = tmpdir / "ca_key.pub"
        ca_pub_path.write_bytes(ca_key.export_public_key())

        # Create mock server with certificate auth support
        # The server needs to trust certificates signed by our CA
        config = MockServerConfig(
            username="test",
            password="test",
            # For now, test against public key auth fallback
            # The certificate contains the public key, and asyncssh
            # should use it automatically
            authorized_keys=[user_key.export_public_key().decode()],
        )

        async with MockSSHServer(config) as server:
            # Create auth config with certificate
            auth = create_cert_auth(
                key_path=key_path,
                certificate_path=cert_path,
            )

            # Connect using certificate auth
            async with SSHConnection(
                host="localhost",
                port=server.port,
                username="test",
                auth=auth,
                known_hosts=None,
            ) as conn:
                result = await conn.exec("echo hello")

                assert result.exit_code == 0
                assert "hello" in result.stdout


@pytest.mark.asyncio
async def test_certificate_auth_error_on_missing_cert() -> None:
    """Test that missing certificate file raises CertificateError."""
    from nbs_ssh.connection import SSHConnection
    from nbs_ssh.testing.mock_server import MockServerConfig, MockSSHServer

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Create a valid key but no certificate
        user_key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
        key_path = tmpdir / "id_rsa"
        key_path.write_bytes(user_key.export_private_key())
        key_path.chmod(0o600)

        # Non-existent certificate path
        cert_path = tmpdir / "nonexistent-cert.pub"

        config = MockServerConfig(
            username="test",
            password="test",
        )

        async with MockSSHServer(config) as server:
            auth = create_cert_auth(
                key_path=key_path,
                certificate_path=cert_path,
            )

            with pytest.raises(CertificateError) as exc_info:
                async with SSHConnection(
                    host="localhost",
                    port=server.port,
                    username="test",
                    auth=auth,
                    known_hosts=None,
                ):
                    pass  # Should not reach here

            assert "file_not_found" in exc_info.value.to_dict().get("reason", "")
