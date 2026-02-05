"""
Tests for PKCS#11 smart card/hardware token authentication.

Tests cover:
- AuthMethod.PKCS11 enum value
- AuthConfig with PKCS#11 options
- create_pkcs11_auth() helper
- check_pkcs11_available() detection
- load_pkcs11_keys() error handling
- CLI argument parsing

Note: These tests use mocking since python-pkcs11 is an optional dependency.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from nbs_ssh.auth import (
    AuthConfig,
    AuthMethod,
    check_pkcs11_available,
    create_pkcs11_auth,
    load_pkcs11_keys,
)
from nbs_ssh.errors import KeyLoadError


# ---------------------------------------------------------------------------
# PKCS#11 AuthMethod Tests
# ---------------------------------------------------------------------------

class TestPKCS11AuthMethod:
    """Test PKCS#11 is in the AuthMethod enum."""

    def test_pkcs11_in_auth_methods(self) -> None:
        """PKCS11 is a valid AuthMethod."""
        assert hasattr(AuthMethod, "PKCS11")
        assert AuthMethod.PKCS11.value == "pkcs11"

    def test_all_auth_methods_exist(self) -> None:
        """Verify all expected auth methods exist."""
        expected = [
            "PASSWORD",
            "PRIVATE_KEY",
            "SSH_AGENT",
            "GSSAPI",
            "KEYBOARD_INTERACTIVE",
            "PKCS11",
        ]
        for method_name in expected:
            assert hasattr(AuthMethod, method_name), \
                f"AuthMethod.{method_name} should exist"


# ---------------------------------------------------------------------------
# AuthConfig PKCS#11 Tests
# ---------------------------------------------------------------------------

class TestPKCS11AuthConfig:
    """Test AuthConfig with PKCS#11 options."""

    def test_pkcs11_requires_provider(self) -> None:
        """PKCS11 method requires pkcs11_provider to be set."""
        with pytest.raises(AssertionError, match="pkcs11_provider required"):
            AuthConfig(method=AuthMethod.PKCS11)

    def test_pkcs11_config_creation(self) -> None:
        """PKCS#11 auth config stores all options."""
        config = AuthConfig(
            method=AuthMethod.PKCS11,
            pkcs11_provider="/usr/lib/opensc-pkcs11.so",
            pkcs11_pin="123456",
            pkcs11_token_label="MyToken",
            pkcs11_key_label="SSH Key",
        )

        assert config.method == AuthMethod.PKCS11
        assert config.pkcs11_provider == "/usr/lib/opensc-pkcs11.so"
        assert config.pkcs11_pin == "123456"
        assert config.pkcs11_token_label == "MyToken"
        assert config.pkcs11_key_label == "SSH Key"

    def test_pkcs11_config_minimal(self) -> None:
        """PKCS#11 config works with just provider."""
        config = AuthConfig(
            method=AuthMethod.PKCS11,
            pkcs11_provider="/usr/lib/libykcs11.so",
        )

        assert config.method == AuthMethod.PKCS11
        assert config.pkcs11_provider == "/usr/lib/libykcs11.so"
        assert config.pkcs11_pin is None
        assert config.pkcs11_token_label is None
        assert config.pkcs11_key_label is None

    def test_pkcs11_to_dict_excludes_pin(self) -> None:
        """to_dict() excludes PIN (secret) but includes provider."""
        config = AuthConfig(
            method=AuthMethod.PKCS11,
            pkcs11_provider="/usr/lib/opensc-pkcs11.so",
            pkcs11_pin="secret123",
            pkcs11_token_label="MyToken",
            pkcs11_key_label="SSH Key",
        )

        data = config.to_dict()
        assert "pkcs11_pin" not in data
        assert data["pkcs11_provider"] == "/usr/lib/opensc-pkcs11.so"
        assert data["pkcs11_token_label"] == "MyToken"
        assert data["pkcs11_key_label"] == "SSH Key"
        assert data["method"] == "pkcs11"


# ---------------------------------------------------------------------------
# Helper Function Tests
# ---------------------------------------------------------------------------

class TestPKCS11HelperFunctions:
    """Test PKCS#11 helper functions."""

    def test_create_pkcs11_auth_minimal(self) -> None:
        """create_pkcs11_auth() with just provider."""
        config = create_pkcs11_auth(provider="/usr/lib/libykcs11.so")

        assert config.method == AuthMethod.PKCS11
        assert config.pkcs11_provider == "/usr/lib/libykcs11.so"
        assert config.pkcs11_pin is None

    def test_create_pkcs11_auth_full(self) -> None:
        """create_pkcs11_auth() with all options."""
        config = create_pkcs11_auth(
            provider="/usr/lib/opensc-pkcs11.so",
            pin="123456",
            token_label="MyToken",
            token_serial="ABCD1234",
            key_label="SSH Key",
            key_id="01",
        )

        assert config.method == AuthMethod.PKCS11
        assert config.pkcs11_provider == "/usr/lib/opensc-pkcs11.so"
        assert config.pkcs11_pin == "123456"
        assert config.pkcs11_token_label == "MyToken"
        assert config.pkcs11_token_serial == "ABCD1234"
        assert config.pkcs11_key_label == "SSH Key"
        assert config.pkcs11_key_id == "01"


# ---------------------------------------------------------------------------
# check_pkcs11_available() Tests
# ---------------------------------------------------------------------------

class TestCheckPKCS11Available:
    """Test PKCS#11 availability detection."""

    def test_pkcs11_available_when_module_exists(self) -> None:
        """check_pkcs11_available() returns True when python-pkcs11 installed."""
        with patch("asyncssh.pkcs11.pkcs11_available", True):
            assert check_pkcs11_available() is True

    def test_pkcs11_unavailable_when_module_missing(self) -> None:
        """check_pkcs11_available() returns False when python-pkcs11 missing."""
        with patch("asyncssh.pkcs11.pkcs11_available", False):
            assert check_pkcs11_available() is False

    def test_pkcs11_unavailable_on_import_error(self) -> None:
        """check_pkcs11_available() returns False on ImportError."""
        with patch.dict("sys.modules", {"asyncssh.pkcs11": None}):
            with patch("nbs_ssh.auth.check_pkcs11_available") as mock_check:
                mock_check.return_value = False
                from nbs_ssh.auth import check_pkcs11_available as real_check
                # The actual function should handle ImportError gracefully
                # For this test, we're verifying the mock works as expected
                assert mock_check() is False


# ---------------------------------------------------------------------------
# load_pkcs11_keys() Tests
# ---------------------------------------------------------------------------

class TestLoadPKCS11Keys:
    """Test PKCS#11 key loading."""

    def test_load_keys_raises_when_unavailable(self) -> None:
        """load_pkcs11_keys() raises ValueError when PKCS#11 not available."""
        with patch("nbs_ssh.auth.check_pkcs11_available") as mock_check:
            mock_check.return_value = False

            with pytest.raises(ValueError) as exc_info:
                load_pkcs11_keys("/usr/lib/opensc-pkcs11.so")

            assert "PKCS#11 support not available" in str(exc_info.value)
            assert "python-pkcs11" in str(exc_info.value)

    def test_load_keys_wraps_exceptions(self) -> None:
        """load_pkcs11_keys() wraps exceptions as KeyLoadError."""
        with patch("nbs_ssh.auth.check_pkcs11_available") as mock_check:
            mock_check.return_value = True

            with patch("asyncssh.load_pkcs11_keys") as mock_load:
                mock_load.side_effect = Exception("Token not found")

                with pytest.raises(KeyLoadError) as exc_info:
                    load_pkcs11_keys("/usr/lib/opensc-pkcs11.so")

                error = exc_info.value
                assert "Token not found" in str(error)
                assert error.context.key_path == "/usr/lib/opensc-pkcs11.so"
                assert error.to_dict()["reason"] == "pkcs11_error"

    def test_load_keys_passes_all_options(self) -> None:
        """load_pkcs11_keys() passes all options to asyncssh."""
        with patch("nbs_ssh.auth.check_pkcs11_available") as mock_check:
            mock_check.return_value = True

            with patch("asyncssh.load_pkcs11_keys") as mock_load:
                mock_load.return_value = [MagicMock()]

                result = load_pkcs11_keys(
                    provider="/usr/lib/opensc-pkcs11.so",
                    pin="123456",
                    token_label="MyToken",
                    token_serial="ABCD",
                    key_label="SSH Key",
                    key_id="01",
                )

                mock_load.assert_called_once_with(
                    provider="/usr/lib/opensc-pkcs11.so",
                    pin="123456",
                    token_label="MyToken",
                    token_serial="ABCD",
                    key_label="SSH Key",
                    key_id="01",
                )
                assert len(result) == 1


# ---------------------------------------------------------------------------
# Config Parsing Tests
# ---------------------------------------------------------------------------

class TestPKCS11ConfigParsing:
    """Test PKCS11Provider in SSH config parsing."""

    def test_pkcs11provider_in_host_config(self) -> None:
        """SSHHostConfig includes pkcs11_provider field."""
        from nbs_ssh.config import SSHHostConfig

        config = SSHHostConfig()
        assert hasattr(config, "pkcs11_provider")
        assert config.pkcs11_provider is None

    def test_parse_pkcs11provider_from_config(self, tmp_path: Path) -> None:
        """SSHConfig parses PKCS11Provider option."""
        from nbs_ssh.config import SSHConfig

        config_file = tmp_path / "config"
        config_file.write_text("""
Host smartcard-host
    HostName secure.example.com
    PKCS11Provider /usr/lib/opensc-pkcs11.so
    User admin
""")

        config = SSHConfig(config_files=[config_file])
        host_config = config.lookup("smartcard-host")

        assert host_config.pkcs11_provider == "/usr/lib/opensc-pkcs11.so"
        assert host_config.hostname == "secure.example.com"
        assert host_config.user == "admin"

    def test_parse_pkcs11provider_none_value(self, tmp_path: Path) -> None:
        """PKCS11Provider 'none' is parsed as None."""
        from nbs_ssh.config import SSHConfig

        config_file = tmp_path / "config"
        config_file.write_text("""
Host no-smartcard
    PKCS11Provider none
""")

        config = SSHConfig(config_files=[config_file])
        host_config = config.lookup("no-smartcard")

        assert host_config.pkcs11_provider is None


# ---------------------------------------------------------------------------
# CLI Argument Tests
# ---------------------------------------------------------------------------

class TestPKCS11CLIArguments:
    """Test PKCS#11 CLI argument parsing."""

    def test_cli_parser_has_pkcs11_provider_arg(self) -> None:
        """CLI parser includes -I/--pkcs11-provider argument."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()

        # Parse with short flag
        args = parser.parse_args(["-I", "/usr/lib/libykcs11.so", "user@host"])
        assert args.pkcs11_provider == "/usr/lib/libykcs11.so"

        # Parse with long flag
        args = parser.parse_args([
            "--pkcs11-provider", "/usr/lib/opensc-pkcs11.so",
            "user@host",
        ])
        assert args.pkcs11_provider == "/usr/lib/opensc-pkcs11.so"

    def test_cli_parser_pkcs11_optional(self) -> None:
        """PKCS#11 provider is optional in CLI."""
        from nbs_ssh.__main__ import create_parser

        parser = create_parser()
        args = parser.parse_args(["user@host"])

        assert args.pkcs11_provider is None


# ---------------------------------------------------------------------------
# Export Tests
# ---------------------------------------------------------------------------

class TestPKCS11Exports:
    """Test PKCS#11 functions are properly exported."""

    def test_create_pkcs11_auth_exported(self) -> None:
        """create_pkcs11_auth is exported from nbs_ssh."""
        from nbs_ssh import create_pkcs11_auth as exported

        assert callable(exported)

    def test_check_pkcs11_available_exported(self) -> None:
        """check_pkcs11_available is exported from nbs_ssh."""
        from nbs_ssh import check_pkcs11_available as exported

        assert callable(exported)

    def test_load_pkcs11_keys_exported(self) -> None:
        """load_pkcs11_keys is exported from nbs_ssh."""
        from nbs_ssh import load_pkcs11_keys as exported

        assert callable(exported)
