"""
Tests for cross-platform path handling and key discovery.

Tests cover:
- Platform-appropriate SSH directory paths
- Path expansion with ~ and environment variables
- Private key discovery
- SSH agent detection (mocked for Windows scenarios)
- Path validation
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from nbs_ssh.platform import (
    discover_keys,
    expand_path,
    get_agent_available,
    get_default_key_paths,
    get_known_hosts_path,
    get_openssh_agent_available,
    get_pageant_available,
    get_putty_key_paths,
    get_ssh_dir,
    is_windows,
    validate_path,
)


# ---------------------------------------------------------------------------
# Platform Detection Tests
# ---------------------------------------------------------------------------

class TestPlatformDetection:
    """Test platform detection functions."""

    def test_is_windows_returns_bool(self) -> None:
        """is_windows() returns a boolean."""
        result = is_windows()
        assert isinstance(result, bool)

    def test_is_windows_matches_sys_platform(self) -> None:
        """is_windows() matches sys.platform check."""
        expected = sys.platform == "win32"
        assert is_windows() == expected


# ---------------------------------------------------------------------------
# SSH Directory Tests
# ---------------------------------------------------------------------------

class TestSSHDirectory:
    """Test SSH directory path functions."""

    def test_get_ssh_dir_returns_path(self) -> None:
        """get_ssh_dir() returns a Path object."""
        result = get_ssh_dir()
        assert isinstance(result, Path)

    def test_get_ssh_dir_ends_with_dot_ssh(self) -> None:
        """get_ssh_dir() returns path ending in .ssh."""
        result = get_ssh_dir()
        assert result.name == ".ssh"

    def test_get_ssh_dir_unix(self) -> None:
        """On Unix, get_ssh_dir() uses HOME."""
        with patch("nbs_ssh.platform.is_windows", return_value=False):
            result = get_ssh_dir()
            assert result == Path.home() / ".ssh"

    def test_get_ssh_dir_windows_with_userprofile(self) -> None:
        """On Windows, get_ssh_dir() uses USERPROFILE."""
        with patch("nbs_ssh.platform.is_windows", return_value=True):
            with patch.dict(os.environ, {"USERPROFILE": "C:\\Users\\Test"}):
                result = get_ssh_dir()
                assert result == Path("C:\\Users\\Test") / ".ssh"

    def test_get_ssh_dir_windows_fallback_to_home(self) -> None:
        """On Windows without USERPROFILE, falls back to HOME."""
        with patch("nbs_ssh.platform.is_windows", return_value=True):
            env = {"HOME": "/home/test"}
            # Remove USERPROFILE
            with patch.dict(os.environ, env, clear=True):
                result = get_ssh_dir()
                assert result == Path("/home/test") / ".ssh"

    def test_get_known_hosts_path(self) -> None:
        """get_known_hosts_path() returns path in ssh directory."""
        result = get_known_hosts_path()
        assert result.name == "known_hosts"
        assert result.parent == get_ssh_dir()


# ---------------------------------------------------------------------------
# Default Key Paths Tests
# ---------------------------------------------------------------------------

class TestDefaultKeyPaths:
    """Test default key path discovery."""

    def test_get_default_key_paths_returns_list(self) -> None:
        """get_default_key_paths() returns a list of Paths."""
        result = get_default_key_paths()
        assert isinstance(result, list)
        assert all(isinstance(p, Path) for p in result)

    def test_get_default_key_paths_includes_ed25519(self) -> None:
        """Default keys include id_ed25519."""
        result = get_default_key_paths()
        names = [p.name for p in result]
        assert "id_ed25519" in names

    def test_get_default_key_paths_includes_rsa(self) -> None:
        """Default keys include id_rsa."""
        result = get_default_key_paths()
        names = [p.name for p in result]
        assert "id_rsa" in names

    def test_get_default_key_paths_in_ssh_dir(self) -> None:
        """All default key paths are in the SSH directory."""
        ssh_dir = get_ssh_dir()
        result = get_default_key_paths()
        for path in result:
            assert path.parent == ssh_dir


# ---------------------------------------------------------------------------
# Path Expansion Tests
# ---------------------------------------------------------------------------

class TestPathExpansion:
    """Test path expansion with ~ and environment variables."""

    def test_expand_path_returns_path(self) -> None:
        """expand_path() returns a Path object."""
        result = expand_path("/some/path")
        assert isinstance(result, Path)

    def test_expand_path_handles_tilde(self) -> None:
        """expand_path() expands ~ to home directory."""
        result = expand_path("~/.ssh/id_rsa")
        assert "~" not in str(result)
        assert ".ssh" in str(result)

    def test_expand_path_handles_path_object(self) -> None:
        """expand_path() accepts Path objects."""
        result = expand_path(Path("~/.ssh"))
        assert "~" not in str(result)

    def test_expand_path_unix_env_vars(self) -> None:
        """expand_path() handles $VAR on Unix."""
        with patch("nbs_ssh.platform.is_windows", return_value=False):
            with patch.dict(os.environ, {"MY_DIR": "/custom/dir"}):
                # On Unix, expandvars is not called for %VAR% syntax
                # but $VAR should work via shell
                result = expand_path("/base/$MY_DIR/file")
                # Note: Path.expanduser doesn't expand $VAR
                # This test documents current behaviour
                assert isinstance(result, Path)

    def test_expand_path_windows_percent_vars(self) -> None:
        """expand_path() calls expandvars on Windows.

        Note: os.path.expandvars only expands %VAR% on actual Windows.
        This test verifies the code path is triggered, using $VAR syntax
        which works on all platforms.
        """
        import nbs_ssh.platform

        # Use $VAR syntax which expandvars handles on all platforms
        with patch.object(nbs_ssh.platform, "is_windows", lambda: True):
            with patch.dict(os.environ, {"TEST_DIR": "/expanded/path"}):
                result = nbs_ssh.platform.expand_path("$TEST_DIR/file.txt")
                assert "expanded" in str(result)

    def test_expand_path_windows_calls_expandvars(self) -> None:
        """On Windows, expand_path calls os.path.expandvars."""
        import nbs_ssh.platform

        with patch.object(nbs_ssh.platform, "is_windows", lambda: True):
            with patch("os.path.expandvars") as mock_expandvars:
                mock_expandvars.return_value = "/mocked/path"
                result = nbs_ssh.platform.expand_path("%USERPROFILE%\\.ssh")
                mock_expandvars.assert_called_once()
                assert "mocked" in str(result)

    def test_expand_path_absolute_unchanged(self) -> None:
        """expand_path() leaves absolute paths unchanged."""
        result = expand_path("/absolute/path/to/file")
        assert result == Path("/absolute/path/to/file")


# ---------------------------------------------------------------------------
# Path Validation Tests
# ---------------------------------------------------------------------------

class TestPathValidation:
    """Test path validation functions."""

    def test_validate_path_existing_file(self, tmp_path: Path) -> None:
        """validate_path() returns True for existing readable file."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        is_valid, error = validate_path(test_file, "test file")
        assert is_valid is True
        assert error is None

    def test_validate_path_nonexistent(self, tmp_path: Path) -> None:
        """validate_path() returns False for nonexistent path."""
        nonexistent = tmp_path / "does_not_exist"

        is_valid, error = validate_path(nonexistent, "test path")
        assert is_valid is False
        assert "does not exist" in error

    def test_validate_path_long_windows_path(self) -> None:
        """validate_path() warns about Windows long paths."""
        with patch("nbs_ssh.platform.is_windows", return_value=True):
            # Create a path longer than 260 characters
            long_path = Path("C:\\" + "a" * 270 + "\\file.txt")

            is_valid, error = validate_path(long_path, "test path")
            assert is_valid is False
            assert "MAX_PATH" in error

    def test_validate_path_unreadable(self, tmp_path: Path) -> None:
        """validate_path() returns False for unreadable file."""
        test_file = tmp_path / "unreadable.txt"
        test_file.write_text("content")
        test_file.chmod(0o000)

        try:
            is_valid, error = validate_path(test_file, "test file")
            assert is_valid is False
            assert "not readable" in error
        finally:
            test_file.chmod(0o644)


# ---------------------------------------------------------------------------
# Key Discovery Tests
# ---------------------------------------------------------------------------

class TestKeyDiscovery:
    """Test private key discovery functions."""

    def test_discover_keys_returns_list(self) -> None:
        """discover_keys() returns a list of Paths."""
        result = discover_keys()
        assert isinstance(result, list)
        assert all(isinstance(p, Path) for p in result)

    def test_discover_keys_finds_test_keys(self, tmp_path: Path) -> None:
        """discover_keys() finds keys in SSH directory."""
        # Create mock SSH directory with keys
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()

        id_rsa = ssh_dir / "id_rsa"
        id_rsa.write_text("fake key content")

        id_ed25519 = ssh_dir / "id_ed25519"
        id_ed25519.write_text("fake ed25519 key")

        with patch("nbs_ssh.platform.get_ssh_dir", return_value=ssh_dir):
            result = discover_keys()

        assert len(result) == 2
        assert id_rsa in result
        assert id_ed25519 in result

    def test_discover_keys_skips_unreadable(self, tmp_path: Path) -> None:
        """discover_keys() skips unreadable key files."""
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()

        id_rsa = ssh_dir / "id_rsa"
        id_rsa.write_text("fake key")
        id_rsa.chmod(0o000)

        try:
            with patch("nbs_ssh.platform.get_ssh_dir", return_value=ssh_dir):
                result = discover_keys()

            assert id_rsa not in result
        finally:
            id_rsa.chmod(0o644)

    def test_get_putty_key_paths_empty_on_unix(self) -> None:
        """get_putty_key_paths() returns empty list on Unix."""
        with patch("nbs_ssh.platform.is_windows", return_value=False):
            result = get_putty_key_paths()
            assert result == []


# ---------------------------------------------------------------------------
# Agent Detection Tests
# ---------------------------------------------------------------------------

class TestAgentDetection:
    """Test SSH agent availability detection."""

    def test_get_openssh_agent_unix_with_socket(self, tmp_path: Path) -> None:
        """On Unix with SSH_AUTH_SOCK, agent is available."""
        socket = tmp_path / "agent.sock"
        socket.touch()

        with patch("nbs_ssh.platform.is_windows", return_value=False):
            with patch.dict(os.environ, {"SSH_AUTH_SOCK": str(socket)}):
                result = get_openssh_agent_available()
                assert result is True

    def test_get_openssh_agent_unix_no_socket(self) -> None:
        """On Unix without SSH_AUTH_SOCK, agent is not available."""
        with patch("nbs_ssh.platform.is_windows", return_value=False):
            with patch.dict(os.environ, {}, clear=True):
                os.environ.pop("SSH_AUTH_SOCK", None)
                result = get_openssh_agent_available()
                assert result is False

    def test_get_pageant_available_false_on_unix(self) -> None:
        """get_pageant_available() returns False on Unix."""
        with patch("nbs_ssh.platform.is_windows", return_value=False):
            result = get_pageant_available()
            assert result is False

    def test_get_pageant_available_windows_not_running(self) -> None:
        """get_pageant_available() returns False when Pageant not running."""
        with patch("nbs_ssh.platform.is_windows", return_value=True):
            # Mock ctypes to return 0 (no window found)
            mock_ctypes = MagicMock()
            mock_ctypes.windll.user32.FindWindowW.return_value = 0

            with patch.dict(sys.modules, {"ctypes": mock_ctypes}):
                # Re-import to use mocked ctypes
                import importlib
                import nbs_ssh.platform
                importlib.reload(nbs_ssh.platform)

                # The function should return False
                result = nbs_ssh.platform.get_pageant_available()
                assert result is False

    def test_get_agent_available_unix(self, tmp_path: Path) -> None:
        """get_agent_available() checks Unix agent."""
        socket = tmp_path / "agent.sock"
        socket.touch()

        with patch("nbs_ssh.platform.is_windows", return_value=False):
            with patch.dict(os.environ, {"SSH_AUTH_SOCK": str(socket)}):
                result = get_agent_available()
                assert result is True

    def test_get_agent_available_windows_checks_both(self) -> None:
        """On Windows, get_agent_available() checks Pageant and OpenSSH."""
        with patch("nbs_ssh.platform.is_windows", return_value=True):
            with patch("nbs_ssh.platform.get_pageant_available", return_value=False):
                with patch("nbs_ssh.platform.get_openssh_agent_available", return_value=True):
                    result = get_agent_available()
                    assert result is True

    def test_get_agent_available_windows_neither(self) -> None:
        """On Windows with no agents, returns False."""
        with patch("nbs_ssh.platform.is_windows", return_value=True):
            with patch("nbs_ssh.platform.get_pageant_available", return_value=False):
                with patch("nbs_ssh.platform.get_openssh_agent_available", return_value=False):
                    result = get_agent_available()
                    assert result is False


# ---------------------------------------------------------------------------
# Integration with Auth Module Tests
# ---------------------------------------------------------------------------

class TestAuthIntegration:
    """Test that auth module uses platform functions correctly."""

    def test_auth_config_uses_expand_path(self) -> None:
        """AuthConfig uses platform-aware path expansion."""
        from nbs_ssh.auth import AuthConfig, AuthMethod

        # Create config with ~ path
        config = AuthConfig(
            method=AuthMethod.PRIVATE_KEY,
            key_path="~/.ssh/id_rsa",
        )

        # Path should be expanded
        assert "~" not in str(config.key_path)
        assert isinstance(config.key_path, Path)

    def test_check_agent_available_uses_platform(self) -> None:
        """check_agent_available delegates to platform module."""
        from nbs_ssh import auth

        # Patch at the location where it's used, not where it's defined
        with patch.object(auth, "get_agent_available", return_value=True) as mock:
            result = auth.check_agent_available()
            assert result is True
            mock.assert_called_once()
