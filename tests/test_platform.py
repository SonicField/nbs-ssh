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
    get_known_hosts_read_paths,
    get_known_hosts_write_path,
    get_openssh_agent_available,
    get_pageant_available,
    get_putty_key_paths,
    get_ssh_dir,
    get_system_known_hosts_path,
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
            # Use a Windows-style absolute path so the postcondition passes
            env = {"HOME": "C:\\Users\\fallback"}
            # Remove USERPROFILE
            with patch.dict(os.environ, env, clear=True):
                result = get_ssh_dir()
                assert result == Path("C:\\Users\\fallback") / ".ssh"

    def test_get_known_hosts_path(self) -> None:
        """get_known_hosts_path() returns path in ssh directory."""
        result = get_known_hosts_path()
        assert result.name == "known_hosts"
        assert result.parent == get_ssh_dir()


# ---------------------------------------------------------------------------
# Known Hosts Path Tests
# ---------------------------------------------------------------------------

class TestKnownHostsPaths:
    """Test known_hosts path discovery functions."""

    def test_get_system_known_hosts_path_unix(self) -> None:
        """On Unix, system known_hosts is in /etc/ssh/."""
        with patch("nbs_ssh.platform.is_windows", return_value=False):
            result = get_system_known_hosts_path()
            assert result == Path("/etc/ssh/ssh_known_hosts")

    def test_get_system_known_hosts_path_windows(self) -> None:
        """On Windows, system known_hosts uses ProgramData."""
        with patch("nbs_ssh.platform.is_windows", return_value=True):
            with patch.dict(os.environ, {"ProgramData": "C:\\ProgramData"}):
                result = get_system_known_hosts_path()
                assert result == Path("C:\\ProgramData") / "ssh" / "ssh_known_hosts"

    def test_get_known_hosts_read_paths_returns_list(self) -> None:
        """get_known_hosts_read_paths() returns a list of Paths."""
        result = get_known_hosts_read_paths()
        assert isinstance(result, list)
        assert all(isinstance(p, Path) for p in result)

    def test_get_known_hosts_read_paths_only_existing(self, tmp_path: Path) -> None:
        """get_known_hosts_read_paths() returns only files that exist."""
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        user_known_hosts = ssh_dir / "known_hosts"
        user_known_hosts.write_text("# test")

        with patch("nbs_ssh.platform.get_known_hosts_path", return_value=user_known_hosts):
            with patch("nbs_ssh.platform.get_system_known_hosts_path",
                       return_value=tmp_path / "nonexistent"):
                result = get_known_hosts_read_paths()

        assert len(result) == 1
        assert result[0] == user_known_hosts

    def test_get_known_hosts_read_paths_user_first(self, tmp_path: Path) -> None:
        """get_known_hosts_read_paths() returns user file before system file."""
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        etc_dir = tmp_path / "etc" / "ssh"
        etc_dir.mkdir(parents=True)

        user_known_hosts = ssh_dir / "known_hosts"
        user_known_hosts.write_text("# user")
        system_known_hosts = etc_dir / "ssh_known_hosts"
        system_known_hosts.write_text("# system")

        with patch("nbs_ssh.platform.get_known_hosts_path", return_value=user_known_hosts):
            with patch("nbs_ssh.platform.get_system_known_hosts_path",
                       return_value=system_known_hosts):
                result = get_known_hosts_read_paths()

        assert len(result) == 2
        assert result[0] == user_known_hosts
        assert result[1] == system_known_hosts

    def test_get_known_hosts_read_paths_empty_when_none_exist(self, tmp_path: Path) -> None:
        """get_known_hosts_read_paths() returns empty list when no files exist."""
        with patch("nbs_ssh.platform.get_known_hosts_path",
                   return_value=tmp_path / "nonexistent1"):
            with patch("nbs_ssh.platform.get_system_known_hosts_path",
                       return_value=tmp_path / "nonexistent2"):
                result = get_known_hosts_read_paths()

        assert result == []

    def test_get_known_hosts_read_paths_skips_directories(self, tmp_path: Path) -> None:
        """get_known_hosts_read_paths() skips paths that are directories."""
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        # Create known_hosts as a directory, not a file
        known_hosts_dir = ssh_dir / "known_hosts"
        known_hosts_dir.mkdir()

        with patch("nbs_ssh.platform.get_known_hosts_path", return_value=known_hosts_dir):
            with patch("nbs_ssh.platform.get_system_known_hosts_path",
                       return_value=tmp_path / "nonexistent"):
                result = get_known_hosts_read_paths()

        assert result == []

    def test_get_known_hosts_write_path_returns_path(self) -> None:
        """get_known_hosts_write_path() returns a Path object."""
        result = get_known_hosts_write_path()
        assert isinstance(result, Path)
        assert result.name == "known_hosts"

    def test_get_known_hosts_write_path_creates_parent_dir(self, tmp_path: Path) -> None:
        """get_known_hosts_write_path() creates parent directory if needed."""
        ssh_dir = tmp_path / "new_user" / ".ssh"
        known_hosts = ssh_dir / "known_hosts"

        assert not ssh_dir.exists()

        with patch("nbs_ssh.platform.get_known_hosts_path", return_value=known_hosts):
            result = get_known_hosts_write_path()

        assert result == known_hosts
        assert ssh_dir.exists()
        assert ssh_dir.is_dir()

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix file permissions not available on Windows")
    def test_get_known_hosts_write_path_sets_dir_permissions(self, tmp_path: Path) -> None:
        """get_known_hosts_write_path() creates directory with mode 0o700."""
        ssh_dir = tmp_path / "perm_test" / ".ssh"
        known_hosts = ssh_dir / "known_hosts"

        with patch("nbs_ssh.platform.get_known_hosts_path", return_value=known_hosts):
            get_known_hosts_write_path()

        # Check permissions (masking out any umask effects on non-permission bits)
        mode = ssh_dir.stat().st_mode & 0o777
        assert mode == 0o700

    def test_get_known_hosts_write_path_existing_dir(self, tmp_path: Path) -> None:
        """get_known_hosts_write_path() works when directory already exists."""
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir(mode=0o755)
        known_hosts = ssh_dir / "known_hosts"

        with patch("nbs_ssh.platform.get_known_hosts_path", return_value=known_hosts):
            result = get_known_hosts_write_path()

        assert result == known_hosts

    def test_get_known_hosts_write_path_file_need_not_exist(self, tmp_path: Path) -> None:
        """get_known_hosts_write_path() returns path even if file doesn't exist."""
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        known_hosts = ssh_dir / "known_hosts"

        assert not known_hosts.exists()

        with patch("nbs_ssh.platform.get_known_hosts_path", return_value=known_hosts):
            result = get_known_hosts_write_path()

        assert result == known_hosts
        # File itself should still not exist (just the path is returned)
        assert not known_hosts.exists()


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
        """Hardcoded default key paths are in the SSH directory."""
        ssh_dir = get_ssh_dir()
        # Mock config to return empty list (test hardcoded defaults only)
        with patch("nbs_ssh.platform.get_config_identity_files", return_value=[]):
            result = get_default_key_paths()
            for path in result:
                assert path.parent == ssh_dir


# ---------------------------------------------------------------------------
# SSH Config Parsing Tests
# ---------------------------------------------------------------------------

class TestSSHConfigParsing:
    """Test parsing of SSH config files for IdentityFile entries."""

    def test_parse_empty_config(self, tmp_path: Path) -> None:
        """parse_ssh_config_identity_files() returns empty list for empty config."""
        from nbs_ssh.platform import parse_ssh_config_identity_files

        config = tmp_path / "config"
        config.write_text("")

        result = parse_ssh_config_identity_files(config)
        assert result == []

    def test_parse_config_with_identity_file(self, tmp_path: Path) -> None:
        """parse_ssh_config_identity_files() extracts IdentityFile entries."""
        from nbs_ssh.platform import parse_ssh_config_identity_files

        config = tmp_path / "config"
        config.write_text("IdentityFile ~/.ssh/my_key\n")

        result = parse_ssh_config_identity_files(config)
        assert len(result) == 1
        assert result[0].name == "my_key"
        assert ".ssh" in str(result[0])

    def test_parse_config_multiple_identity_files(self, tmp_path: Path) -> None:
        """parse_ssh_config_identity_files() extracts multiple entries."""
        from nbs_ssh.platform import parse_ssh_config_identity_files

        config = tmp_path / "config"
        config.write_text(
            "IdentityFile ~/.ssh/key1\n"
            "IdentityFile ~/.ssh/key2\n"
            "IdentityFile /absolute/path/key3\n"
        )

        result = parse_ssh_config_identity_files(config)
        assert len(result) == 3
        names = [p.name for p in result]
        assert "key1" in names
        assert "key2" in names
        assert "key3" in names

    def test_parse_config_case_insensitive(self, tmp_path: Path) -> None:
        """parse_ssh_config_identity_files() is case-insensitive."""
        from nbs_ssh.platform import parse_ssh_config_identity_files

        config = tmp_path / "config"
        config.write_text("identityfile ~/.ssh/lower\nIDENTITYFILE ~/.ssh/upper\n")

        result = parse_ssh_config_identity_files(config)
        assert len(result) == 2

    def test_parse_config_skips_comments(self, tmp_path: Path) -> None:
        """parse_ssh_config_identity_files() skips comment lines."""
        from nbs_ssh.platform import parse_ssh_config_identity_files

        config = tmp_path / "config"
        config.write_text(
            "# IdentityFile ~/.ssh/commented\n"
            "IdentityFile ~/.ssh/real\n"
        )

        result = parse_ssh_config_identity_files(config)
        assert len(result) == 1
        assert result[0].name == "real"

    def test_parse_config_expands_username_token(self, tmp_path: Path) -> None:
        """parse_ssh_config_identity_files() expands %u to username."""
        from nbs_ssh.platform import parse_ssh_config_identity_files

        config = tmp_path / "config"
        config.write_text("IdentityFile /var/keys/%u/id_rsa\n")

        result = parse_ssh_config_identity_files(config, username="testuser")
        assert len(result) == 1
        assert "testuser" in str(result[0])
        assert "%u" not in str(result[0])

    def test_parse_nonexistent_config(self, tmp_path: Path) -> None:
        """parse_ssh_config_identity_files() returns empty for nonexistent file."""
        from nbs_ssh.platform import parse_ssh_config_identity_files

        config = tmp_path / "nonexistent"
        result = parse_ssh_config_identity_files(config)
        assert result == []

    def test_get_config_identity_files_deduplicates(self, tmp_path: Path, monkeypatch) -> None:
        """get_config_identity_files() removes duplicate paths."""
        # Import the real function (autouse fixture mocks it)
        import nbs_ssh.platform as platform_module
        from nbs_ssh.platform import parse_ssh_config_identity_files

        # Restore the real get_config_identity_files for this test
        def real_get_config_identity_files(username=None):
            identity_files = []
            seen = set()
            for path in parse_ssh_config_identity_files(platform_module.get_config_path(), username):
                if path not in seen:
                    identity_files.append(path)
                    seen.add(path)
            for path in parse_ssh_config_identity_files(platform_module.get_system_config_path(), username):
                if path not in seen:
                    identity_files.append(path)
                    seen.add(path)
            return identity_files

        monkeypatch.setattr("nbs_ssh.platform.get_config_identity_files", real_get_config_identity_files)

        user_config = tmp_path / "user_config"
        system_config = tmp_path / "system_config"

        # Same path in both configs
        user_config.write_text("IdentityFile ~/.ssh/shared_key\n")
        system_config.write_text("IdentityFile ~/.ssh/shared_key\n")

        with patch("nbs_ssh.platform.get_config_path", return_value=user_config):
            with patch("nbs_ssh.platform.get_system_config_path", return_value=system_config):
                result = real_get_config_identity_files()

        # Should only appear once
        names = [p.name for p in result]
        assert names.count("shared_key") == 1

    def test_get_default_key_paths_includes_config_paths(self, tmp_path: Path, monkeypatch) -> None:
        """get_default_key_paths() includes paths from SSH config."""
        # Import the real function
        import nbs_ssh.platform as platform_module
        from nbs_ssh.platform import parse_ssh_config_identity_files

        # Restore the real get_config_identity_files for this test
        def real_get_config_identity_files(username=None):
            identity_files = []
            seen = set()
            for path in parse_ssh_config_identity_files(platform_module.get_config_path(), username):
                if path not in seen:
                    identity_files.append(path)
                    seen.add(path)
            for path in parse_ssh_config_identity_files(platform_module.get_system_config_path(), username):
                if path not in seen:
                    identity_files.append(path)
                    seen.add(path)
            return identity_files

        monkeypatch.setattr("nbs_ssh.platform.get_config_identity_files", real_get_config_identity_files)

        config = tmp_path / "config"
        config.write_text("IdentityFile /custom/location/special_key\n")

        with patch("nbs_ssh.platform.get_config_path", return_value=config):
            with patch("nbs_ssh.platform.get_system_config_path", return_value=tmp_path / "none"):
                result = get_default_key_paths()

        # Should include our custom path
        paths_str = [str(p) for p in result]
        assert any("special_key" in p for p in paths_str)


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

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix file permissions not available on Windows")
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
            with patch("nbs_ssh.platform.get_config_identity_files", return_value=[]):
                result = discover_keys()

        assert len(result) == 2
        assert id_rsa in result
        assert id_ed25519 in result

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix file permissions not available on Windows")
    def test_discover_keys_skips_unreadable(self, tmp_path: Path) -> None:
        """discover_keys() skips unreadable key files."""
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()

        id_rsa = ssh_dir / "id_rsa"
        id_rsa.write_text("fake key")
        id_rsa.chmod(0o000)

        try:
            with patch("nbs_ssh.platform.get_ssh_dir", return_value=ssh_dir):
                with patch("nbs_ssh.platform.get_config_identity_files", return_value=[]):
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
