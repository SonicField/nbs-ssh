"""
Cross-platform path handling and key discovery.

Provides:
- Platform-appropriate SSH directory and file paths
- Private key discovery across common locations
- SSH agent detection for Unix and Windows
- Path expansion and validation
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


def is_windows() -> bool:
    """Check if running on Windows."""
    return sys.platform == "win32"


def get_ssh_dir() -> Path:
    """
    Get the platform-appropriate SSH directory.

    Returns:
        ~/.ssh on Unix, %USERPROFILE%\\.ssh on Windows
    """
    if is_windows():
        # Windows: use USERPROFILE
        userprofile = os.environ.get("USERPROFILE")
        if userprofile:
            return Path(userprofile) / ".ssh"
        # Fallback to HOME if USERPROFILE not set
        home = os.environ.get("HOME")
        if home:
            return Path(home) / ".ssh"
        # Last resort: expanduser
        return Path.home() / ".ssh"
    else:
        # Unix: use HOME or expanduser
        return Path.home() / ".ssh"


def get_known_hosts_path() -> Path:
    """
    Get the platform-appropriate known_hosts file path.

    Returns:
        Path to known_hosts file
    """
    return get_ssh_dir() / "known_hosts"


def get_config_path() -> Path:
    """
    Get the platform-appropriate SSH config file path.

    Returns:
        Path to SSH config file
    """
    return get_ssh_dir() / "config"


def get_system_config_path() -> Path:
    """
    Get the system-wide SSH config file path.

    Returns:
        Path to system SSH config file (/etc/ssh/ssh_config on Unix)
    """
    if is_windows():
        # Windows OpenSSH uses ProgramData
        program_data = os.environ.get("ProgramData", "C:\\ProgramData")
        return Path(program_data) / "ssh" / "ssh_config"
    else:
        return Path("/etc/ssh/ssh_config")


def parse_ssh_config_identity_files(
    config_path: Path,
    username: str | None = None,
) -> list[Path]:
    """
    Parse an SSH config file and extract IdentityFile entries.

    Parses IdentityFile directives from SSH config, expanding tokens:
    - ~ expands to home directory
    - %u expands to local username

    Args:
        config_path: Path to SSH config file
        username: Username for %u expansion (defaults to current user)

    Returns:
        List of expanded identity file paths (existence not verified)
    """
    if not config_path.exists():
        return []

    if username is None:
        import getpass
        username = getpass.getuser()

    identity_files: list[Path] = []

    try:
        with open(config_path, "r") as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith("#"):
                    continue

                # Parse IdentityFile directive (case-insensitive)
                parts = line.split(None, 1)
                if len(parts) == 2 and parts[0].lower() == "identityfile":
                    path_str = parts[1]

                    # Expand tokens
                    path_str = path_str.replace("%u", username)

                    # Expand ~ and environment variables
                    expanded = expand_path(path_str)
                    identity_files.append(expanded)
    except (OSError, IOError):
        # Config file not readable, skip silently
        pass

    return identity_files


def get_config_identity_files(username: str | None = None) -> list[Path]:
    """
    Get IdentityFile paths from SSH config files.

    Reads both user config (~/.ssh/config) and system config
    (/etc/ssh/ssh_config), returning all IdentityFile entries.

    Args:
        username: Username for %u expansion (defaults to current user)

    Returns:
        List of identity file paths from config (user config first)
    """
    identity_files: list[Path] = []
    seen: set[Path] = set()

    # User config takes precedence
    user_config = get_config_path()
    for path in parse_ssh_config_identity_files(user_config, username):
        if path not in seen:
            identity_files.append(path)
            seen.add(path)

    # Then system config
    system_config = get_system_config_path()
    for path in parse_ssh_config_identity_files(system_config, username):
        if path not in seen:
            identity_files.append(path)
            seen.add(path)

    return identity_files


def get_default_key_paths() -> list[Path]:
    """
    Get the default private key file paths.

    Includes:
    1. Paths from SSH config files (IdentityFile directives)
    2. Common key filenames in ~/.ssh/:
       - id_ed25519 (modern, preferred)
       - id_rsa (legacy but common)
       - id_ecdsa
       - id_dsa (deprecated)

    Returns:
        List of paths to check for private keys (config paths first)
    """
    paths: list[Path] = []
    seen: set[Path] = set()

    # First: paths from SSH config files
    for path in get_config_identity_files():
        if path not in seen:
            paths.append(path)
            seen.add(path)

    # Then: hardcoded defaults (if not already in config)
    ssh_dir = get_ssh_dir()
    for name in ["id_ed25519", "id_rsa", "id_ecdsa", "id_dsa"]:
        path = ssh_dir / name
        if path not in seen:
            paths.append(path)
            seen.add(path)

    return paths


def expand_path(path: str | Path) -> Path:
    """
    Expand a path, handling ~ and environment variables.

    On Unix: expands ~ to $HOME
    On Windows: expands ~ to %USERPROFILE%, also expands %VAR% syntax

    Args:
        path: Path string or Path object to expand

    Returns:
        Expanded Path object
    """
    path_str = str(path)

    # Handle Windows %VAR% syntax
    if is_windows():
        # Expand %VARIABLE% patterns
        path_str = os.path.expandvars(path_str)

    # Expand ~ to home directory (works on both platforms)
    expanded = Path(path_str).expanduser()

    return expanded


def validate_path(path: Path, description: str = "path") -> tuple[bool, str | None]:
    """
    Validate a path for common issues.

    Checks for:
    - Path exists
    - Path is accessible
    - Path length (Windows 260 char limit)

    Args:
        path: Path to validate
        description: Description for error messages

    Returns:
        Tuple of (is_valid, error_message)
        error_message is None if valid
    """
    # Check Windows long path limit
    if is_windows():
        # Windows MAX_PATH is 260, but some APIs handle up to 32767 with \\?\ prefix
        # We warn at 260 as it's the most common limit
        if len(str(path)) >= 260:
            return False, f"{description} exceeds Windows MAX_PATH (260 chars): {path}"

    # Check if path exists
    if not path.exists():
        return False, f"{description} does not exist: {path}"

    # Check if readable
    if not os.access(path, os.R_OK):
        return False, f"{description} is not readable: {path}"

    return True, None


def discover_keys() -> list[Path]:
    """
    Discover available private keys on the system.

    Searches:
    - Default SSH directory keys (id_ed25519, id_rsa, etc.)
    - PuTTY key location on Windows (%USERPROFILE%\\.putty\\keys)

    Returns:
        List of paths to discovered private key files
    """
    discovered = []

    # Check default key locations
    for key_path in get_default_key_paths():
        if key_path.exists() and key_path.is_file():
            # Verify it's readable
            if os.access(key_path, os.R_OK):
                discovered.append(key_path)

    # On Windows, also check PuTTY key locations
    if is_windows():
        putty_paths = get_putty_key_paths()
        for key_path in putty_paths:
            if key_path.exists() and key_path.is_file():
                if os.access(key_path, os.R_OK):
                    discovered.append(key_path)

    return discovered


def get_putty_key_paths() -> list[Path]:
    """
    Get common PuTTY private key locations on Windows.

    Returns:
        List of paths where PuTTY keys might be stored
    """
    if not is_windows():
        return []

    paths = []

    # PuTTY's default key directory
    userprofile = os.environ.get("USERPROFILE")
    if userprofile:
        putty_dir = Path(userprofile) / ".putty"
        if putty_dir.exists():
            # Check for .ppk files
            paths.extend(putty_dir.glob("*.ppk"))

        # Some users store keys in Documents
        documents = Path(userprofile) / "Documents" / "SSH Keys"
        if documents.exists():
            paths.extend(documents.glob("*.ppk"))
            paths.extend(documents.glob("id_*"))

    return list(paths)


def get_pageant_available() -> bool:
    """
    Check if Pageant (PuTTY's SSH agent) is available on Windows.

    Uses the Windows named pipe interface that Pageant creates.

    Returns:
        True if Pageant appears to be running
    """
    if not is_windows():
        return False

    try:
        # Pageant creates a window with a specific class name
        # We check for the named pipe it creates
        import ctypes
        from ctypes import wintypes

        # Try to find Pageant window
        FindWindowW = ctypes.windll.user32.FindWindowW
        FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
        FindWindowW.restype = wintypes.HWND

        hwnd = FindWindowW("Pageant", "Pageant")
        return hwnd != 0
    except (ImportError, AttributeError, OSError):
        # ctypes not available or not on Windows
        return False


def get_openssh_agent_available() -> bool:
    """
    Check if OpenSSH agent is available.

    On Unix: checks SSH_AUTH_SOCK environment variable
    On Windows: checks for the OpenSSH Authentication Agent service

    Returns:
        True if an OpenSSH agent is available
    """
    if is_windows():
        return _check_windows_openssh_agent()
    else:
        return _check_unix_ssh_agent()


def _check_unix_ssh_agent() -> bool:
    """Check for SSH agent on Unix via SSH_AUTH_SOCK."""
    auth_sock = os.environ.get("SSH_AUTH_SOCK")
    if not auth_sock:
        return False

    sock_path = Path(auth_sock)
    return sock_path.exists()


def _check_windows_openssh_agent() -> bool:
    """Check for OpenSSH Authentication Agent service on Windows."""
    if not is_windows():
        return False

    try:
        import subprocess

        # Check if the service is running
        result = subprocess.run(
            ["sc", "query", "ssh-agent"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        # Look for "STATE" and "RUNNING" in output
        return "RUNNING" in result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def get_agent_available() -> bool:
    """
    Check if any SSH agent is available on the current platform.

    Checks:
    - Unix: SSH_AUTH_SOCK environment variable
    - Windows: Pageant and OpenSSH Authentication Agent service

    Returns:
        True if any agent is available
    """
    if is_windows():
        return get_pageant_available() or get_openssh_agent_available()
    else:
        return get_openssh_agent_available()
