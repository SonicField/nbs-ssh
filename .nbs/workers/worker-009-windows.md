# Worker: Windows Hardening (Slice 8)

## Task

Add cross-platform support with Windows-specific path handling, key discovery, and CI compatibility.

## Context

- Project: ~/local/nbs-ssh
- Venv: ~/local/nbs-ssh/venv (activate before work)
- Use PYTHONPATH=src for running tests
- This is running on Linux but code must work on Windows
- Terminal goal: AI-inspectable SSH client that works cross-platform

## Deliverables

### 1. Path Abstractions

Create `src/nbs_ssh/platform.py`:
- `get_ssh_dir() -> Path` - ~/.ssh on Unix, %USERPROFILE%\.ssh on Windows
- `get_known_hosts_path() -> Path` - platform-appropriate known_hosts
- `get_default_key_paths() -> list[Path]` - id_rsa, id_ed25519, etc.
- `expand_path(path: str) -> Path` - handle ~ and %VARS%

### 2. Key Discovery

Add to platform.py:
- `discover_keys() -> list[Path]` - find available private keys
- `get_pageant_available() -> bool` - check for Pageant on Windows
- Handle both OpenSSH and PuTTY key locations

### 3. Agent Detection

Update auth.py to use platform functions:
- Unix: SSH_AUTH_SOCK environment variable
- Windows: Check for Pageant, OpenSSH agent service
- `get_agent_available() -> bool`

### 4. Path Validation

Add defensive path handling:
- Validate paths before use
- Handle long paths on Windows (260 char limit)
- Proper error messages for path issues

### 5. Tests

Create `tests/test_platform.py`:
- Test: get_ssh_dir returns correct path
- Test: expand_path handles ~ and env vars
- Test: discover_keys finds test keys
- Mock Windows platform for cross-platform testing

## Success Criteria

1. Does get_ssh_dir() return correct path for current platform?
2. Does expand_path() handle both ~ and %USERPROFILE%?
3. Do all path operations work with Path objects?

## Engineering Standards

- Use pathlib.Path everywhere (no os.path)
- No hardcoded path separators
- Test with mocked platform for Windows scenarios

## Status

State: completed
Started: 2026-02-04
Completed: 2026-02-04

## Log

### 2026-02-04: Implementation Complete

**Deliverable 1: Path Abstractions** ✓
- Created `src/nbs_ssh/platform.py` with:
  - `is_windows()` - Platform detection
  - `get_ssh_dir()` - Returns ~/.ssh on Unix, %USERPROFILE%\.ssh on Windows
  - `get_known_hosts_path()` - Platform-appropriate known_hosts path
  - `get_config_path()` - SSH config file path
  - `get_default_key_paths()` - Returns [id_ed25519, id_rsa, id_ecdsa, id_dsa]
  - `expand_path(path)` - Handles ~ and %VARS% (Windows) expansion

**Deliverable 2: Key Discovery** ✓
- Added to platform.py:
  - `discover_keys()` - Finds available private keys in SSH and PuTTY locations
  - `get_putty_key_paths()` - Checks %USERPROFILE%\.putty and Documents\SSH Keys
  - `get_pageant_available()` - Uses ctypes to check for Pageant window on Windows

**Deliverable 3: Agent Detection** ✓
- Updated `auth.py` to use platform functions:
  - Imported `expand_path`, `get_agent_available`, `get_openssh_agent_available`
  - `check_agent_available()` now delegates to `platform.get_agent_available()`
  - `AuthConfig.__post_init__` now uses `expand_path()` for key paths
  - `load_private_key()` now uses `expand_path()` for key paths
- Platform module provides:
  - `get_openssh_agent_available()` - Checks SSH_AUTH_SOCK on Unix, sc query on Windows
  - `get_agent_available()` - Checks Pageant + OpenSSH agent on Windows, SSH_AUTH_SOCK on Unix

**Deliverable 4: Path Validation** ✓
- Added `validate_path(path, description)` function:
  - Returns (is_valid, error_message) tuple
  - Checks path exists
  - Checks path is readable
  - Checks Windows MAX_PATH (260 chars) limit

**Deliverable 5: Tests** ✓
- Created `tests/test_platform.py` with 36 tests:
  - TestPlatformDetection: 2 tests
  - TestSSHDirectory: 6 tests
  - TestDefaultKeyPaths: 4 tests
  - TestPathExpansion: 7 tests (including mocked Windows scenarios)
  - TestPathValidation: 4 tests
  - TestKeyDiscovery: 4 tests
  - TestAgentDetection: 7 tests
  - TestAuthIntegration: 2 tests

**Success Criteria Verification:**
1. ✓ `get_ssh_dir()` returns correct path for current platform
2. ✓ `expand_path()` handles both ~ and %USERPROFILE% (via os.path.expandvars on Windows)
3. ✓ All path operations use pathlib.Path objects

**Test Results:**
- 36/36 platform tests passing
- 28/28 auth tests passing
- All functions exported via `__init__.py`

**Notes:**
- `os.path.expandvars` only expands %VAR% on actual Windows; tests mock this behaviour
- PuTTY key detection uses ctypes FindWindowW - gracefully fails on non-Windows
- Windows OpenSSH agent detection uses `sc query ssh-agent` subprocess
