# Worker: Add Key Auth to MockSSHServer

## Task

Add SSH key-based authentication support to MockSSHServer so test_connect_with_key can run.

## Context

- Project: ~/local/nbs-ssh
- Venv: ~/local/nbs-ssh/venv (activate before work)
- Use PYTHONPATH=src for tests

## The Gap

MockSSHServer currently only supports password authentication. The test `test_connect_with_key` in `tests/test_hello_ssh.py` is skipped because key auth is not implemented.

## Instructions

1. Read `src/nbs_ssh/testing/mock_server.py` to understand MockSSHServer
2. Read AsyncSSH documentation on server-side key authentication
3. Add key auth support to MockServerConfig (e.g., `authorized_keys: list[str]` or path to authorized_keys file)
4. Implement key verification in the server
5. Update `tests/test_hello_ssh.py` to use key auth with the mock server
6. Unskip `test_connect_with_key`
7. Run the test: `PYTHONPATH=src python -m pytest tests/test_hello_ssh.py -v`
8. Run full test suite to ensure no regressions
9. Commit with descriptive message

## Success Criteria

1. Does `test_connect_with_key` pass (not skip)?
2. Does the full test suite still pass?
3. Is key auth configurable via MockServerConfig?

## Status

State: complete
Started: 2026-02-05 01:08
Completed: 2026-02-05 01:13

## Log

### Implementation

1. **Read MockSSHServer** - Understood existing password auth implementation in `MockSSHServerProtocol.validate_password()`

2. **Added key auth to MockServerConfig** - Added `authorized_keys: list[SSHKey | str]` field to accept public keys in either SSHKey object or OpenSSH string format

3. **Implemented key verification** - Updated `MockSSHServerProtocol`:
   - `public_key_auth_supported()` now returns True when authorized_keys is configured
   - Added `validate_public_key()` method that compares presented keys against authorized keys

4. **Updated test** - Rewrote `test_connect_with_key` to:
   - Generate a temporary RSA keypair
   - Write private key to temp file (SSHConnection expects paths)
   - Configure MockServerConfig with public key
   - Connect using key auth and verify command execution
   - Assert AUTH event shows `private_key` method

5. **Tests pass**:
   - `test_connect_with_key` now passes (was skipped)
   - All 6 tests in `test_hello_ssh.py` pass
   - 246 tests pass overall (6 failures in test_streaming.py are pre-existing fixture issues unrelated to this change)
