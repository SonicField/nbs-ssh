# Worker: Auth Matrix (Slice 1)

## Task

Implement comprehensive authentication support with failure taxonomy. Extend the existing SSHConnection to support password, keyfile, and SSH agent authentication with proper error classification.

## Context

- Project: ~/local/nbs-ssh
- Venv: ~/local/nbs-ssh/venv (activate before work)
- Use PYTHONPATH=src for running tests (pip install -e doesn't work due to proxy)
- Existing code: src/nbs_ssh/connection.py has basic password auth
- Docker unavailable: tests should skip gracefully or use unit tests
- Terminal goal: AI-inspectable SSH client with evidence-first diagnostics

## Deliverables

### 1. Auth Module

Create `src/nbs_ssh/auth.py`:
- `AuthMethod` enum: PASSWORD, PRIVATE_KEY, SSH_AGENT
- `AuthConfig` dataclass: method, password, key_path, passphrase
- Helper functions for loading keys with proper error handling

### 2. Failure Taxonomy

Create `src/nbs_ssh/errors.py`:
- `SSHError` base class
- `AuthenticationError` with subtypes:
  - `AuthFailed`: Invalid credentials
  - `HostKeyMismatch`: Known hosts verification failed
  - `NoMutualKex`: Key exchange algorithm mismatch
  - `KeyLoadError`: Private key file issues
  - `AgentError`: SSH agent communication failed
- Each error should carry structured data for JSONL logging

### 3. Update Connection

Modify `src/nbs_ssh/connection.py`:
- Accept `AuthConfig` instead of separate password/key params
- Try auth methods in order if multiple provided
- Emit AUTH events with method tried and result
- Map AsyncSSH exceptions to our error taxonomy

### 4. Auth Tests

Create `tests/test_auth.py`:
- Test each auth method (unit tests where possible)
- Test failure scenarios with correct error types
- Test auth event emission with method details
- Property: auth errors carry enough context for debugging

## Success Criteria

1. Can authenticate with password, private key (with/without passphrase), and agent?
2. Do auth failures produce specific error types (not generic exceptions)?
3. Do AUTH events include method, success/failure, and timing?

## Engineering Standards

- Write tests FIRST
- Assertions for error type validation
- Each error type must be distinguishable programmatically

## Notes from Previous Worker

- AsyncSSH combines connect + auth; emit separate events for clarity
- Use PYTHONPATH=src pytest tests/ to run tests
- Docker unavailable - focus on unit tests for auth logic

## Status

State: completed
Started: 2026-02-04T16:00:00Z
Completed: 2026-02-04T16:15:00Z

## Log

### 2026-02-04 - Implementation Review & Fix

**Finding 1: Implementation Already Complete**
All four deliverables were already implemented:
- `src/nbs_ssh/auth.py` - AuthMethod enum, AuthConfig dataclass, key loading helpers
- `src/nbs_ssh/errors.py` - Full error taxonomy with SSHError base, AuthenticationError subtypes
- `src/nbs_ssh/connection.py` - Updated with AuthConfig support, auth fallback, AUTH events
- `tests/test_auth.py` - 28 comprehensive unit tests

**Finding 2: Missing ERROR Event Emission**
Test `test_connection_refused_error` failed because connection errors weren't emitting ERROR events before raising. Fixed by adding event emission in `_connect()` exception handler (connection.py:219-229).

**Test Results:**
- 29 passed, 4 skipped (Docker integration tests)
- All auth tests pass: error taxonomy, AuthConfig validation, key loading, agent detection, event emission

**Success Criteria Verification:**
1. ✓ Can authenticate with password, private key, SSH agent (via AuthConfig + method fallback)
2. ✓ Auth failures produce specific error types (AuthFailed, KeyLoadError, AgentError, etc.)
3. ✓ AUTH events include method, success/failure, and timing (duration_ms)

---

## Supervisor Actions (on completion)

After reading this completed task, supervisor must:
1. Capture 3Ws in supervisor.md
2. Increment workers_since_check
3. If workers_since_check >= 3, run self-check
