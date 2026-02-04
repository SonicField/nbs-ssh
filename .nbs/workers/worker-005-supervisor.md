# Worker: Supervisor FSM + Reconnection (Slice 4)

## Task

Implement a state machine for connection lifecycle with automatic reconnection, exponential backoff, and retry policies.

## Context

- Project: ~/local/nbs-ssh
- Venv: ~/local/nbs-ssh/venv (activate before work)
- Use PYTHONPATH=src for running tests
- Existing: SSHConnection, KeepaliveConfig, DisconnectReason
- Terminal goal: AI-inspectable SSH client with supervisor-managed reconnection

## Deliverables

### 1. Connection State Machine

Create `src/nbs_ssh/supervisor.py`:
- `ConnectionState` enum: DISCONNECTED, CONNECTING, CONNECTED, RECONNECTING, FAILED
- `SSHSupervisor` class that wraps SSHConnection
- State transitions with event emission

### 2. Retry Policy

Add to supervisor.py:
- `RetryPolicy` dataclass: max_retries, base_delay_sec, max_delay_sec, exponential_base
- Exponential backoff: delay = base * (exponential_base ** attempt)
- Jitter option to prevent thundering herd

### 3. Reconnection Logic

SSHSupervisor should:
- Automatically reconnect on disconnect (unless FAILED state)
- Use retry policy for backoff
- Emit STATE_CHANGE events
- Track reconnection_count

### 4. Supervised Connection API

Provide:
- `async with SSHSupervisor(...) as supervisor:` context manager
- `supervisor.exec(cmd)` that auto-retries on transient failures
- `supervisor.wait_connected()` coroutine
- `supervisor.close()` for clean shutdown

### 5. Tests

Create `tests/test_supervisor.py`:
- Test: State transitions are correct
- Test: Exponential backoff timing
- Test: Max retries enforced
- Test: STATE_CHANGE events emitted

## Success Criteria

1. Does SSHSupervisor reconnect automatically on disconnect?
2. Is exponential backoff correctly implemented?
3. Do STATE_CHANGE events show all transitions?

## Status

State: in_progress
Started: 2026-02-04
Completed:

## Log

[Worker will append findings here]
