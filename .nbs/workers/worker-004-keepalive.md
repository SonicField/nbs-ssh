# Worker: Keepalive + Freeze Detection (Slice 3)

## Task

Implement connection keepalive and freeze detection using AsyncSSH's keepalive semantics. This is the foundation for the supervisor's reconnection logic.

## Context

- Project: ~/local/nbs-ssh
- Venv: ~/local/nbs-ssh/venv (activate before work)
- Use PYTHONPATH=src for running tests
- AsyncSSH has: keepalive_interval, keepalive_count_max
- Terminal goal: AI-inspectable SSH client with evidence-first diagnostics

## Deliverables

### 1. Keepalive Configuration

Add to `src/nbs_ssh/connection.py` or create `src/nbs_ssh/keepalive.py`:
- `KeepaliveConfig` dataclass: interval_sec, max_count, progress_timeout_sec
- Pass keepalive settings to AsyncSSH on connect
- Default: 30s interval, 3 max count (90s total before disconnect)

### 2. Freeze Detection

Implement two-level freeze detection:
- **SSH-level**: AsyncSSH keepalive timeout (connection actually dead)
- **Progress-level**: Command running but no output (application frozen)

Add:
- `ProgressWatchdog` class that monitors exec output
- Configurable timeout for "no output received"
- Emit WARNING event before hard timeout

### 3. Disconnect Reasons

Add to `src/nbs_ssh/errors.py`:
- `DisconnectReason` enum: NORMAL, KEEPALIVE_TIMEOUT, PROGRESS_TIMEOUT, NETWORK_ERROR, AUTH_FAILURE
- Ensure disconnect events include the reason

### 4. Keepalive Events

Add event types:
- `KEEPALIVE_SENT`: Keepalive request sent
- `KEEPALIVE_RECEIVED`: Response received
- `KEEPALIVE_TIMEOUT`: No response after max_count

### 5. Tests

Create `tests/test_keepalive.py`:
- Test: KeepaliveConfig validation
- Test: Keepalive events emitted (mock or short intervals)
- Test: ProgressWatchdog triggers after timeout
- Test: DisconnectReason correctly classified

## Success Criteria

1. Can configure keepalive_interval and keepalive_count_max on connection?
2. Does DISCONNECT event include the correct DisconnectReason?
3. Does ProgressWatchdog emit WARNING before timeout?

## Engineering Standards

- Write tests FIRST
- Keepalive must be configurable, not hardcoded
- Progress watchdog separate from SSH keepalive

## Status

State: completed
Started: 2026-02-04
Completed: 2026-02-04

## Log

2026-02-04: Started. Reviewed existing codebase structure:
- connection.py: SSHConnection with async context manager, exec(), EventEmitter integration
- events.py: EventType enum (CONNECT, AUTH, EXEC, DISCONNECT, ERROR), EventCollector, EventEmitter
- errors.py: Error taxonomy with ErrorContext
- auth.py: AuthConfig, AuthMethod enum

Plan:
1. Write tests first (test_keepalive.py)
2. Add DisconnectReason enum to errors.py
3. Add keepalive event types to events.py
4. Create keepalive.py with KeepaliveConfig and ProgressWatchdog
5. Update connection.py to integrate keepalive
6. Update __init__.py exports

2026-02-04: Implementation complete. All deliverables:

### Deliverables Completed:

1. **KeepaliveConfig** (src/nbs_ssh/keepalive.py:24-72)
   - Dataclass with: interval_sec (default 30.0), max_count (default 3), progress_timeout_sec
   - Validation via __post_init__ for positive values
   - total_timeout_sec property: interval * max_count
   - to_asyncssh_options() method for passing to AsyncSSH

2. **Freeze Detection** (src/nbs_ssh/keepalive.py:75-214)
   - Two-level detection as specified:
     - SSH-level: Via AsyncSSH keepalive_interval/keepalive_count_max
     - Progress-level: ProgressWatchdog class
   - ProgressWatchdog monitors exec output with configurable timeout
   - Emits PROGRESS_WARNING event before hard timeout (at warning_threshold, default 75%)
   - Supports on_timeout callback

3. **DisconnectReason enum** (src/nbs_ssh/errors.py:29-39)
   - NORMAL, KEEPALIVE_TIMEOUT, PROGRESS_TIMEOUT, NETWORK_ERROR, AUTH_FAILURE
   - DISCONNECT events now include reason field

4. **Keepalive Events** (src/nbs_ssh/events.py:36-41)
   - KEEPALIVE_SENT, KEEPALIVE_RECEIVED, KEEPALIVE_TIMEOUT
   - PROGRESS_WARNING (for watchdog warnings)

5. **Tests** (tests/test_keepalive.py)
   - 18 tests covering all deliverables
   - TestKeepaliveConfig: 7 tests for validation and options
   - TestDisconnectReason: 2 tests for enum values
   - TestProgressWatchdog: 5 tests for watchdog behavior
   - TestKeepaliveEventTypes: 2 tests for event types
   - TestDisconnectWithReason/TestKeepaliveIntegration: 2 integration tests (Docker-dependent)

6. **SSHConnection Integration** (src/nbs_ssh/connection.py)
   - Added keepalive parameter to __init__
   - Passes keepalive options to AsyncSSH via to_asyncssh_options()
   - _disconnect() now includes DisconnectReason in event

### Test Results:
- 45 tests passed, 12 skipped (Docker integration tests)
- No regressions in existing functionality

### Success Criteria Met:
1. ✅ Can configure keepalive_interval and keepalive_count_max on connection
2. ✅ DISCONNECT event includes the correct DisconnectReason
3. ✅ ProgressWatchdog emits WARNING before timeout (at 75% threshold)

---

## Supervisor Actions (on completion)

After reading this completed task, supervisor must:
1. Capture 3Ws in supervisor.md
2. Increment workers_since_check
3. If workers_since_check >= 3, run self-check
