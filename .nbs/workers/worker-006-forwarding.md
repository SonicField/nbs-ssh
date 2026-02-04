# Worker: Port Forwarding (Slice 5)

## Task

Implement local, remote, and dynamic (SOCKS) port forwarding with intent replay on reconnection.

## Context

- Project: ~/local/nbs-ssh
- Venv: ~/local/nbs-ssh/venv (activate before work)
- Use PYTHONPATH=src for running tests
- Existing: SSHConnection, SSHSupervisor (if completed)
- AsyncSSH has: forward_local_port, forward_remote_port, forward_socks
- Terminal goal: AI-inspectable SSH client with port forwarding

## Deliverables

### 1. Forwarding Types

Create `src/nbs_ssh/forwarding.py`:
- `ForwardType` enum: LOCAL, REMOTE, DYNAMIC
- `ForwardIntent` dataclass: type, local_host, local_port, remote_host, remote_port
- For dynamic: only local_host/port needed

### 2. Forward Manager

Add to forwarding.py:
- `ForwardManager` class that tracks active forwards
- Methods: add_forward(), remove_forward(), list_forwards()
- Stores intents for replay on reconnect

### 3. SSHConnection Integration

Update SSHConnection or create wrapper:
- `forward_local(local_port, remote_host, remote_port)` -> ForwardHandle
- `forward_remote(remote_port, local_host, local_port)` -> ForwardHandle
- `forward_dynamic(local_port)` -> ForwardHandle
- ForwardHandle has `close()` method

### 4. Reconnection Replay

If SSHSupervisor exists, integrate:
- On reconnect, replay all active ForwardIntents
- Emit FORWARD events with intent details
- Handle replay failures gracefully

### 5. Tests

Create `tests/test_forwarding.py`:
- Test: ForwardIntent validation
- Test: ForwardManager tracks intents
- Test: FORWARD events emitted
- Integration: Forward works (if Docker available)

## Success Criteria

1. Can create local/remote/dynamic forwards?
2. Are forward intents stored for replay?
3. Do FORWARD events include type, ports, and status?

## Status

State: completed
Started: 2026-02-04
Completed: 2026-02-04

## Log

### 2026-02-04: Implementation Complete

**Deliverables completed:**

1. **Forwarding Types** (`src/nbs_ssh/forwarding.py`):
   - `ForwardType` enum: LOCAL, REMOTE, DYNAMIC
   - `ForwardIntent` frozen dataclass with validation
   - Validation ensures required fields per forward type

2. **Forward Manager**:
   - `ForwardManager` class tracks active forwards and intents
   - Methods: `add_intent()`, `remove_intent()`, `clear_intents()`, `forward_local()`, `forward_remote()`, `forward_dynamic()`, `replay_all()`, `close_all()`
   - Intents are immutable and hashable for deduplication

3. **SSHSupervisor Integration**:
   - Added `forward_local()`, `forward_remote()`, `forward_dynamic()` methods
   - Added `forward_manager` property for direct access
   - Integrated ForwardManager lifecycle with connection

4. **Reconnection Replay**:
   - On reconnect, `replay_all()` is called automatically
   - FORWARD events emitted: establishing, established, closed, failed, replay_failed
   - Clean shutdown clears intents and closes all forwards

5. **Tests** (`tests/test_forwarding.py`):
   - 20 unit tests pass
   - 3 integration tests (skip gracefully without Docker)
   - Tests cover: validation, intent tracking, event emission, frozen dataclass behaviour

**Event additions:**
- Added `EventType.FORWARD` to events.py

**Success criteria verified:**
1. ✓ Can create local/remote/dynamic forwards
2. ✓ Forward intents stored for replay
3. ✓ FORWARD events include type, ports, and status
