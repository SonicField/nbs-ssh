# Worker: Streaming Exec (Slice 2)

## Task

Implement streaming command execution with cancellation support. The current `exec()` method blocks until completion - we need `stream_exec()` that yields structured output events as they arrive.

## Context

- Project: ~/local/nbs-ssh
- Venv: ~/local/nbs-ssh/venv (activate before work)
- Use PYTHONPATH=src for running tests
- Existing: SSHConnection.exec() returns full ExecResult
- Terminal goal: AI-inspectable SSH client with evidence-first diagnostics

## Deliverables

### 1. StreamExecResult

Add to `src/nbs_ssh/connection.py` or create `src/nbs_ssh/streaming.py`:
- `StreamEvent` dataclass: timestamp, stream (stdout/stderr), data, is_eof
- `StreamExecResult`: async iterator yielding StreamEvents
- Support cancellation via `cancel()` method

### 2. stream_exec() Method

Add to `SSHConnection`:
- `async def stream_exec(command) -> StreamExecResult`
- Yields events as output arrives (not buffered)
- Emits EXEC events with streaming=True
- Handles cancellation gracefully (sends signal, waits for cleanup)

### 3. Exec Event Enhancement

Update EXEC events to include:
- `streaming`: bool (true for stream_exec)
- `bytes_stdout`, `bytes_stderr`: running totals
- `cancelled`: bool if cancelled before completion

### 4. Streaming Tests

Create `tests/test_streaming.py`:
- Test: stream_exec yields events in order
- Test: cancellation stops the stream
- Test: EXEC events include streaming metadata
- Test: stdout/stderr interleaving preserved

## Success Criteria

1. Can `async for event in conn.stream_exec("command")` and receive events as they arrive?
2. Can cancel a running stream_exec and have it terminate gracefully?
3. Do EXEC events distinguish between exec() and stream_exec()?

## Engineering Standards

- Write tests FIRST
- stream_exec must not buffer (true streaming)
- Cancellation must be clean (no zombie processes)

## Status

State: completed
Started: 2026-02-04
Completed: 2026-02-04

## Log

### 2026-02-04: Implementation Complete

**Deliverables completed:**

1. **StreamEvent dataclass** (`connection.py:59-79`)
   - Fields: timestamp, stream ('stdout'/'stderr'/'exit'), data, exit_code
   - Validation in __post_init__ for valid stream types and positive timestamps

2. **StreamExecResult class** (`connection.py:82-228`)
   - Async iterator yielding StreamEvents as output arrives
   - `cancel()` method sends SIGTERM, waits 2s, then SIGKILL if needed
   - Tracks bytes_stdout and bytes_stderr counters
   - Emits EXEC event on completion with streaming=True, byte counts, cancelled flag

3. **stream_exec() method** (`connection.py:550-578`)
   - Returns _StreamExecResultFactory (lazy process creation)
   - Usage: `async for event in conn.stream_exec("cmd")`

4. **EXEC event enhancement**
   - streaming: bool - True for stream_exec, not set for regular exec
   - bytes_stdout, bytes_stderr: running totals
   - cancelled: bool - True if cancelled before completion

5. **Tests** (`tests/test_streaming.py`)
   - 7 unit tests (no Docker required) - all pass
   - 6 integration tests (require Docker) - skipped in this environment

**Testing notes:**
- Docker not available in this environment
- Unit tests validate StreamEvent construction and cancel() behavior
- Integration tests exist for full end-to-end validation with Docker SSH server

**Exports updated:**
- `__init__.py` exports StreamEvent and StreamExecResult

---

## Supervisor Actions (on completion)

After reading this completed task, supervisor must:
1. Capture 3Ws in supervisor.md
2. Increment workers_since_check
3. If workers_since_check >= 3, run self-check
