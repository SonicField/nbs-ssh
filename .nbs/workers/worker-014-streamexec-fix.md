# Worker: Fix StreamExecResult Bug

## Task

Fix the bug in StreamExecResult.__anext__ that causes 7 streaming tests to be skipped.

## Context

- Project: ~/local/nbs-ssh
- Venv: ~/local/nbs-ssh/venv (activate before work)
- Use PYTHONPATH=src for tests

## The Bug

From worker-011 findings:

1. `StreamExecResult.__anext__` returns `wait_task.result()` (which is `SSHCompletedProcess`) directly instead of handling it separately from stdout/stderr results
2. `StreamExecResult.__anext__` raises `StopAsyncIteration` when no data is available but the process is still running, preventing timeout from triggering

Location: `src/nbs_ssh/connection.py` in the `StreamExecResult` class

## Instructions

1. Read `src/nbs_ssh/connection.py` and find the `StreamExecResult` class
2. Understand the `__anext__` method logic
3. Fix the bug: wait_task completion should emit an exit event, not return the SSHCompletedProcess directly
4. Fix the premature StopAsyncIteration - should only stop when process is done AND no more data
5. Run the streaming tests: `PYTHONPATH=src python -m pytest tests/test_streaming.py -v`
6. Unskip the tests that were skipped due to this bug
7. Run full test suite to ensure no regressions
8. Commit with descriptive message

## Success Criteria

1. Do all streaming integration tests pass (not skip)?
2. Does `test_automation_timeout_behaviour` pass?
3. Does the full test suite still pass?

## Status

State: completed
Started: 2026-02-05
Completed: 2026-02-05

## Log

[Worker will append findings here]

### Analysis

The bug was in `StreamExecResult.__anext__` in `src/nbs_ssh/connection.py`:

1. **Bug #1 - wait_task.result() returned directly**: The for loop checking completed tasks
   would iterate over all tasks including `wait_task`. When `wait_task` completed, calling
   `task.result()` returned an `SSHCompletedProcess` object (not None), which would be
   returned directly instead of creating a proper exit StreamEvent.

2. **Bug #2 - Premature StopAsyncIteration**: When no data was available from stdout/stderr
   (both returned None after timeout) but process was still running, the code raised
   `StopAsyncIteration`, ending iteration prematurely.

3. **Bug #3 - CancelledError caught incorrectly**: The original code caught `CancelledError`
   and converted it to `StopAsyncIteration`, which prevented `asyncio.timeout()` from
   working correctly in calling code (like AutomationEngine.expect).

### Fixes Applied

1. Added `if task is not wait_task` check to skip wait_task when iterating completed tasks
2. Changed from raising `StopAsyncIteration` to using a `while True` loop that continues
   waiting when no data is available but process is still running
3. Moved `CancelledError` handling to clean up tasks then re-raise, allowing asyncio.timeout()
   to properly convert it to TimeoutError

### Tests Updated

- Implemented 6 integration tests in `tests/test_streaming.py` that were previously skipped
- Implemented `test_automation_timeout_behaviour` in `tests/test_automation.py` that was
  previously skipped

### Verification

- All 13 streaming tests pass (7 unit tests + 6 integration tests)
- `test_automation_timeout_behaviour` passes
- Full test suite: 253 passed, 1 warning (unrelated subprocess cleanup)
