# Worker: Interactive Shell Mode

## Task

Add interactive shell mode so `python -m nbs_ssh user@host` (no command) opens a PTY session where the user can type commands interactively, like regular `ssh`.

## Context

- Project: ~/local/nbs-ssh
- Venv: ~/local/nbs-ssh/venv (activate before work)
- Use PYTHONPATH=src for tests
- CLI exists in src/nbs_ssh/__main__.py
- Currently CLI requires a command argument - no interactive mode

## The Gap

Running `ssh user@host` gives you an interactive shell with PTY. Running `python -m nbs_ssh user@host` should do the same, but currently requires a command argument.

## Requirements

1. When no command is given, open interactive shell session
2. Request PTY from remote server
3. Put local terminal in raw mode (pass keypresses directly)
4. Forward stdin to remote, remote stdout/stderr to local terminal
5. Handle terminal resize (SIGWINCH)
6. Restore terminal on exit (even on crash)
7. Still emit JSONL events if --events is specified
8. Exit with remote shell's exit code

## Instructions

1. Read src/nbs_ssh/__main__.py to understand current CLI
2. Read asyncssh documentation on interactive sessions and PTY
3. Add SSHConnection.shell() method or similar for interactive sessions
4. Update CLI to detect when no command given → call shell mode
5. Implement terminal raw mode (tty.setraw or similar)
6. Handle SIGWINCH for terminal resize
7. Use try/finally to restore terminal state
8. Write tests (may need to use pty-session or mock)
9. Test manually: `PYTHONPATH=src python -m nbs_ssh test@localhost` against MockSSHServer
10. Commit with descriptive message

## Success Criteria

1. Can run `python -m nbs_ssh user@host` and get interactive shell?
2. Can type commands and see output in real-time?
3. Does Ctrl+C, Ctrl+D work correctly?
4. Is terminal restored properly on exit?
5. Does --events still work (logs session events)?

## Status

State: completed
Started: 2026-02-05
Completed: 2026-02-05

## Log

[Worker will append findings here]

### Implementation Summary

1. **Added SHELL event type** to `events.py` for tracking interactive shell sessions

2. **Added `SSHConnection.shell()` method** in `connection.py`:
   - Requests PTY from remote server with current terminal size and type
   - Puts local terminal in raw mode using `tty.setraw()`
   - Forwards stdin to remote, remote stdout to local terminal
   - Handles SIGWINCH for terminal resize events
   - Uses try/finally to guarantee terminal state restoration
   - Emits SHELL events with status and timing information

3. **Updated CLI** in `__main__.py`:
   - When no command is given, calls `conn.shell()` for interactive mode
   - Falls back gracefully with informative message when stdin is not a TTY
   - Updated module docstring to document interactive mode usage

4. **Updated MockSSHServer** in `testing/mock_server.py`:
   - Added `_handle_shell_session()` to handle shell requests (command=None)
   - Simple mock shell that echoes input and handles basic commands
   - Supports real shell execution when `execute_commands=True`
   - Emits SERVER_SHELL_START, SERVER_SHELL_PTY, SERVER_SHELL_END events

5. **Added test suite** `tests/test_shell.py`:
   - Tests shell requires TTY (raises RuntimeError otherwise)
   - Tests shell emits events correctly
   - Tests CLI behaviour with/without command
   - Tests MockSSHServer shell support

### Files Modified
- `src/nbs_ssh/events.py` - Added SHELL event type
- `src/nbs_ssh/connection.py` - Added shell() method and imports
- `src/nbs_ssh/__main__.py` - Updated CLI for interactive mode
- `src/nbs_ssh/testing/mock_server.py` - Added shell session handling
- `tests/test_shell.py` - New test file for shell functionality

### Test Results
All 247 tests pass (6 new shell tests + 241 existing).
