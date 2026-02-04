# Worker: CLI Interface

## Task

Check if nbs-ssh can be used as a command-line SSH client. If not, implement a CLI interface.

## Context

- Project: ~/local/nbs-ssh
- Venv: ~/local/nbs-ssh/venv (activate before work)
- Use PYTHONPATH=src for tests
- Currently the library is Python API only
- User expectation: should be usable like `python -m nbs_ssh user@host "command"`

## Instructions

1. Check if __main__.py exists in src/nbs_ssh/
2. If not, implement CLI interface with:
   - `python -m nbs_ssh user@host command` - basic exec
   - `python -m nbs_ssh -p 2222 user@host command` - custom port
   - `python -m nbs_ssh -i keyfile user@host command` - key auth
   - `python -m nbs_ssh --password user@host command` - prompt for password
   - `python -m nbs_ssh --events user@host command` - show JSONL events
   - `python -m nbs_ssh --help` - usage
3. Use argparse for argument parsing
4. Return exit code from remote command
5. Write tests in tests/test_cli.py
6. Commit when complete

## Success Criteria

1. Can run `python -m nbs_ssh --help` and see usage?
2. Can run `python -m nbs_ssh user@host "echo hello"` (against test server)?
3. Does exit code propagate correctly?
4. Are CLI tests passing?

## Status

State: completed
Started: 2026-02-04
Completed: 2026-02-04

## Log

### 2026-02-04

1. Checked for existing __main__.py - none found
2. Implemented CLI in `src/nbs_ssh/__main__.py` with:
   - `python -m nbs_ssh user@host command` - basic exec with password prompt
   - `python -m nbs_ssh -p 2222 user@host command` - custom port
   - `python -m nbs_ssh -i keyfile user@host command` - key authentication
   - `python -m nbs_ssh --password user@host command` - explicit password prompt
   - `python -m nbs_ssh --events user@host command` - JSONL events to stderr
   - `python -m nbs_ssh --no-host-check user@host command` - disable host key verification
   - `python -m nbs_ssh --timeout 60 user@host command` - custom timeout
   - `python -m nbs_ssh -l user host command` - alternative login syntax
   - `python -m nbs_ssh --help` - usage documentation
   - `python -m nbs_ssh --version` - version info
3. Exit code propagates from remote command
4. Created tests in `tests/test_cli.py`:
   - 9 argument parsing tests
   - 2 help/version output tests
   - 4 integration tests (exec, exit code, events, connection error)
5. All 15 CLI tests pass

### Success Criteria Verification

1. `python -m nbs_ssh --help` - YES, shows usage
2. `python -m nbs_ssh user@host "echo hello"` - YES, works against MockSSHServer
3. Exit code propagation - YES, tested with exit 42
4. CLI tests passing - YES, 15/15 pass
