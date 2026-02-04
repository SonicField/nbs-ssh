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

State: pending
Started:
Completed:

## Log

[Worker will append findings here]
