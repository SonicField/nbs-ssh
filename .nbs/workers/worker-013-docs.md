# Worker: Documentation

## Task

Write comprehensive user documentation in a docs/ directory.

## Context

- Project: ~/local/nbs-ssh
- Venv: ~/local/nbs-ssh/venv (activate before work)
- Library provides: SSHConnection, SSHSupervisor, streaming exec, port forwarding, automation (expect/respond), evidence bundles
- CLI interface should exist (from worker-012)
- Target audience: developers using this as SSH client library

## Instructions

Create docs/ directory with:

### 1. docs/getting-started.md
- Installation (pip install from source for now)
- Quick start: connect and run a command
- CLI usage if available
- First streaming example
- Where to go next

### 2. docs/user-guide.md
Full documentation covering:
- SSHConnection: all constructor options, exec(), stream_exec()
- Authentication: password, key, agent
- SSHSupervisor: reconnection, state machine, retry policy
- Port forwarding: local, remote, dynamic
- Automation: expect/respond patterns, transcripts
- Evidence bundles: what they contain, how to export
- Event system: JSONL logging, event types
- Error handling: error taxonomy, what each exception means
- Cross-platform: Windows path handling, agent detection

### 3. docs/debugging.md
- How to enable JSONL event logging
- Reading event logs
- Evidence bundle analysis
- Common issues and solutions
- How to report bugs (what info to include)

### 4. docs/api-reference.md
- All public classes and functions
- Constructor parameters
- Method signatures
- Example usage for each

## Success Criteria

1. Can a new user get started in 5 minutes using getting-started.md?
2. Does user-guide.md cover all features?
3. Does debugging.md explain how to diagnose issues?
4. Is the documentation accurate (verified against code)?

## Status

State: pending
Started:
Completed:

## Log

[Worker will append findings here]
