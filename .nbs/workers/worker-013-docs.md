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

State: completed
Started: 2026-02-04T12:00:00Z
Completed: 2026-02-04T12:30:00Z

## Log

### 2026-02-04

**Exploration**: Explored codebase to understand all public APIs, including:
- SSHConnection and SSHSupervisor classes
- Authentication system (AuthConfig, AuthMethod, helper functions)
- Port forwarding (ForwardManager, ForwardIntent, ForwardHandle)
- Automation engine (expect/respond patterns, transcripts)
- Evidence bundles and JSONL event system
- Error taxonomy (SSHError hierarchy)
- CLI interface

**Documentation Created**:

1. **docs/getting-started.md** (~130 lines)
   - Installation from source
   - Quick start with key and password auth
   - CLI usage examples
   - Streaming output example
   - Error handling basics
   - Links to further documentation

2. **docs/user-guide.md** (~600 lines)
   - SSHConnection: all constructor options, exec(), stream_exec()
   - Authentication: password, key, agent, multiple methods with fallback
   - SSHSupervisor: states, retry policy, wait_connected()
   - Port forwarding: local, remote, dynamic with auto-replay
   - Automation: expect/respond patterns, sequences, transcripts
   - Evidence bundles: capturing, contents, export formats, redaction
   - Event system: types, collection, JSONL logging
   - Error handling: full exception hierarchy with examples
   - Cross-platform: key discovery, path utilities

3. **docs/debugging.md** (~350 lines)
   - Enabling JSONL event logging (code and CLI)
   - Reading event logs with jq and programmatically
   - Event types reference with JSON examples
   - Evidence bundle analysis
   - Common issues: ConnectionRefused, Timeout, AuthFailed, KeyLoadError, HostKeyMismatch, NoMutualKex, AgentError
   - Bug reporting checklist
   - Debug checklist

4. **docs/api-reference.md** (~700 lines)
   - All public classes with full constructor parameters
   - Method signatures with parameter tables
   - Example usage for each major feature
   - Complete module import list

**Verification**:
- Documentation verified against actual code implementation
- Examples based on real API patterns found in codebase
- All features from task requirements covered
