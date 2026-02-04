# nbs-ssh Project Plan

## Terminal Goal

Build an AI-inspectable SSH client library using AsyncSSH that provides exec, streaming exec, port forwarding, automated interaction (expect/respond), supervisor-managed reconnection, and evidence-first diagnostics (JSONL event logs, failure bundles) - all with falsifiable tests against a Docker-based chaos testing rig.

## Architecture Overview

**Core Principle**: Not a terminal emulator. A library + CLI that is AI-inspectable.

### Components

1. **Event System** - JSONL structured logging for all operations
2. **Connection Manager** - AsyncSSH wrapper with lifecycle management
3. **Auth Module** - Password, keyfile, agent authentication
4. **Exec Engine** - exec() and stream_exec() with cancellation
5. **Keepalive/Watchdog** - Freeze detection using AsyncSSH keepalive
6. **Supervisor FSM** - State machine for connection lifecycle
7. **Port Forwarding** - Local/remote/dynamic with replay on reconnect
8. **Automation Engine** - Expect/respond with deterministic transcripts
9. **Evidence Bundle** - Diagnostic export for debugging
10. **Cross-Platform** - Windows path abstractions

### Dependencies

- asyncssh (protocol engine)
- Python 3.12+

## Slice Plan (from issue)

| Slice | Name | Deliverable |
|-------|------|-------------|
| 0 | Hello SSH | Connect, host key validation, run `echo hello`, JSONL events |
| 1 | Auth Matrix | Password + keyfile + agent auth, failure taxonomy |
| 2 | Exec + Streaming | exec() returns result, stream_exec() yields events + cancellation |
| 3 | Keepalive + Freeze | AsyncSSH keepalive config, progress watchdog |
| 4 | Supervisor + Reconnect | State machine FSM, exponential backoff, retry policies |
| 5 | Port Forwards | Local/remote/dynamic, replay intents on reconnect |
| 6 | Automated Interaction | Expect/respond engine, deterministic transcripts |
| 7 | Evidence Bundles | Export: events, algos, disconnect reason, timing, redacted secrets |
| 8 | Windows Hardening | Path abstractions, key discovery, CI green on Windows |

## Testing Infrastructure (Slice -1)

Before any slices, we need:
- Docker-based OpenSSH server for tests
- Chaos proxy for fault injection (packet drop, latency, blackhole)
- pytest fixtures for SSH connections
- JSONL event assertion helpers

## Worker Phases

### Phase 0: Foundation (Slices -1, 0)
- Worker: Set up test infrastructure + basic connection

### Phase 1: Core Functionality (Slices 1, 2, 3)
- Worker: Auth matrix implementation
- Worker: Exec engine with streaming
- Worker: Keepalive and freeze detection

### Phase 2: Resilience (Slices 4, 5)
- Worker: Supervisor state machine + reconnection
- Worker: Port forwarding with replay

### Phase 3: Automation (Slices 6, 7)
- Worker: Expect/respond automation engine
- Worker: Evidence bundle export

### Phase 4: Polish (Slice 8)
- Worker: Windows hardening

## Success Criteria

Each slice ships with:
1. Tests that try to falsify the implementation
2. JSONL event evidence of correct behaviour
3. Documentation of what was learned

## Venv Setup

```bash
source ~/local/nbs-ssh/venv/bin/activate
# AsyncSSH installation requires Alex's help (no pip on this machine)
```

