# Worker: Evidence Bundles (Slice 7)

## Task

Implement evidence bundle export for debugging - a self-contained package of diagnostic information that captures everything needed to understand a connection failure.

## Context

- Project: ~/local/nbs-ssh
- Venv: ~/local/nbs-ssh/venv (activate before work)
- Use PYTHONPATH=src for running tests
- Existing: EventCollector, Transcript, DisconnectReason, JSONL events
- Terminal goal: AI-inspectable SSH client with evidence-first diagnostics

## Deliverables

### 1. Evidence Bundle Structure

Create `src/nbs_ssh/evidence.py`:
- `EvidenceBundle` dataclass containing:
  - events: list of all JSONL events
  - transcript: automation transcript if any
  - algorithms: negotiated SSH algorithms (kex, cipher, mac)
  - disconnect_reason: why connection ended
  - timing: connection timeline
  - host_info: redacted host/port info
  - error_context: structured error details

### 2. Secret Redaction

Implement:
- `redact_secrets()` function that replaces sensitive data
- Passwords, private key contents replaced with "[REDACTED]"
- Preserve structure for debugging while removing secrets

### 3. Bundle Export

Add to evidence.py:
- `to_jsonl()` - export as JSONL file
- `to_dict()` - export as single dict
- `to_file(path)` - write bundle to file
- `from_file(path)` - load bundle from file

### 4. SSHConnection Integration

Update SSHConnection or SSHSupervisor:
- `get_evidence_bundle() -> EvidenceBundle`
- Automatically collects all diagnostic data
- Capture negotiated algorithms from AsyncSSH

### 5. Tests

Create `tests/test_evidence.py`:
- Test: Bundle contains all required fields
- Test: Secrets are properly redacted
- Test: JSONL roundtrip preserves data
- Test: Timing information is accurate

## Success Criteria

1. Can export a complete evidence bundle after connection/failure?
2. Are passwords and key contents redacted?
3. Does the bundle include timing, algorithms, and events?

## Status

State: in_progress
Started: 2026-02-04T14:30:00Z
Completed:

## Log

[Worker will append findings here]
