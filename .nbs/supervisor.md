# Supervisor: nbs-ssh

## Terminal Goal

Build an AI-inspectable SSH client library using AsyncSSH that provides exec, streaming exec, port forwarding, automated interaction (expect/respond), supervisor-managed reconnection, and evidence-first diagnostics (JSONL event logs, failure bundles) - all with falsifiable tests against a Docker-based chaos testing rig.

## Current State

Phase: IMPLEMENTATION
Active workers: none
Workers since last check: 2

## Progress

- [2026-02-04] Project structure created
- [2026-02-04] Dependencies installed: asyncssh-2.22.0, pytest, pytest-asyncio, hypothesis
- [2026-02-04] Worker-001 spawned: Foundation (test infrastructure + Hello SSH)
- [2026-02-04] Worker-001 completed: All 5 deliverables done, tests pass/skip gracefully
- [2026-02-04] Worker-002 completed: Auth Matrix verified + bug fix (ERROR event emission)
- [2026-02-04] Total: 1929 lines of code, 29 tests passing

## Decisions Log

See `.nbs/decisions.log`

---

## 3Ws + Self-Check Log

### Worker: worker-001-foundation - 2026-02-04

**What went well:**
- Worker followed engineering standards correctly (tests FIRST)
- Created comprehensive event system with assertions
- Graceful Docker skip pattern works well
- Worker documented learnings in task log
- Completed in ~5 minutes

**What didn't work:**
- pip install failed due to proxy restrictions (worker adapted by using PYTHONPATH)
- Docker unavailable, so integration tests couldn't fully run
- Multiple permission prompts needed for bash commands

**What we can do better:**
- Pre-approve common bash patterns (pytest, python -c) in future worker tasks
- Note Docker availability in task context
- Include proxy setup instructions for pip commands

### Worker: worker-002-auth-matrix - 2026-02-04

**What went well:**
- Found implementation already existed (from parallel session or prior work)
- Quickly identified and fixed missing ERROR event emission bug
- All 29 tests pass (28 auth + 1 hello_ssh, 4 skipped)
- Proper verification of success criteria

**What didn't work:**
- Session confusion initially (picked up wrong project context)
- Had to use unique session names to avoid conflicts

**What we can do better:**
- Always use unique session names (e.g., project-prefixed)
- Consider that previous sessions may have completed work
- Verify existing state before starting fresh implementation

<!--
Template for each entry:

### Worker: [name] - [date]

**What went well:**
-

**What didn't work:**
-

**What we can do better:**
-

**Self-check** (if workers_since_check >= 3):
- [ ] Am I still pursuing terminal goal?
- [ ] Am I delegating vs doing tactical work myself?
- [ ] Have I captured learnings that should improve future tasks?
- [ ] Should I escalate anything to human?

[Reset workers_since_check to 0 after self-check]
-->

---
