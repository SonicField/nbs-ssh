# Worker: Automated Interaction / Expect-Respond (Slice 6)

## Task

Implement an expect/respond engine for automated interaction with remote commands, producing deterministic transcripts.

## Context

- Project: ~/local/nbs-ssh
- Venv: ~/local/nbs-ssh/venv (activate before work)
- Use PYTHONPATH=src for running tests
- Existing: StreamExecResult for streaming output
- NOT a terminal emulator - pattern matching on output
- Terminal goal: AI-inspectable SSH client with automated interaction

## Deliverables

### 1. Expect Pattern Types

Create `src/nbs_ssh/automation.py`:
- `ExpectPattern`: regex or literal string to match
- `ExpectTimeout`: timeout for pattern match
- `ExpectResult`: what matched, captured groups, timing

### 2. Respond Actions

Add to automation.py:
- `RespondAction`: what to send when pattern matches
- `RespondDelay`: optional delay before sending
- `ExpectRespond`: combines pattern + action

### 3. Automation Engine

Create `AutomationEngine` class:
- `expect(pattern, timeout=30) -> ExpectResult`
- `send(text)`
- `expect_respond(pattern, response, timeout=30)`
- Builds deterministic transcript of all interactions

### 4. Transcript Output

Implement:
- `Transcript` class with ordered list of interactions
- Each entry: timestamp, type (expect/send), content, duration
- `to_jsonl()` method for serialisation
- Transcript is reproducible evidence

### 5. Tests

Create `tests/test_automation.py`:
- Test: ExpectPattern matching (regex, literal)
- Test: Transcript records all interactions
- Test: Timeout handling
- Test: JSONL serialisation of transcript

## Success Criteria

1. Can match patterns in command output?
2. Can send responses and record them?
3. Is the transcript deterministic and serialisable?

## Engineering Standards

- This is NOT a terminal emulator
- No PTY allocation needed - works with stream_exec output
- Transcript must be reproducible evidence

## Status

State: completed
Started: 2026-02-04T16:45:00Z
Completed: 2026-02-04T17:00:00Z

## Log

### 2026-02-04: Implementation Complete

**Files created:**
- `src/nbs_ssh/automation.py` - Full expect/respond automation engine

**Implementation summary:**

1. **Expect Pattern Types** (Deliverable 1):
   - `PatternType` enum: LITERAL, REGEX
   - `ExpectPattern`: Supports literal and regex matching with validation
   - `ExpectTimeout`: Configurable timeout with on_timeout behaviour
   - `ExpectResult`: Match details, captured groups, timing, timeout state

2. **Respond Actions** (Deliverable 2):
   - `RespondAction`: Text to send with optional newline
   - `RespondDelay`: Configurable delay before responding
   - `ExpectRespond`: Combines pattern + action for automated sequences

3. **Automation Engine** (Deliverable 3):
   - `AutomationEngine` class with:
     - `expect(pattern, timeout=30)` - Wait for pattern in output
     - `send(text)` - Send to stdin
     - `expect_respond(pattern, response)` - Combined operation
     - `run_sequence(steps)` - Run multiple expect/respond pairs
   - Buffers output from StreamEvent async iterator
   - Records all interactions in transcript

4. **Transcript Output** (Deliverable 4):
   - `InteractionType` enum: EXPECT, SEND, OUTPUT, TIMEOUT
   - `TranscriptEntry`: timestamp, type, content, duration, metadata
   - `Transcript` class with:
     - `add_expect()`, `add_send()`, `add_output()` methods
     - `to_jsonl()` for JSONL serialisation
     - `to_dict()` for full transcript metadata
   - Deterministic, reproducible evidence

5. **Tests** (Deliverable 5):
   - `tests/test_automation.py` with 42 tests:
     - 8 tests for ExpectPattern (literal, regex, validation)
     - 4 tests for ExpectTimeout
     - 3 tests for ExpectResult
     - 2 tests for RespondAction
     - 2 tests for RespondDelay
     - 1 test for ExpectRespond
     - 9 tests for Transcript and TranscriptEntry
     - 9 tests for AutomationEngine unit tests
     - 4 integration tests (require Docker)

**Test results:** 38 passed, 4 skipped (Docker-dependent integration tests)

**Success criteria verification:**
1. ✅ Can match patterns in command output - both literal and regex
2. ✅ Can send responses and record them in transcript
3. ✅ Transcript is deterministic and serialisable to JSONL

**Exports added to `__init__.py`:**
- AutomationEngine, ExpectPattern, ExpectRespond, ExpectResult
- ExpectTimeout, ExpectTimeoutError, InteractionType, PatternType
- RespondAction, RespondDelay, Transcript, TranscriptEntry
