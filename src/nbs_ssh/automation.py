"""
Expect/respond automation engine for SSH command interaction.

Provides pattern matching on command output with automated responses,
producing deterministic transcripts for AI inspection.

Key concepts:
- ExpectPattern: What to look for in output (regex or literal)
- RespondAction: What to send when pattern matches
- Transcript: Complete record of all interactions

This is NOT a terminal emulator - it performs pattern matching on
stream_exec output without PTY allocation.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import AsyncIterator, Pattern


class PatternType(str, Enum):
    """Type of pattern matching to use."""
    LITERAL = "literal"
    REGEX = "regex"


@dataclass(frozen=True)
class ExpectPattern:
    """
    Pattern to match in command output.

    Supports both literal string matching and regex patterns.

    Attributes:
        pattern: The pattern string to match
        pattern_type: LITERAL for exact substring, REGEX for regex
        name: Optional name for the pattern (for transcript clarity)
    """
    pattern: str
    pattern_type: PatternType = PatternType.LITERAL
    name: str | None = None

    def __post_init__(self) -> None:
        """Validate pattern on creation."""
        assert self.pattern, "Pattern must not be empty"
        if self.pattern_type == PatternType.REGEX:
            # Validate regex compiles
            try:
                re.compile(self.pattern)
            except re.error as e:
                raise AssertionError(f"Invalid regex pattern: {e}") from e

    @property
    def compiled(self) -> Pattern[str]:
        """Return compiled regex for matching."""
        if self.pattern_type == PatternType.LITERAL:
            return re.compile(re.escape(self.pattern))
        return re.compile(self.pattern)

    def match(self, text: str) -> re.Match[str] | None:
        """
        Try to match this pattern against text.

        Args:
            text: The text to search in

        Returns:
            Match object if found, None otherwise
        """
        return self.compiled.search(text)


@dataclass(frozen=True)
class ExpectTimeout:
    """
    Configuration for pattern match timeout.

    Attributes:
        seconds: Maximum time to wait for pattern match
        on_timeout: What to do when timeout occurs ('raise' or 'continue')
    """
    seconds: float = 30.0
    on_timeout: str = "raise"

    def __post_init__(self) -> None:
        """Validate timeout configuration."""
        assert self.seconds > 0, f"Timeout must be positive, got {self.seconds}"
        assert self.on_timeout in ("raise", "continue"), \
            f"on_timeout must be 'raise' or 'continue', got '{self.on_timeout}'"


@dataclass
class ExpectResult:
    """
    Result of an expect operation.

    Attributes:
        matched: Whether the pattern was matched
        pattern: The pattern that was matched (or attempted)
        match_text: The text that matched (if matched)
        groups: Captured groups from regex (if any)
        buffer: Full buffer at time of match
        duration_ms: Time taken to match
        timed_out: Whether the operation timed out
    """
    matched: bool
    pattern: ExpectPattern
    match_text: str = ""
    groups: tuple[str, ...] = field(default_factory=tuple)
    buffer: str = ""
    duration_ms: float = 0.0
    timed_out: bool = False

    def to_dict(self) -> dict:
        """Convert to dictionary for serialisation."""
        return {
            "matched": self.matched,
            "pattern": self.pattern.pattern,
            "pattern_type": self.pattern.pattern_type.value,
            "pattern_name": self.pattern.name,
            "match_text": self.match_text,
            "groups": list(self.groups),
            "duration_ms": self.duration_ms,
            "timed_out": self.timed_out,
        }


@dataclass(frozen=True)
class RespondAction:
    """
    Action to send in response to a pattern match.

    Attributes:
        text: The text to send
        add_newline: Whether to append newline (default True)
    """
    text: str
    add_newline: bool = True

    @property
    def full_text(self) -> str:
        """Return text with optional newline."""
        if self.add_newline:
            return self.text + "\n"
        return self.text


@dataclass(frozen=True)
class RespondDelay:
    """
    Delay before sending a response.

    Attributes:
        seconds: Time to wait before responding
    """
    seconds: float = 0.0

    def __post_init__(self) -> None:
        """Validate delay configuration."""
        assert self.seconds >= 0, f"Delay must be non-negative, got {self.seconds}"


@dataclass(frozen=True)
class ExpectRespond:
    """
    Combined expect pattern with response action.

    Used for defining automated interaction sequences.

    Attributes:
        pattern: Pattern to match
        response: Action to take when matched
        delay: Optional delay before responding
        timeout: Timeout configuration
    """
    pattern: ExpectPattern
    response: RespondAction
    delay: RespondDelay = field(default_factory=RespondDelay)
    timeout: ExpectTimeout = field(default_factory=ExpectTimeout)


class InteractionType(str, Enum):
    """Type of interaction in transcript."""
    EXPECT = "expect"
    SEND = "send"
    OUTPUT = "output"
    TIMEOUT = "timeout"


@dataclass
class TranscriptEntry:
    """
    Single entry in an automation transcript.

    Attributes:
        timestamp_ms: Unix timestamp in milliseconds
        interaction_type: Type of interaction
        content: Content of the interaction
        duration_ms: Duration of the operation (for expect)
        metadata: Additional metadata
    """
    timestamp_ms: float
    interaction_type: InteractionType
    content: str
    duration_ms: float = 0.0
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary for serialisation."""
        return {
            "timestamp_ms": self.timestamp_ms,
            "type": self.interaction_type.value,
            "content": self.content,
            "duration_ms": self.duration_ms,
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), default=str)


class Transcript:
    """
    Ordered record of all automation interactions.

    Provides reproducible evidence of what happened during
    automated command interaction.

    Thread-safe for async usage.
    """

    def __init__(self) -> None:
        self._entries: list[TranscriptEntry] = []
        self._start_ms: float = time.time() * 1000

    def add_expect(
        self,
        result: ExpectResult,
    ) -> TranscriptEntry:
        """
        Record an expect operation.

        Args:
            result: The ExpectResult from the expect operation

        Returns:
            The created TranscriptEntry
        """
        entry = TranscriptEntry(
            timestamp_ms=time.time() * 1000,
            interaction_type=InteractionType.TIMEOUT if result.timed_out else InteractionType.EXPECT,
            content=result.match_text if result.matched else result.pattern.pattern,
            duration_ms=result.duration_ms,
            metadata=result.to_dict(),
        )
        self._entries.append(entry)
        return entry

    def add_send(
        self,
        text: str,
        metadata: dict | None = None,
    ) -> TranscriptEntry:
        """
        Record a send operation.

        Args:
            text: The text that was sent
            metadata: Optional additional metadata

        Returns:
            The created TranscriptEntry
        """
        entry = TranscriptEntry(
            timestamp_ms=time.time() * 1000,
            interaction_type=InteractionType.SEND,
            content=text,
            metadata=metadata or {},
        )
        self._entries.append(entry)
        return entry

    def add_output(
        self,
        text: str,
        stream: str = "stdout",
    ) -> TranscriptEntry:
        """
        Record raw output received.

        Args:
            text: The output text
            stream: Which stream (stdout/stderr)

        Returns:
            The created TranscriptEntry
        """
        entry = TranscriptEntry(
            timestamp_ms=time.time() * 1000,
            interaction_type=InteractionType.OUTPUT,
            content=text,
            metadata={"stream": stream},
        )
        self._entries.append(entry)
        return entry

    @property
    def entries(self) -> list[TranscriptEntry]:
        """Return list of entries (immutable view)."""
        return list(self._entries)

    @property
    def duration_ms(self) -> float:
        """Total duration from start to now."""
        return (time.time() * 1000) - self._start_ms

    def to_jsonl(self) -> str:
        """
        Serialise transcript to JSONL format.

        Each entry is a single line of JSON.

        Returns:
            JSONL string with one entry per line
        """
        lines = [entry.to_json() for entry in self._entries]
        return "\n".join(lines)

    def to_dict(self) -> dict:
        """
        Convert transcript to dictionary.

        Returns:
            Dictionary with metadata and entries
        """
        return {
            "start_ms": self._start_ms,
            "duration_ms": self.duration_ms,
            "entry_count": len(self._entries),
            "entries": [e.to_dict() for e in self._entries],
        }

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self):
        return iter(self._entries)


class ExpectTimeoutError(Exception):
    """Raised when an expect operation times out."""

    def __init__(
        self,
        pattern: ExpectPattern,
        timeout_seconds: float,
        buffer: str,
    ) -> None:
        self.pattern = pattern
        self.timeout_seconds = timeout_seconds
        self.buffer = buffer
        super().__init__(
            f"Timeout after {timeout_seconds}s waiting for pattern: {pattern.pattern!r}"
        )


class AutomationEngine:
    """
    Engine for automated expect/respond interactions.

    Works with an async iterator of StreamEvent objects from stream_exec().
    Buffers output and matches patterns, sending responses via stdin.

    Usage:
        stream = conn.stream_exec("interactive_command")
        engine = AutomationEngine(stream, process.stdin)

        result = await engine.expect(ExpectPattern("Password:"))
        await engine.send("mypassword")

        transcript = engine.transcript
    """

    def __init__(
        self,
        stream: AsyncIterator,
        stdin_write=None,
    ) -> None:
        """
        Initialise automation engine.

        Args:
            stream: Async iterator yielding StreamEvent objects
            stdin_write: Callable to write to stdin (optional for expect-only use)
        """
        self._stream = stream
        self._stdin_write = stdin_write
        self._buffer: str = ""
        self._transcript = Transcript()
        self._stream_exhausted = False

    @property
    def transcript(self) -> Transcript:
        """Return the interaction transcript."""
        return self._transcript

    @property
    def buffer(self) -> str:
        """Return current output buffer."""
        return self._buffer

    async def expect(
        self,
        pattern: ExpectPattern | str,
        timeout: float = 30.0,
    ) -> ExpectResult:
        """
        Wait for a pattern to appear in output.

        Args:
            pattern: Pattern to match (string converted to literal pattern)
            timeout: Maximum time to wait in seconds

        Returns:
            ExpectResult with match details

        Raises:
            ExpectTimeoutError: If pattern not matched within timeout
        """
        if isinstance(pattern, str):
            pattern = ExpectPattern(pattern)

        start_ms = time.time() * 1000

        # Check buffer first
        match = pattern.match(self._buffer)
        if match:
            duration_ms = (time.time() * 1000) - start_ms
            result = ExpectResult(
                matched=True,
                pattern=pattern,
                match_text=match.group(0),
                groups=match.groups(),
                buffer=self._buffer,
                duration_ms=duration_ms,
            )
            self._transcript.add_expect(result)
            return result

        # Read from stream until match or timeout
        try:
            async with asyncio.timeout(timeout):
                while not self._stream_exhausted:
                    try:
                        event = await self._stream.__anext__()
                    except StopAsyncIteration:
                        self._stream_exhausted = True
                        break

                    # Buffer output events
                    if hasattr(event, 'stream') and event.stream in ("stdout", "stderr"):
                        self._buffer += event.data
                        self._transcript.add_output(event.data, event.stream)

                        # Check for match
                        match = pattern.match(self._buffer)
                        if match:
                            duration_ms = (time.time() * 1000) - start_ms
                            result = ExpectResult(
                                matched=True,
                                pattern=pattern,
                                match_text=match.group(0),
                                groups=match.groups(),
                                buffer=self._buffer,
                                duration_ms=duration_ms,
                            )
                            self._transcript.add_expect(result)
                            return result

                    # Exit event means no more output coming
                    if hasattr(event, 'stream') and event.stream == "exit":
                        self._stream_exhausted = True
                        break

        except asyncio.TimeoutError:
            duration_ms = (time.time() * 1000) - start_ms
            result = ExpectResult(
                matched=False,
                pattern=pattern,
                buffer=self._buffer,
                duration_ms=duration_ms,
                timed_out=True,
            )
            self._transcript.add_expect(result)
            raise ExpectTimeoutError(pattern, timeout, self._buffer)

        # Stream exhausted without match
        duration_ms = (time.time() * 1000) - start_ms
        result = ExpectResult(
            matched=False,
            pattern=pattern,
            buffer=self._buffer,
            duration_ms=duration_ms,
            timed_out=False,
        )
        self._transcript.add_expect(result)
        return result

    async def send(self, text: str, add_newline: bool = True) -> None:
        """
        Send text to stdin.

        Args:
            text: Text to send
            add_newline: Whether to append newline

        Raises:
            AssertionError: If stdin_write not configured
        """
        assert self._stdin_write is not None, \
            "stdin_write not configured - cannot send"

        full_text = text + "\n" if add_newline else text

        if asyncio.iscoroutinefunction(self._stdin_write):
            await self._stdin_write(full_text)
        else:
            self._stdin_write(full_text)

        self._transcript.add_send(full_text)

    async def expect_respond(
        self,
        pattern: ExpectPattern | str,
        response: str,
        timeout: float = 30.0,
        delay: float = 0.0,
    ) -> ExpectResult:
        """
        Wait for pattern then send response.

        Convenience method combining expect() and send().

        Args:
            pattern: Pattern to wait for
            response: Text to send when matched
            timeout: Maximum time to wait for pattern
            delay: Delay before sending response

        Returns:
            ExpectResult from the expect operation
        """
        result = await self.expect(pattern, timeout)

        if result.matched:
            if delay > 0:
                await asyncio.sleep(delay)
            await self.send(response)

        return result

    async def run_sequence(
        self,
        sequence: list[ExpectRespond],
    ) -> list[ExpectResult]:
        """
        Run a sequence of expect/respond operations.

        Args:
            sequence: List of ExpectRespond objects

        Returns:
            List of ExpectResult objects for each step
        """
        results = []
        for step in sequence:
            result = await self.expect(step.pattern, step.timeout.seconds)
            results.append(result)

            if result.matched:
                if step.delay.seconds > 0:
                    await asyncio.sleep(step.delay.seconds)
                await self.send(step.response.text, step.response.add_newline)

        return results
