"""
Event system for nbs-ssh.

Provides structured JSONL event logging for AI-inspectable diagnostics.

Event types:
- CONNECT: SSH connection initiated/established
- AUTH: Authentication attempted/succeeded/failed
- EXEC: Command execution started/completed
- DISCONNECT: Connection closed
- ERROR: Any error condition

All events include:
- timestamp: Unix timestamp in milliseconds
- event_type: One of the above types
- data: Event-specific structured data
"""
from __future__ import annotations

import json
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import IO, Any, Iterator


class EventType(str, Enum):
    """SSH event types for structured logging."""
    CONNECT = "CONNECT"
    AUTH = "AUTH"
    EXEC = "EXEC"
    DISCONNECT = "DISCONNECT"
    ERROR = "ERROR"


@dataclass
class Event:
    """
    Base event for SSH operations.

    All events are immutable records with:
    - event_type: The category of event
    - timestamp: When the event occurred (Unix ms)
    - data: Event-specific structured data
    """
    event_type: str
    timestamp: float = field(default_factory=lambda: time.time() * 1000)
    data: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate event on creation."""
        # Precondition: event_type must be valid
        valid_types = {e.value for e in EventType}
        assert self.event_type in valid_types, \
            f"Invalid event_type '{self.event_type}'. Must be one of: {valid_types}"

        # Precondition: timestamp must be positive
        assert self.timestamp > 0, \
            f"Timestamp must be positive, got {self.timestamp}"

    def to_json(self) -> str:
        """Serialise event to JSON string."""
        return json.dumps(asdict(self), default=str)

    @classmethod
    def from_json(cls, json_str: str) -> "Event":
        """Deserialise event from JSON string."""
        data = json.loads(json_str)
        return cls(
            event_type=data["event_type"],
            timestamp=data["timestamp"],
            data=data.get("data", {}),
        )


class EventCollector:
    """
    Collects events in memory for testing and inspection.

    Thread-safe for async usage.
    """

    def __init__(self) -> None:
        self._events: list[Event] = []

    def emit(self, event: Event) -> None:
        """Add an event to the collection."""
        assert isinstance(event, Event), f"Expected Event, got {type(event)}"
        self._events.append(event)

    @property
    def events(self) -> list[Event]:
        """Return collected events (immutable view)."""
        return list(self._events)

    def clear(self) -> None:
        """Clear all collected events."""
        self._events.clear()

    def get_by_type(self, event_type: str | EventType) -> list[Event]:
        """Get all events of a specific type."""
        if isinstance(event_type, EventType):
            event_type = event_type.value
        return [e for e in self._events if e.event_type == event_type]


class JSONLEventWriter:
    """
    Writes events to a JSONL file.

    Each event is written as a single line of JSON, enabling:
    - Streaming reads
    - Append-only logging
    - Easy parsing for AI inspection
    """

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        self._file: IO[str] | None = None

    def open(self) -> None:
        """Open the log file for writing."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(self._path, "a", encoding="utf-8")

    def close(self) -> None:
        """Close the log file."""
        if self._file:
            self._file.close()
            self._file = None

    def emit(self, event: Event) -> None:
        """Write an event to the log file."""
        assert self._file is not None, "Writer not opened. Call open() first."
        self._file.write(event.to_json() + "\n")
        self._file.flush()

    def __enter__(self) -> "JSONLEventWriter":
        self.open()
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


class EventEmitter:
    """
    Composite event emitter that dispatches to multiple sinks.

    Supports:
    - In-memory collector (for testing)
    - JSONL file writer (for persistence)
    - Future: streaming sinks
    """

    def __init__(
        self,
        collector: EventCollector | None = None,
        jsonl_path: Path | str | None = None,
    ) -> None:
        self._collector = collector
        self._jsonl_writer: JSONLEventWriter | None = None

        if jsonl_path:
            self._jsonl_writer = JSONLEventWriter(jsonl_path)
            self._jsonl_writer.open()

    def emit(self, event_type: str | EventType, **data: Any) -> Event:
        """
        Create and emit an event.

        Args:
            event_type: The type of event
            **data: Event-specific data

        Returns:
            The created event
        """
        if isinstance(event_type, EventType):
            event_type = event_type.value

        event = Event(event_type=event_type, data=data)

        if self._collector:
            self._collector.emit(event)

        if self._jsonl_writer:
            self._jsonl_writer.emit(event)

        return event

    def close(self) -> None:
        """Close any open resources."""
        if self._jsonl_writer:
            self._jsonl_writer.close()

    @contextmanager
    def timed_event(
        self,
        event_type: str | EventType,
        **initial_data: Any,
    ) -> Iterator[dict[str, Any]]:
        """
        Context manager for timing an operation.

        Emits the event on exit with duration_ms added to data.

        Usage:
            with emitter.timed_event("EXEC", command="echo hello") as data:
                result = await run_command()
                data["exit_code"] = result.exit_code
        """
        start_ms = time.time() * 1000
        event_data = dict(initial_data)

        try:
            yield event_data
        finally:
            duration_ms = (time.time() * 1000) - start_ms
            event_data["duration_ms"] = duration_ms
            self.emit(event_type, **event_data)


def read_jsonl_events(path: Path | str) -> list[Event]:
    """
    Read all events from a JSONL file.

    Args:
        path: Path to the JSONL file

    Returns:
        List of Event objects
    """
    path = Path(path)
    assert path.exists(), f"JSONL file not found: {path}"

    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(Event.from_json(line))

    return events
