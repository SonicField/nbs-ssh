"""
SSH keepalive configuration and progress watchdog.

Provides:
- KeepaliveConfig: Configuration for SSH-level keepalive
- ProgressWatchdog: Application-level freeze detection

Two-level freeze detection:
1. SSH-level: AsyncSSH keepalive timeout (connection actually dead)
2. Progress-level: Command running but no output (application frozen)
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from nbs_ssh.events import EventCollector

logger = logging.getLogger(__name__)


@dataclass
class KeepaliveConfig:
    """
    Configuration for SSH connection keepalive.

    Controls AsyncSSH's keepalive behaviour:
    - interval_sec: Seconds between keepalive packets
    - max_count: Number of missed keepalives before disconnect
    - progress_timeout_sec: Optional timeout for application progress

    Default: 30s interval, 3 max count = 90s total before disconnect.

    Usage:
        # Default keepalive
        config = KeepaliveConfig()

        # Aggressive keepalive (faster failure detection)
        config = KeepaliveConfig(interval_sec=10.0, max_count=2)

        # With progress watchdog
        config = KeepaliveConfig(progress_timeout_sec=60.0)
    """
    interval_sec: float = 30.0
    max_count: int = 3
    progress_timeout_sec: float | None = None

    def __post_init__(self) -> None:
        """Validate configuration."""
        assert self.interval_sec > 0, \
            f"interval_sec must be positive, got {self.interval_sec}"
        assert self.max_count > 0, \
            f"max_count must be positive, got {self.max_count}"
        if self.progress_timeout_sec is not None:
            assert self.progress_timeout_sec > 0, \
                f"progress_timeout_sec must be positive, got {self.progress_timeout_sec}"

    @property
    def total_timeout_sec(self) -> float:
        """Total time before keepalive failure (interval * max_count)."""
        return self.interval_sec * self.max_count

    def to_asyncssh_options(self) -> dict[str, Any]:
        """
        Convert to AsyncSSH connection options.

        Returns:
            Dict with keepalive_interval and keepalive_count_max keys.
        """
        return {
            "keepalive_interval": self.interval_sec,
            "keepalive_count_max": self.max_count,
        }


class ProgressWatchdog:
    """
    Application-level freeze detection.

    Monitors command output for progress. If no progress is received
    within the timeout, emits a warning and optionally triggers a callback.

    This is separate from SSH keepalive:
    - SSH keepalive: Network-level connectivity
    - Progress watchdog: Application-level responsiveness

    Usage:
        watchdog = ProgressWatchdog(
            timeout_sec=60.0,
            event_collector=collector,
            on_timeout=lambda: print("Frozen!"),
        )

        watchdog.start()
        try:
            async for chunk in stream:
                watchdog.progress()  # Reset timer on each chunk
                process(chunk)
        finally:
            watchdog.stop()
    """

    def __init__(
        self,
        timeout_sec: float,
        event_collector: "EventCollector | None" = None,
        on_timeout: Callable[[], None] | None = None,
        warning_threshold: float = 0.75,
    ) -> None:
        """
        Initialise progress watchdog.

        Args:
            timeout_sec: Seconds of no progress before timeout
            event_collector: Optional collector for events
            on_timeout: Optional callback when timeout occurs
            warning_threshold: Fraction of timeout before warning (0.0-1.0)
        """
        assert timeout_sec > 0, f"timeout_sec must be positive, got {timeout_sec}"
        assert 0.0 < warning_threshold < 1.0, \
            f"warning_threshold must be between 0 and 1, got {warning_threshold}"

        self._timeout_sec = timeout_sec
        self._event_collector = event_collector
        self._on_timeout = on_timeout
        self._warning_threshold = warning_threshold

        self._timer_task: asyncio.Task[None] | None = None
        self._last_progress: float = 0.0
        self._timed_out = False
        self._warning_emitted = False
        self._running = False

    @property
    def timeout_sec(self) -> float:
        """Return the timeout in seconds."""
        return self._timeout_sec

    @property
    def is_running(self) -> bool:
        """Return True if watchdog is running."""
        return self._running

    @property
    def timed_out(self) -> bool:
        """Return True if watchdog has timed out."""
        return self._timed_out

    def start(self) -> None:
        """Start the watchdog timer."""
        assert not self._running, (
            "ProgressWatchdog.start() called while already running. "
            "Call stop() before restarting."
        )

        self._running = True
        self._timed_out = False
        self._warning_emitted = False
        self._last_progress = time.time()
        self._timer_task = asyncio.create_task(self._timer_loop())

        # Postcondition: watchdog is now fully initialised and running
        assert self._running and self._timer_task is not None, (
            "Postcondition violated: start() completed but watchdog state is inconsistent. "
            f"running={self._running}, timer_task={self._timer_task}"
        )

    def stop(self) -> None:
        """Stop the watchdog timer. Idempotent: safe to call after timeout."""
        if not self._running:
            logger.debug(
                "ProgressWatchdog.stop() called when not running "
                "(timed_out=%s). No action taken.",
                self._timed_out,
            )
            return

        self._running = False
        if self._timer_task is not None:
            self._timer_task.cancel()
            self._timer_task = None

    def progress(self) -> None:
        """
        Signal that progress has been made.

        Call this whenever output is received to reset the timer.
        """
        assert self._running, (
            "ProgressWatchdog.progress() called when not running. "
            "Call start() before signalling progress."
        )
        self._last_progress = time.time()
        self._warning_emitted = False  # Reset warning on progress

    async def _timer_loop(self) -> None:
        """Internal timer loop for checking progress."""
        check_interval = min(0.1, self._timeout_sec / 10)
        # Invariant: check_interval must be positive for the sleep to yield
        assert check_interval > 0, (
            f"check_interval must be positive, got {check_interval}. "
            f"Derived from timeout_sec={self._timeout_sec}."
        )

        try:
            while self._running:
                await asyncio.sleep(check_interval)

                if not self._running:
                    break

                elapsed = time.time() - self._last_progress
                remaining = self._timeout_sec - elapsed

                # Check for warning threshold
                if not self._warning_emitted and elapsed >= self._timeout_sec * self._warning_threshold:
                    self._emit_warning(remaining)
                    self._warning_emitted = True

                # Check for timeout
                if elapsed >= self._timeout_sec:
                    self._handle_timeout()
                    break

        except asyncio.CancelledError:
            # Expected path: stop() cancels the timer task.
            # No cleanup needed; stop() handles state transitions.
            pass
        except Exception:
            # Unexpected error in timer loop. Log and mark as not running
            # to avoid silent hangs. Re-raise to surface the bug.
            logger.exception("Unexpected error in ProgressWatchdog timer loop")
            self._running = False
            raise

    def _emit_warning(self, seconds_remaining: float) -> None:
        """Emit a progress warning event."""
        if self._event_collector is not None:
            from nbs_ssh.events import Event, EventType

            event = Event(
                event_type=EventType.PROGRESS_WARNING.value,
                data={
                    "seconds_remaining": round(seconds_remaining, 2),
                    "timeout_sec": self._timeout_sec,
                    "message": f"No progress for {self._timeout_sec - seconds_remaining:.1f}s",
                },
            )
            self._event_collector.emit(event)

    def _handle_timeout(self) -> None:
        """Handle progress timeout."""
        self._timed_out = True
        self._running = False

        if self._on_timeout is not None:
            self._on_timeout()

        # Postcondition: after timeout, we must be timed out and not running
        assert self._timed_out and not self._running, (
            "Postcondition violated: _handle_timeout() completed but state is inconsistent. "
            f"timed_out={self._timed_out}, running={self._running}"
        )
