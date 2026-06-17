"""Timer scheduling for the ``set-timer`` skill.

When a timer expires it fires a notifier callback (the "alert"). Scheduling is
injectable so tests can drive expiry deterministically instead of waiting on a
wall-clock delay.
"""
from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any

# A scheduler runs ``callback`` after ``delay`` seconds and returns a handle.
Scheduler = Callable[[float, Callable[[], None]], Any]
Notifier = Callable[[str], None]


def threading_scheduler(delay: float, callback: Callable[[], None]) -> threading.Timer:
    """Default scheduler backed by a daemon :class:`threading.Timer`."""
    timer = threading.Timer(delay, callback)
    timer.daemon = True
    timer.start()
    return timer


class Timer:
    """A single pending timer that fires its notifier exactly once on expiry."""

    def __init__(self, seconds: int, label: str, message: str, notifier: Notifier | None):
        self.seconds = seconds
        self.label = label
        self.message = message
        self.fired = False
        self._notifier = notifier
        self._handle: Any = None

    def fire(self) -> None:
        if self.fired:
            return
        self.fired = True
        if self._notifier is not None:
            self._notifier(self.message)

    def cancel(self) -> None:
        if self._handle is not None and hasattr(self._handle, "cancel"):
            self._handle.cancel()


class TimerService:
    """Creates and tracks timers, scheduling each one's expiry."""

    def __init__(self, scheduler: Scheduler | None = None):
        self._scheduler = scheduler or threading_scheduler
        self.timers: list[Timer] = []

    def set(self, seconds: int, label: str, notifier: Notifier | None = None) -> Timer:
        message = f"\u23f0 Time's up! Your timer for {label} is done."
        timer = Timer(seconds, label, message, notifier)
        timer._handle = self._scheduler(seconds, timer.fire)
        self.timers.append(timer)
        return timer
