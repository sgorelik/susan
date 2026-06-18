"""Countdown timer scheduling with an asynchronous expiry alert.

``parse_duration`` turns spoken durations ("5 minutes", "1 hour 30 minutes")
into seconds. ``TimerService`` schedules a background task that waits out the
duration and then invokes a notifier so the user is alerted when time is up.
"""
from __future__ import annotations

import asyncio
import inspect
import re
from typing import Awaitable, Callable

from app.config import logger

# Singular unit -> seconds. Plurals/abbreviations are normalised below.
_UNIT_SECONDS = {
    "second": 1,
    "sec": 1,
    "s": 1,
    "minute": 60,
    "min": 60,
    "m": 60,
    "hour": 3600,
    "hr": 3600,
    "h": 3600,
    "day": 86400,
    "d": 86400,
}

_DURATION_RE = re.compile(
    r"\b(\d+(?:\.\d+)?|an|a|one)\s*"
    r"(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d)\b",
    re.IGNORECASE,
)


def _unit_key(unit: str) -> str | None:
    u = unit.lower()
    if u in _UNIT_SECONDS:
        return u
    # Drop a plural "s" (e.g. "seconds" -> "second", "secs" -> "sec", "hrs" -> "hr"),
    # but only when the singular is a known unit so bare "s" still maps correctly.
    if u.endswith("s") and u[:-1] in _UNIT_SECONDS:
        return u[:-1]
    return None


def parse_duration(text: str) -> int | None:
    """Parse a human duration into whole seconds, or ``None`` if unparseable."""
    if not text:
        return None
    total = 0.0
    found = False
    for qty, unit in _DURATION_RE.findall(text):
        key = _unit_key(unit)
        if key is None:
            continue
        amount = 1.0 if qty.lower() in ("a", "an", "one") else float(qty)
        total += amount * _UNIT_SECONDS[key]
        found = True
    if not found:
        return None
    seconds = int(round(total))
    return seconds if seconds > 0 else None


Notifier = Callable[[str], Awaitable[None] | None]


async def _default_notifier(message: str) -> None:
    logger.info("Timer expired: %s", message)


class TimerService:
    """Schedules timers as asyncio tasks and notifies on expiry.

    ``notifier`` is invoked with the alert message when a timer fires (it may be
    sync or async). ``sleep`` is injectable so tests can avoid real delays.
    """

    def __init__(
        self,
        notifier: Notifier | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._notifier: Notifier = notifier or _default_notifier
        self._sleep = sleep
        self.active: set[asyncio.Task] = set()

    async def schedule(self, seconds: float, message: str) -> asyncio.Task:
        """Start a background timer; returns the task (awaitable in tests)."""
        task = asyncio.create_task(self._run(seconds, message))
        self.active.add(task)
        task.add_done_callback(self.active.discard)
        return task

    async def _run(self, seconds: float, message: str) -> None:
        await self._sleep(seconds)
        await self._notify(message)

    async def _notify(self, message: str) -> None:
        try:
            result = self._notifier(message)
            if inspect.isawaitable(result):
                await result
        except Exception:  # never let a notifier failure crash the task
            logger.exception("Timer notifier failed")
