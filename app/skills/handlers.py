"""Dynamic response handlers, addressed by name from skill YAML.

Handler names match the registry in the skill spec: ``time.current_local``,
``time.current_date``, ``content.random_joke``, ``content.random_fact``,
``timer.set``, ``weather.current``, ``session.replay_last``, and ``help.summary``.

Each handler is ``(HandlerRequest) -> HandlerResult`` and may be async.
"""
from __future__ import annotations

from datetime import datetime

from app.skills.matching import parse_duration
from app.skills.models import HandlerRequest, HandlerResult
from app.skills.weather import WeatherError

_WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
_MONTHS = (
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
)


def format_time(now: datetime) -> str:
    """Format as a human 12-hour clock, e.g. "3:45 PM"."""
    hour12 = now.hour % 12 or 12
    meridiem = "AM" if now.hour < 12 else "PM"
    return f"{hour12}:{now.minute:02d} {meridiem}"


def format_date(now: datetime) -> str:
    """Format as weekday + month + day, e.g. "Tuesday, June 17"."""
    return f"{_WEEKDAYS[now.weekday()]}, {_MONTHS[now.month - 1]} {now.day}"


def current_local(req: HandlerRequest) -> HandlerResult:
    return HandlerResult(text=f"It's {format_time(req.context.clock())}.")


def current_date(req: HandlerRequest) -> HandlerResult:
    return HandlerResult(text=f"Today is {format_date(req.context.clock())}.")


def random_joke(req: HandlerRequest) -> HandlerResult:
    return HandlerResult(text=req.context.jokes.next())


def random_fact(req: HandlerRequest) -> HandlerResult:
    return HandlerResult(text=req.context.facts.next())


def timer_set(req: HandlerRequest) -> HandlerResult:
    raw = (req.slots.get("duration") or "").strip()
    seconds = parse_duration(raw)
    if not seconds:
        return HandlerResult(
            text="Sorry, I couldn't understand that duration. Try something like \"5 minutes\".",
        )
    timer = req.context.timers.set(seconds, raw, notifier=req.context.notifier)
    return HandlerResult(
        text=f"Timer set for {raw}. I'll let you know when it's done.",
        data={"timer": timer},
    )


async def weather_current(req: HandlerRequest) -> HandlerResult:
    permission = req.session.permissions.get("location")
    if permission == "denied":
        return HandlerResult(
            text="I can't check the weather without access to your location. "
            "Enable location access and ask me again.",
        )
    if permission != "granted":
        req.session.permissions["location"] = "requested"
        return HandlerResult(
            text="I need access to your location to check the weather. May I use it?",
            permission_request="location",
        )
    try:
        report = await req.context.weather.current(req.session.location)
    except WeatherError:
        return HandlerResult(
            text="Sorry, I'm having trouble reaching the weather service right now. "
            "Please try again later.",
        )
    except Exception:  # defensive: never leak provider internals to the user
        return HandlerResult(
            text="Sorry, I'm having trouble reaching the weather service right now. "
            "Please try again later.",
        )
    return HandlerResult(
        text=f"Currently in {report.location}: {report.conditions}, {report.temperature}.",
    )


def replay_last(req: HandlerRequest) -> HandlerResult:
    last = req.session.last_response
    if not last:
        return HandlerResult(text="I haven't said anything yet!")
    return HandlerResult(text=last)


def help_summary(req: HandlerRequest) -> HandlerResult:
    """Describe every registered skill so the list stays in sync with the registry."""
    skills = sorted(req.engine.skills, key=lambda s: (s.order, s.name))
    parts = [s.help_summary for s in skills if s.help_summary]
    return HandlerResult(text=f"Here's what I can do: {_join_natural(parts)}. Just ask!")


def _join_natural(items: list[str]) -> str:
    if not items:
        return "not much yet"
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + ", and " + items[-1]


def default_handlers() -> dict[str, object]:
    """Map handler names (as referenced in YAML) to their callables."""
    return {
        "time.current_local": current_local,
        "time.current_date": current_date,
        "content.random_joke": random_joke,
        "content.random_fact": random_fact,
        "timer.set": timer_set,
        "weather.current": weather_current,
        "session.replay_last": replay_last,
        "help.summary": help_summary,
    }
