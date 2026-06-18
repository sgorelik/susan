"""Dynamic skill handlers, keyed by the ``handler`` string in a definition."""
from __future__ import annotations

from typing import Awaitable, Callable

from app.skills.models import Session, Skill, SkillResult
from app.skills.services import Services
from app.skills.timer import parse_duration
from app.skills.weather import WeatherUnavailable

Handler = Callable[..., Awaitable[SkillResult]]

_HANDLERS: dict[str, Handler] = {}


def handler(name: str) -> Callable[[Handler], Handler]:
    def register(fn: Handler) -> Handler:
        _HANDLERS[name] = fn
        return fn

    return register


def get_handler(name: str) -> Handler:
    try:
        return _HANDLERS[name]
    except KeyError:
        raise KeyError(f"no skill handler registered for {name!r}") from None


@handler("timer.set")
async def timer_set(
    *, slots: dict, session: Session, skill: Skill, services: Services
) -> SkillResult:
    """Parse the duration, schedule the expiry alert, and confirm."""
    duration_text = (slots.get("duration") or "").strip()
    seconds = parse_duration(duration_text)
    if not seconds:
        return SkillResult(
            skill=skill.name,
            error=True,
            text="Sorry, I couldn't understand that duration. Try something like '5 minutes'.",
        )

    await services.timer.schedule(seconds, f"Time's up! Your {duration_text} timer is done.")

    template = skill.response.text or "Timer set for {duration}."
    return SkillResult(
        skill=skill.name,
        text=template.format(duration=duration_text),
        data={"seconds": seconds},
    )


@handler("weather.current")
async def weather_current(
    *, slots: dict, session: Session, skill: Skill, services: Services
) -> SkillResult:
    """Check location permission, then fetch and format current conditions."""
    permission = skill.permission or "location"
    status = session.permissions.get(permission)
    if status == "denied":
        return SkillResult(
            skill=skill.name,
            error=True,
            text="I can't check the weather without access to your location.",
        )
    if status != "granted":
        return SkillResult(
            skill=skill.name,
            needs_permission=permission,
            text="I need permission to use your location to check the weather. Is that okay?",
        )

    try:
        weather = await services.weather.current()
    except WeatherUnavailable:
        return SkillResult(
            skill=skill.name,
            error=True,
            text="Sorry, I can't reach the weather service right now. Please try again later.",
        )

    template = skill.response.text or "Currently in {location}: {conditions}, {temperature}."
    return SkillResult(
        skill=skill.name,
        text=template.format(
            location=weather.location,
            conditions=weather.conditions,
            temperature=weather.temperature,
        ),
    )
