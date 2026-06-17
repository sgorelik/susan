"""The skill engine: match an utterance to a skill, run it, manage session state."""
from __future__ import annotations

import inspect
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from app.skills import matching
from app.skills.content import RotatingPool, default_fact_pool, default_joke_pool
from app.skills.handlers import default_handlers
from app.skills.loader import load_definitions
from app.skills.models import (
    HandlerRequest,
    HandlerResult,
    Session,
    Skill,
    SkillResponse,
)
from app.skills.timers import TimerService
from app.skills.weather import WeatherProvider

UNKNOWN_RESPONSE = "Sorry, I didn't catch that. Say \"help\" to hear what I can do."


@dataclass
class SkillContext:
    """Shared services injected into dynamic handlers (all overridable for tests)."""

    clock: Callable[[], datetime] = field(default_factory=lambda: datetime.now)
    jokes: RotatingPool = field(default_factory=default_joke_pool)
    facts: RotatingPool = field(default_factory=default_fact_pool)
    timers: TimerService = field(default_factory=TimerService)
    weather: WeatherProvider = field(default_factory=WeatherProvider)
    notifier: Callable[[str], None] | None = None
    notifications: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.notifier is None:
            self.notifier = self.notifications.append


class SkillEngine:
    """Routes utterances to skills and runs their static or dynamic responses."""

    def __init__(
        self,
        skills: list[Skill],
        handlers: dict[str, Callable] | None = None,
        context: SkillContext | None = None,
    ):
        self.skills = list(skills)
        self.registry: dict[str, Skill] = {s.name: s for s in self.skills}
        self.handlers = handlers if handlers is not None else default_handlers()
        self.context = context or SkillContext()
        self._validate()

    def _validate(self) -> None:
        for skill in self.skills:
            if skill.response.dynamic and skill.response.handler not in self.handlers:
                raise KeyError(
                    f"skill '{skill.name}' references unknown handler "
                    f"'{skill.response.handler}'"
                )

    def match(self, text: str) -> matching.TriggerMatch | None:
        return matching.match(self.skills, text)

    async def handle(self, text: str, session: Session | None = None) -> SkillResponse:
        """Process one turn of conversation and return Susan's response."""
        session = session or Session()

        # Continue an in-progress slot elicitation: the whole utterance is the value.
        if session.pending_slot and session.pending_skill in self.registry:
            skill = self.registry[session.pending_skill]
            slots = dict(session.pending_slots)
            slots[session.pending_slot] = (text or "").strip()
            session.clear_pending()
            return self._finalize(await self._run(skill, slots, session), session)

        found = self.match(text)
        if found is None:
            return self._finalize(
                SkillResponse(text=UNKNOWN_RESPONSE, matched=False), session
            )

        if found.missing_slot:
            return self._finalize(
                self._elicit(found.skill, found.missing_slot, found.slots, session),
                session,
            )

        return self._finalize(await self._run(found.skill, found.slots, session), session)

    def _elicit(
        self, skill: Skill, slot_name: str, slots: dict[str, str], session: Session
    ) -> SkillResponse:
        session.set_pending(skill.name, slot_name, slots)
        slot = skill.slot(slot_name)
        prompt = (slot.prompt if slot else None) or f"What's the {slot_name}?"
        return SkillResponse(text=prompt, skill=skill.name, eliciting=True)

    async def _run(self, skill: Skill, slots: dict[str, str], session: Session) -> SkillResponse:
        # Re-elicit if a required slot is still missing after a resume attempt.
        for slot in skill.slots:
            if slot.required and not (slots.get(slot.name) or "").strip():
                return self._elicit(skill, slot.name, slots, session)

        if not skill.response.dynamic:
            return SkillResponse(
                text=skill.response.text or "",
                skill=skill.name,
                end_session=skill.end_session,
            )

        handler = self.handlers[skill.response.handler]
        result = handler(HandlerRequest(skill, slots, session, self.context, self))
        if inspect.isawaitable(result):
            result = await result
        assert isinstance(result, HandlerResult)
        return SkillResponse(
            text=result.text,
            skill=skill.name,
            end_session=result.end_session or skill.end_session,
            permission_request=result.permission_request,
            data=result.data,
        )

    def _finalize(self, response: SkillResponse, session: Session) -> SkillResponse:
        if response.end_session:
            session.ended = True
        # Persist the spoken response so 'repeat' can replay it; the repeat skill
        # itself must not overwrite what it is replaying.
        if response.matched and response.text and response.skill != "repeat":
            session.last_response = response.text
        return response


def default_engine() -> SkillEngine:
    """Build an engine from the bundled YAML definitions and default services."""
    return SkillEngine(load_definitions())
