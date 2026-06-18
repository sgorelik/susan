"""Dispatch utterances to skills: match, elicit slots, respond, end sessions."""
from __future__ import annotations

from app.skills.handlers import get_handler
from app.skills.loader import get_registry
from app.skills.matcher import match
from app.skills.models import Session, Skill, SkillResult
from app.skills.services import Services, build_default_services

_NO_MATCH = "Sorry, I didn't catch that. Could you rephrase?"


async def dispatch(
    utterance: str,
    session: Session | None = None,
    *,
    registry: dict[str, Skill] | None = None,
    services: Services | None = None,
) -> SkillResult:
    """Process one user utterance and return Susan's response.

    Mutates ``session`` to carry slot-elicitation state and the ``ended`` flag.
    """
    session = session if session is not None else Session()
    registry = registry if registry is not None else get_registry()
    services = services if services is not None else build_default_services()

    # A slot was being elicited: treat this utterance as that slot's value.
    if session.pending_skill and session.pending_slot:
        skill = registry[session.pending_skill]
        session.slots[session.pending_slot] = (utterance or "").strip()
        session.pending_slot = None
        return await _resolve(skill, session, services)

    result = match(utterance, registry.values())
    if result is None:
        return SkillResult(matched=False, text=_NO_MATCH)

    session.slots = dict(result.slots)
    return await _resolve(result.skill, session, services)


async def _resolve(skill: Skill, session: Session, services: Services) -> SkillResult:
    """Elicit the next missing required slot, or build the final response."""
    for slot in skill.slots:
        if slot.required and not (session.slots.get(slot.name) or "").strip():
            session.pending_skill = skill.name
            session.pending_slot = slot.name
            return SkillResult(
                skill=skill.name,
                elicit=True,
                text=slot.prompt or f"What is the {slot.name}?",
            )

    session.pending_skill = None
    session.pending_slot = None

    result = await _respond(skill, session, services)

    if skill.session_end:
        session.ended = True
        result.session_end = True
    return result


async def _respond(skill: Skill, session: Session, services: Services) -> SkillResult:
    response = skill.response
    if response.dynamic:
        handler = get_handler(response.handler)
        return await handler(
            slots=session.slots, session=session, skill=skill, services=services
        )

    text = response.text or ""
    try:
        text = text.format(**session.slots)
    except (KeyError, IndexError):
        pass
    return SkillResult(skill=skill.name, text=text)
