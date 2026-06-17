"""Load and validate YAML skill definitions into :class:`Skill` objects."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from app.skills.models import (
    Requirement,
    Response,
    Skill,
    SkillDefinitionError,
    Slot,
)

DEFINITIONS_DIR = Path(__file__).resolve().parent / "definitions"


def load_skill(data: dict[str, Any], *, source: str = "<dict>") -> Skill:
    """Build a :class:`Skill` from a parsed YAML mapping, validating fields."""
    if not isinstance(data, dict):
        raise SkillDefinitionError(f"{source}: skill definition must be a mapping")

    name = data.get("name")
    if not isinstance(name, str) or not name.strip():
        raise SkillDefinitionError(f"{source}: skill is missing a 'name'")

    triggers_raw = data.get("triggers")
    if not isinstance(triggers_raw, list) or not triggers_raw:
        raise SkillDefinitionError(f"{name}: 'triggers' must be a non-empty list")
    triggers = tuple(str(t).strip() for t in triggers_raw if str(t).strip())
    if not triggers:
        raise SkillDefinitionError(f"{name}: 'triggers' must contain at least one phrase")

    response = _parse_response(name, data.get("response"))
    slots = _parse_slots(name, data.get("slots"))
    requires = _parse_requires(name, data.get("requires"))

    session = data.get("session") or {}
    end_session = bool(session.get("end")) if isinstance(session, dict) else False

    return Skill(
        name=name.strip(),
        triggers=triggers,
        response=response,
        slots=slots,
        requires=requires,
        end_session=end_session,
        help_summary=(data.get("help_summary") or None),
        order=int(data.get("order", 1000)),
    )


def _parse_response(name: str, raw: Any) -> Response:
    if not isinstance(raw, dict):
        raise SkillDefinitionError(f"{name}: 'response' must be a mapping")
    dynamic = bool(raw.get("dynamic"))
    handler = raw.get("handler")
    text = raw.get("text")
    if dynamic:
        if not isinstance(handler, str) or not handler.strip():
            raise SkillDefinitionError(f"{name}: dynamic response requires a 'handler'")
        return Response(dynamic=True, handler=handler.strip())
    if not isinstance(text, str) or not text.strip():
        raise SkillDefinitionError(f"{name}: static response requires non-empty 'text'")
    return Response(text=text)


def _parse_slots(name: str, raw: Any) -> tuple[Slot, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise SkillDefinitionError(f"{name}: 'slots' must be a list")
    slots: list[Slot] = []
    for entry in raw:
        if not isinstance(entry, dict) or not entry.get("name"):
            raise SkillDefinitionError(f"{name}: each slot needs a 'name'")
        slots.append(
            Slot(
                name=str(entry["name"]),
                type=str(entry.get("type", "string")),
                required=bool(entry.get("required", False)),
                prompt=(entry.get("prompt") or None),
            )
        )
    return tuple(slots)


def _parse_requires(name: str, raw: Any) -> tuple[Requirement, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise SkillDefinitionError(f"{name}: 'requires' must be a list")
    reqs: list[Requirement] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise SkillDefinitionError(f"{name}: each requirement must be a mapping")
        reqs.append(
            Requirement(
                api=(entry.get("api") or None),
                permission=(entry.get("permission") or None),
            )
        )
    return tuple(reqs)


def load_definitions(directory: Path | None = None) -> list[Skill]:
    """Load every ``*.yaml`` skill in ``directory`` (sorted by filename)."""
    directory = directory or DEFINITIONS_DIR
    skills: list[Skill] = []
    seen: set[str] = set()
    for path in sorted(directory.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        skill = load_skill(data, source=path.name)
        if skill.name in seen:
            raise SkillDefinitionError(f"duplicate skill name: {skill.name}")
        seen.add(skill.name)
        skills.append(skill)
    if not skills:
        raise SkillDefinitionError(f"no skill definitions found in {directory}")
    return skills
