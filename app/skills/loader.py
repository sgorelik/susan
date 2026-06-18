"""Load YAML skill definitions into a name-keyed registry."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from app.config import logger
from app.skills.models import ResponseSpec, Skill, Slot

DEFINITIONS_DIR = Path(__file__).resolve().parent / "definitions"


def _parse_slot(raw: dict[str, Any]) -> Slot:
    return Slot(
        name=str(raw["name"]),
        type=str(raw.get("type", "string")),
        required=bool(raw.get("required", True)),
        prompt=raw.get("prompt"),
    )


def _parse_skill(raw: dict[str, Any]) -> Skill:
    name = str(raw["name"]).strip()
    if not name:
        raise ValueError("skill definition is missing a name")

    response_raw = raw.get("response") or {}
    response = ResponseSpec(
        text=response_raw.get("text"),
        dynamic=bool(response_raw.get("dynamic", False)),
        handler=response_raw.get("handler"),
    )
    if response.dynamic and not response.handler:
        raise ValueError(f"skill {name!r} is dynamic but declares no handler")

    triggers = [str(t) for t in (raw.get("triggers") or [])]
    if not triggers:
        raise ValueError(f"skill {name!r} declares no triggers")

    session_raw = raw.get("session") or {}

    return Skill(
        name=name,
        description=str(raw.get("description", "")),
        triggers=triggers,
        response=response,
        slots=[_parse_slot(s) for s in (raw.get("slots") or [])],
        session_end=bool(session_raw.get("end", False)),
        api=raw.get("api"),
        permission=raw.get("permission"),
    )


def load_skills(directory: Path | str | None = None) -> dict[str, Skill]:
    """Parse every ``*.yaml`` definition into a ``{name: Skill}`` registry."""
    base = Path(directory) if directory is not None else DEFINITIONS_DIR
    registry: dict[str, Skill] = {}
    for path in sorted(base.glob("*.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        skill = _parse_skill(raw)
        if skill.name in registry:
            raise ValueError(f"duplicate skill name {skill.name!r} in {path.name}")
        registry[skill.name] = skill
    logger.info("Loaded %d skill(s): %s", len(registry), ", ".join(sorted(registry)))
    return registry


_REGISTRY: dict[str, Skill] | None = None


def get_registry() -> dict[str, Skill]:
    """Return the process-wide skill registry, loading definitions on first use."""
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = load_skills()
    return _REGISTRY
