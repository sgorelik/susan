"""Static-response skill registry loaded from YAML definitions in ``skills/``.

A *skill* is the simplest unit of Susan behavior: a named set of trigger phrases
and a static text response — no slots, no external API calls, and no session
state (each invocation is fully independent). ``hello-world`` is the canonical
reference implementation; see ``skills/hello-world.yaml`` for the definition.

The YAML files are the source of truth. This module loads them at import time
and exposes :func:`match_skill`, which the ``/susan`` slash-command handler uses
to map a user's message to a skill's static response.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from app.config import logger

SKILLS_DIR = Path(__file__).resolve().parent.parent / "skills"


@dataclass(frozen=True)
class Skill:
    name: str
    description: str
    triggers: tuple[str, ...]
    response_text: str


def _normalize(text: str) -> str:
    """Lowercase, collapse whitespace, and drop trailing greeting punctuation.

    Lets ``Hello``, ``hello!``, and ``Hi   Susan`` all match the ``hello`` /
    ``hi susan`` triggers (case-insensitive, as required).
    """
    s = " ".join((text or "").strip().lower().split())
    return s.rstrip("!.?,").strip()


def _load_skills() -> tuple[dict[str, Skill], dict[str, Skill]]:
    """Parse every ``skills/*.yaml`` definition into a registry and a trigger index."""
    registry: dict[str, Skill] = {}
    index: dict[str, Skill] = {}
    if not SKILLS_DIR.is_dir():
        return registry, index
    for path in sorted(SKILLS_DIR.glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            logger.exception("Failed to load skill definition %s", path)
            continue
        spec = (data or {}).get("skill") or {}
        name = (spec.get("name") or "").strip()
        triggers_raw = spec.get("triggers") or []
        response_text = ((spec.get("response") or {}).get("text"))
        if not name or not triggers_raw or not isinstance(response_text, str):
            logger.warning("Skipping invalid skill definition: %s", path)
            continue
        triggers = tuple(dict.fromkeys(t for t in (_normalize(t) for t in triggers_raw) if t))
        skill = Skill(
            name=name,
            description=(spec.get("description") or "").strip(),
            triggers=triggers,
            response_text=response_text,
        )
        registry[name] = skill
        for trigger in triggers:
            index[trigger] = skill
    return registry, index


SKILLS, _TRIGGER_INDEX = _load_skills()


def match_skill(text: str) -> Skill | None:
    """Return the skill whose trigger phrase matches ``text`` exactly, else ``None``."""
    return _TRIGGER_INDEX.get(_normalize(text))
