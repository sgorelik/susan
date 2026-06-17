"""Declarative, stateless skill registry.

A *skill* is a simple conversational intent defined as a YAML file under the
repository ``skills/`` directory. The canonical / reference example is
``hello-world``: a static-text greeting that needs no slots, no handler, and
makes no external API calls.

Each YAML file describes exactly one skill::

    skill:
      name: hello-world
      description: Greets the user with a Hello World message.
      triggers:
        - "hello"
        - "hi susan"
      response:
        text: "Hello, World! I'm Susan, and I'm ready to help."

At import time every ``*.yaml`` file in :data:`SKILLS_DIR` is loaded into the
:data:`SKILLS` registry, keyed by skill name. :func:`match_skill` returns the
skill whose trigger phrases match the user's message (case-insensitive), or
``None``. Matching is fully stateless — each call is independent.

Only the static ``response.text`` form is supported here; dynamic skills
(``response.dynamic``/``response.handler``) are out of scope.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from app.config import logger

SKILLS_DIR = Path(__file__).resolve().parent.parent / "skills"


@dataclass(frozen=True)
class Skill:
    """A loaded, stateless skill with static-text response."""

    name: str
    description: str
    triggers: tuple[str, ...]
    response_text: str


def _normalize(text: str) -> str:
    """Lowercase, trim, strip surrounding punctuation, and collapse whitespace."""
    s = (text or "").strip().lower()
    s = s.strip(" \t\r\n!.?,;:")
    s = re.sub(r"\s+", " ", s)
    return s


def _load_skill_file(path: Path) -> Skill | None:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as e:
        logger.warning("Skipping skill file %s: %s", path.name, e)
        return None
    spec = (data or {}).get("skill") or {}
    name = (spec.get("name") or "").strip()
    triggers = spec.get("triggers") or []
    response = spec.get("response") or {}
    text = response.get("text")
    if not name or not isinstance(text, str) or not isinstance(triggers, list):
        logger.warning("Skipping malformed skill file %s", path.name)
        return None
    normalized = tuple(
        _normalize(t) for t in triggers if isinstance(t, str) and _normalize(t)
    )
    if not normalized:
        logger.warning("Skill %s in %s has no usable triggers", name, path.name)
        return None
    return Skill(
        name=name,
        description=(spec.get("description") or "").strip(),
        triggers=normalized,
        response_text=text,
    )


def _load_skills(directory: Path = SKILLS_DIR) -> dict[str, Skill]:
    registry: dict[str, Skill] = {}
    if not directory.is_dir():
        return registry
    for path in sorted(directory.glob("*.yaml")):
        skill = _load_skill_file(path)
        if skill is not None:
            registry[skill.name] = skill
    return registry


SKILLS: dict[str, Skill] = _load_skills()


def match_skill(text: str) -> Skill | None:
    """Return the skill whose trigger phrase matches ``text`` (case-insensitive)."""
    normalized = _normalize(text)
    if not normalized:
        return None
    for skill in SKILLS.values():
        if normalized in skill.triggers:
            return skill
    return None
