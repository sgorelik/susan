"""Skill catalog: YAML-defined skills and case-insensitive trigger routing.

Skills are the standard way to add small, self-contained Susan capabilities. Each
skill is described by a YAML file in the top-level ``skills/`` directory and follows
this schema::

    skill:
      name: hello-world
      description: Greets the user with a Hello World message.
      triggers:
        - "hello"
        - "hi susan"
      response:
        text: "Hello, World! I'm Susan, and I'm ready to help."

``hello-world`` is the reference implementation: a stateless skill with a static
text response, no slots/parameters, and no external API calls. Trigger matching is
case-insensitive. Future skills (help, tell-time, …) follow the same template; a
skill that needs to compute its reply declares a dynamic response instead
(``response.dynamic: true`` with a ``handler``).
"""
from __future__ import annotations

import string
from dataclasses import dataclass
from pathlib import Path

import yaml

# Skill definitions live in the repo-root ``skills/`` directory (sibling of ``app/``).
SKILLS_DIR = Path(__file__).resolve().parent.parent / "skills"

# Characters trimmed from the edges of an utterance before matching, so "Hello!" and
# "hi susan." still match the "hello" / "hi susan" triggers.
_EDGE_CHARS = string.whitespace + string.punctuation


def _normalize(text: str) -> str:
    """Lower-case and strip surrounding whitespace/punctuation for trigger matching."""
    return (text or "").strip().lower().strip(_EDGE_CHARS)


@dataclass(frozen=True)
class Skill:
    """A single skill loaded from a YAML definition."""

    name: str
    description: str
    triggers: tuple[str, ...]
    response_text: str | None = None
    dynamic: bool = False
    handler: str | None = None

    def matches(self, text: str) -> bool:
        """True when ``text`` is one of this skill's triggers (case-insensitive)."""
        normalized = _normalize(text)
        return any(normalized == _normalize(trigger) for trigger in self.triggers)

    def respond(self) -> str | None:
        """Return the static response text. Stateless: same input → same output.

        Dynamic skills (``dynamic=True``) compute their reply via a handler and are
        not used by the static reference skill ``hello-world``.
        """
        return self.response_text


class SkillCatalog:
    """In-memory registry of skills, addressable by name and trigger phrase."""

    def __init__(self, skills: list[Skill]) -> None:
        self._skills = list(skills)
        self._by_name = {skill.name: skill for skill in self._skills}

    def all(self) -> list[Skill]:
        return list(self._skills)

    def get(self, name: str) -> Skill | None:
        return self._by_name.get(name)

    def match(self, text: str) -> Skill | None:
        """Return the first skill whose triggers match ``text``, or ``None``."""
        for skill in self._skills:
            if skill.matches(text):
                return skill
        return None


def _load_skill_file(path: Path) -> Skill:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    spec = data.get("skill", data)
    response = spec.get("response") or {}
    return Skill(
        name=spec["name"],
        description=spec.get("description", ""),
        triggers=tuple(str(trigger) for trigger in spec.get("triggers", [])),
        response_text=response.get("text"),
        dynamic=bool(response.get("dynamic", False)),
        handler=response.get("handler"),
    )


def load_skills(directory: Path = SKILLS_DIR) -> SkillCatalog:
    """Load every ``*.yaml`` / ``*.yml`` skill definition under ``directory``."""
    paths = sorted(p for p in directory.glob("*.y*ml")) if directory.is_dir() else []
    return SkillCatalog([_load_skill_file(path) for path in paths])


# Loaded once at import; skill definitions are static files shipped with the app.
CATALOG = load_skills()


def match_skill(text: str) -> Skill | None:
    """Find the skill triggered by ``text`` in the default catalog."""
    return CATALOG.match(text)


def skill_response(text: str) -> str | None:
    """Return the response text for the skill triggered by ``text``, else ``None``."""
    skill = CATALOG.match(text)
    if skill is None:
        return None
    return skill.respond()
