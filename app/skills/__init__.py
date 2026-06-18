"""Susan's declarative skill system.

Skills are defined as YAML files under ``definitions/`` and dispatched through
:func:`app.skills.engine.dispatch`. Importing this package also registers the
built-in dynamic handlers (``timer.set``, ``weather.current``).

Example::

    from app.skills import dispatch, Session

    session = Session()
    result = await dispatch("set a timer for 5 minutes", session)
    print(result.text)  # "Timer set for 5 minutes. I'll let you know when it's done."
"""
from __future__ import annotations

from app.skills import handlers as _handlers  # noqa: F401  (registers handlers)
from app.skills.engine import dispatch
from app.skills.loader import get_registry, load_skills
from app.skills.models import Session, Skill, SkillResult, Slot

__all__ = [
    "dispatch",
    "get_registry",
    "load_skills",
    "Session",
    "Skill",
    "SkillResult",
    "Slot",
]
