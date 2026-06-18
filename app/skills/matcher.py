"""Match an utterance against skill triggers and extract slot values.

Triggers are plain phrases that may embed ``{slot}`` placeholders, e.g.
``"set a timer for {duration}"``. Matching is case-insensitive and tolerant of
trailing punctuation. When a trigger's slot is omitted (``"set a timer"``) the
matcher still recognises the skill so the engine can elicit the missing slot.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from app.skills.models import Skill

_SLOT_RE = re.compile(r"\{(\w+)\}")

# Connector words dropped from the tail of an utterance/stem when recognising a
# slot-bearing trigger that was spoken without its slot value.
_TRAILING_FILLER = frozenset({"for", "to", "of", "about", "the", "a", "an"})


@dataclass
class MatchResult:
    skill: Skill
    slots: dict[str, str]


def _normalize(text: str) -> str:
    """Collapse whitespace and drop surrounding/trailing punctuation."""
    cleaned = re.sub(r"\s+", " ", (text or "").strip())
    return cleaned.strip(" ?!.,").strip()


def _trigger_regex(trigger: str) -> re.Pattern[str]:
    """Compile a trigger into an anchored, case-insensitive regex with named groups."""
    parts: list[str] = []
    last = 0
    for m in _SLOT_RE.finditer(trigger):
        parts.append(re.escape(trigger[last : m.start()]))
        parts.append(rf"(?P<{m.group(1)}>.+?)")
        last = m.end()
    parts.append(re.escape(trigger[last:]))
    return re.compile(r"^\s*" + "".join(parts) + r"\s*$", re.IGNORECASE)


def _word_key(text: str) -> str:
    """Lowercase word sequence with trailing connector words removed."""
    words = re.findall(r"[\w']+", text.lower())
    while words and words[-1] in _TRAILING_FILLER:
        words.pop()
    return " ".join(words)


def _trigger_stem(trigger: str) -> str | None:
    """The literal text before a trigger's first slot, or ``None`` if slotless."""
    idx = trigger.find("{")
    if idx == -1:
        return None
    return trigger[:idx]


def match(utterance: str, skills: Iterable[Skill]) -> MatchResult | None:
    """Return the best matching skill and any extracted slots, or ``None``."""
    text = _normalize(utterance)
    if not text:
        return None
    skills = list(skills)

    # Pass 1: a full trigger (with all slot values supplied) matches the utterance.
    for skill in skills:
        for trigger in skill.triggers:
            m = _trigger_regex(trigger).match(text)
            if m:
                slots = {k: (v or "").strip() for k, v in m.groupdict().items()}
                return MatchResult(skill, slots)

    # Pass 2: the utterance matches a slot-bearing trigger's stem (slot omitted),
    # so the skill is recognised with no slots and the engine elicits them.
    key = _word_key(text)
    for skill in skills:
        for trigger in skill.triggers:
            stem = _trigger_stem(trigger)
            if stem is not None and key == _word_key(stem):
                return MatchResult(skill, {})

    return None
