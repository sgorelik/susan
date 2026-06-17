"""Case-insensitive trigger matching, slot extraction, and duration parsing.

Triggers are plain phrases ("hello", "what time is it") and may embed a single
trailing slot placeholder ("set a timer for {duration}"). Matching is
case-insensitive and tolerant of surrounding words and trailing punctuation.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from app.skills.models import Skill

_SLOT_RE = re.compile(r"\{(\w+)\}")
_WS_RE = re.compile(r"\s+")


def normalize(text: str) -> str:
    """Lower-case, collapse whitespace, and strip surrounding punctuation."""
    t = (text or "").strip().lower()
    t = _WS_RE.sub(" ", t)
    return t.strip(" \t\r\n.!?,;")


@dataclass(frozen=True)
class TriggerMatch:
    skill: Skill
    trigger: str
    slots: dict[str, str]
    missing_slot: str | None
    specificity: int


def _match_one(trigger: str, utterance: str) -> tuple[dict[str, str], str | None, int] | None:
    """Match a single trigger against a normalized utterance.

    Returns ``(slots, missing_slot, specificity)`` or ``None``. ``missing_slot``
    is set when the intent is recognized but a required slot value is absent so
    the engine can elicit it.
    """
    slot_m = _SLOT_RE.search(trigger)

    if not slot_m:
        if utterance == trigger or re.search(rf"\b{re.escape(trigger)}\b", utterance):
            return {}, None, len(trigger)
        return None

    slot_name = slot_m.group(1)
    prefix = trigger[: slot_m.start()].strip()
    suffix = trigger[slot_m.end():].strip()

    # Full match: prefix <value> [suffix].
    pattern = rf"\b{re.escape(prefix)}\s+(?P<val>.+?)"
    if suffix:
        pattern += rf"\s+{re.escape(suffix)}"
    pattern += r"\s*$"
    full = re.search(pattern, utterance)
    if full:
        value = full.group("val").strip(" \t\r\n.!?,;")
        if value:
            return {slot_name: value}, None, len(prefix)

    # Intent recognized but value missing (e.g. "set a timer for"): elicit.
    if utterance == prefix or re.search(rf"\b{re.escape(prefix)}\s*$", utterance):
        return {}, slot_name, len(prefix)

    # Allow dropping a trailing connector word ("set a timer" from "... for").
    stem = re.sub(r"\s+\w+$", "", prefix).strip()
    if stem and (utterance == stem or re.search(rf"\b{re.escape(stem)}\s*$", utterance)):
        return {}, slot_name, len(stem)

    return None


def match(skills: list[Skill], text: str) -> TriggerMatch | None:
    """Return the best matching skill for ``text``, or ``None``.

    When several triggers match, the most specific one wins (longest literal
    match), and a full slot match beats a slot-elicitation match.
    """
    utterance = normalize(text)
    if not utterance:
        return None

    best: TriggerMatch | None = None
    for skill in skills:
        for trigger in skill.triggers:
            result = _match_one(normalize(trigger), utterance)
            if result is None:
                continue
            slots, missing, specificity = result
            candidate = TriggerMatch(skill, trigger, slots, missing, specificity)
            if best is None or _better(candidate, best):
                best = candidate
    return best


def _better(a: TriggerMatch, b: TriggerMatch) -> bool:
    """``a`` beats ``b`` if it is more specific, or equally specific but fully
    matched (no missing slot)."""
    if a.specificity != b.specificity:
        return a.specificity > b.specificity
    a_full = a.missing_slot is None
    b_full = b.missing_slot is None
    if a_full != b_full:
        return a_full
    return False


_DURATION_UNITS = {
    "second": 1, "seconds": 1, "sec": 1, "secs": 1, "s": 1,
    "minute": 60, "minutes": 60, "min": 60, "mins": 60, "m": 60,
    "hour": 3600, "hours": 3600, "hr": 3600, "hrs": 3600, "h": 3600,
    "day": 86400, "days": 86400, "d": 86400,
}
_DURATION_RE = re.compile(r"(\d+|an?|half)\s*([a-z]+)")


def parse_duration(text: str) -> int | None:
    """Parse a spoken duration into total seconds.

    Handles e.g. "5 minutes", "1 hour 30 minutes", "30 seconds", "an hour".
    Returns ``None`` when nothing parseable is found.
    """
    total = 0
    found = False
    for count, unit in _DURATION_RE.findall((text or "").lower()):
        if unit not in _DURATION_UNITS:
            continue
        if count in ("a", "an"):
            qty = 1.0
        elif count == "half":
            qty = 0.5
        else:
            qty = float(count)
        total += int(round(qty * _DURATION_UNITS[unit]))
        found = True
    return total if found else None
