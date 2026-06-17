"""Curated joke and fact pools plus a rotating selector.

The ``tell-joke`` and ``fun-fact`` skills must return different content across
invocations, so :class:`RotatingPool` cycles deterministically through its items
(round-robin) — consecutive calls differ and every item is eventually used.
"""
from __future__ import annotations

import random
from collections.abc import Iterable


class RotatingPool:
    """Yields pool items in rotation so repeats are spread out."""

    def __init__(self, items: Iterable[str], *, shuffle: bool = False, rng: random.Random | None = None):
        self._items = list(items)
        if not self._items:
            raise ValueError("RotatingPool requires at least one item")
        self._index = 0
        if shuffle:
            (rng or random).shuffle(self._items)

    def __len__(self) -> int:
        return len(self._items)

    @property
    def items(self) -> list[str]:
        return list(self._items)

    def next(self) -> str:
        item = self._items[self._index % len(self._items)]
        self._index += 1
        return item


JOKES: tuple[str, ...] = (
    "Why don't scientists trust atoms? Because they make up everything!",
    "I told my computer I needed a break, and now it won't stop sending me KitKat ads.",
    "Why did the scarecrow win an award? Because he was outstanding in his field!",
    "I would tell you a construction joke, but I'm still working on it.",
    "Why don't skeletons fight each other? They don't have the guts.",
    "What do you call fake spaghetti? An impasta!",
    "I'm reading a book about anti-gravity. It's impossible to put down!",
    "Why did the bicycle fall over? Because it was two-tired.",
)

FACTS: tuple[str, ...] = (
    "Honey never spoils — archaeologists have found 3,000-year-old honey that's still edible.",
    "Octopuses have three hearts and blue blood.",
    "A day on Venus is longer than a year on Venus.",
    "Bananas are berries, but strawberries aren't.",
    "Sharks existed before trees did.",
    "The Eiffel Tower can grow more than 15 centimeters taller in summer heat.",
    "Wombats produce cube-shaped poop.",
    "There are more possible games of chess than atoms in the observable universe.",
)


def default_joke_pool() -> RotatingPool:
    return RotatingPool(JOKES)


def default_fact_pool() -> RotatingPool:
    return RotatingPool(FACTS)
