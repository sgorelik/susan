"""Hello World skill — a minimal, stateless greeting.

This is the reference implementation for new Susan skills: it shows the smallest
useful shape a skill can take. The skill is registered under the name
``hello-world``, triggers on the phrases "hello" and "hi susan"
(case-insensitive), and always replies with a fixed greeting. It takes no
parameters or slots and makes no external API calls, so every invocation is
fully independent (stateless).

It mirrors this generic skill spec::

    skill:
      name: hello-world
      description: Greets the user with a Hello World message.
      triggers:
        - "hello"
        - "hi susan"
      response:
        text: "Hello, World! I'm Susan, and I'm ready to help."
"""
from __future__ import annotations

# Skill identity — matches ``skill.name`` in the spec.
HELLO_WORLD_SKILL_NAME = "hello-world"

# Trigger phrases (``skill.triggers``). Compared case-insensitively against the
# whitespace-trimmed slash-command text.
HELLO_WORLD_TRIGGERS: tuple[str, ...] = ("hello", "hi susan")

# Exact response (``skill.response.text``) — must match the spec precisely.
HELLO_WORLD_RESPONSE = "Hello, World! I'm Susan, and I'm ready to help."


def matches_hello_world(text: str) -> bool:
    """Return True if ``text`` is a Hello World trigger phrase (case-insensitive)."""
    return (text or "").strip().lower() in HELLO_WORLD_TRIGGERS


def handle_hello_world(text: str) -> str | None:
    """Return the greeting for a trigger phrase, else ``None``.

    Pure and stateless: the same input always yields the same output and no
    external calls or session state are involved.
    """
    if matches_hello_world(text):
        return HELLO_WORLD_RESPONSE
    return None
