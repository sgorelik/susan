"""Ask the roadmap board questions in Slack, and turn decisions into board items.

Skills (slash phrasing):
  /susan board status [last 7 days]      — weekly digest: shipped, moved, blocked
  /susan board pack [last 14 days]       — the board / investor update
  /susan board risks                     — P0/P1 that would stop a pilot handover
  /susan board claims                    — what is safe to tell a customer today
  /susan customer ask <name>             — what we owe a customer, and what we wait on
  /susan roadmap <question>              — anything else, answered from the board
  /susan roadmap add <decision>          — draft a roadmap issue, preview before filing

Read-only by default. `roadmap add` files an issue only after you approve it, and
Susan never merges anything.
"""
from __future__ import annotations

import json
import os
import re
from inspect import cleandoc
from typing import Literal

from db import create_user_draft, get_github_token

from app.channel_surface import parse_surface_time_window
from app.claude_client import call_claude
from app.config import SUSAN_VOICE, logger
from app.github_graphql import (
    GithubProjectScopeError,
    add_issue_to_project,
    board_write_enabled,
    set_project_single_select,
)
from app.github_http import github_create_issue
from app.roadmap_context import (
    Board,
    assemble_context,
    load_board,
    load_epic_block,
    load_topic_block,
    load_window_activity,
    render_board_arithmetic,
    render_board_digest,
    roadmap_configured,
    roadmap_issue_repo,
    roadmap_lookback_days,
    roadmap_phase_field,
    roadmap_priority_field,
    roadmap_status_field,
)
from app.slack_api import (
    fetch_slack_history,
    markdownish_to_slack_mrkdwn,
    notify_user_ephemeral,
    post_pr_summary_to_channel,
)
from app.weekly_context import strip_weekly_status_auto_post_flags

RoadmapKind = Literal["status", "pack", "risks", "claims", "customer", "ask", "add"]

# Phrase parsers — longer / more specific first, and `add` before everything so
# "roadmap add …" is never read as a question about the roadmap.
_ADD_PREFIXES = (
    "roadmap add",
    "board add",
    "add roadmap item",
    "add to the roadmap",
    "add to roadmap",
    "new roadmap item",
    "capture roadmap",
    "file roadmap issue",
)

_STATUS_PREFIXES = (
    "state of the plan",
    "what changed on the board",
    "weekly roadmap digest",
    "roadmap digest",
    "board digest",
    "roadmap status",
    "board status",
)

_PACK_PREFIXES = (
    "board pack",
    "roadmap pack",
    "investor update",
    "investor pack",
    "board update",
    "board deck",
)

_RISK_PREFIXES = (
    "risk before the pilot",
    "pilot readiness",
    "roadmap risks",
    "roadmap risk",
    "board risks",
    "board risk",
    "pilot risks",
    "pilot risk",
)

_CLAIMS_PREFIXES = (
    "claims i can make",
    "claims i can safely make",
    "what can i safely say",
    "what can i say",
    "what can we say",
    "safe claims",
    "board claims",
    "roadmap claims",
    "customer claims",
)

_CUSTOMER_PREFIXES = (
    "what do we owe",
    "customer commitments",
    "customer ask",
    "commitments for",
    "customer",
)

_ASK_PREFIXES = (
    "ask the roadmap",
    "ask the board",
    "roadmap",
    "board",
)


def _normalize_for_prefix(text: str) -> str:
    """Let `board-status` match `board status` — people arrive with the old skill names.

    Substitution is length-preserving so remainder offsets still line up with the raw text.
    """
    return re.sub(r"[-_]", " ", (text or "").lower())


def _match_prefix(text: str, prefixes: tuple[str, ...]) -> str | None:
    raw = (text or "").strip().lstrip("/").strip()
    if not raw:
        return None
    lower = _normalize_for_prefix(raw)
    for prefix in prefixes:
        if lower == prefix:
            return ""
        if lower.startswith(prefix + " "):
            return raw[len(prefix) :].strip()
    return None


def parse_roadmap_command(text: str) -> tuple[RoadmapKind, str] | None:
    """(kind, remainder) for any roadmap phrasing, else None."""
    for kind, prefixes in (
        ("add", _ADD_PREFIXES),
        ("status", _STATUS_PREFIXES),
        ("pack", _PACK_PREFIXES),
        ("risks", _RISK_PREFIXES),
        ("claims", _CLAIMS_PREFIXES),
        ("customer", _CUSTOMER_PREFIXES),
        ("ask", _ASK_PREFIXES),
    ):
        remainder = _match_prefix(text, prefixes)
        if remainder is None:
            continue
        if kind == "customer" and not remainder:
            # "customer" on its own is not a question Susan can answer.
            continue
        if kind == "ask" and not remainder:
            return "status", ""  # bare `/susan board` → this week's digest
        return kind, remainder  # type: ignore[return-value]
    return None


ROADMAP_ACKS: dict[str, str] = {
    "status": (
        "Got it — Susan is reading the *roadmap board*, the plan-of-record epic and the last "
        "window of GitHub activity, then will send you a private digest of what shipped, what "
        "only moved, and what's blocked."
    ),
    "pack": (
        "Got it — Susan is building a *board update* from the roadmap board: shipped since last "
        "time, current risks, and an honest read on anything Partial or Done (dev)."
    ),
    "risks": (
        "Got it — Susan is ranking *P0/P1 roadmap risk* to a pilot handover from the board and "
        "the epic. Private answer coming."
    ),
    "claims": (
        "Got it — Susan is separating what you can describe as *live today* from what is only "
        "*Partial* or *Done (dev)*, with issue numbers for each."
    ),
    "customer": (
        "Got it — Susan is searching the roadmap repos for everything tied to that customer: "
        "commitments, current status, and what we're waiting on them for."
    ),
    "ask": (
        "Got it — Susan is reading the *roadmap board* and the plan-of-record epic to answer "
        "that. Private answer coming."
    ),
    "add": (
        "Got it — Susan is checking whether the roadmap already covers this, then will draft a "
        "roadmap issue for you to review *before* anything is filed."
    ),
}

# The house rules, in the model's own instructions. This is the part that keeps a
# status summary honest enough to repeat to a customer or an investor.
ROADMAP_DOCTRINE = cleandoc(
    """
    The board is the plan of record — not any deck, sheet or summary. Its Status words were
    chosen so status stays honest rather than optimistic, and they mean specific things:

    - *Todo* — not started.
    - *In Progress* — someone is actively working it right now.
    - *Partial* — some pieces are in place, usually proven on dev; the rest is outstanding.
      This does NOT mean nearly done.
    - *Done (dev)* — working in the development environment. The pilot or production
      re-apply has not happened.
    - *Blocked* — waiting on a prerequisite or an external party; the blocker is named on the issue.
    - *Done* — complete and verified. Nothing else outstanding.

    Rules you must follow:
    - Treat *Partial* and *Done (dev)* as NOT done. Never round them up.
    - Quote the Status word verbatim. Never paraphrase it as "nearly done" or "basically shipped".
    - Cite the issue reference (`repo#number`) for every claim about status. No reference, no claim.
    - Use the figures under "Board arithmetic" exactly as given; never recount or estimate them.
    - If the board and the issue discussion disagree, say so plainly — that is a finding, not noise.
    - Distinguish what shipped (merged PRs, closed issues, Status Done) from what only moved status.
    - If the evidence does not cover something, say what you could not see instead of inferring it.
    - You are read-only. Never claim to have changed, closed, merged or filed anything.
    """
)

_SLACK_FORMAT = cleandoc(
    """
    Output Slack mrkdwn only: single *asterisks* for bold, `code` for issue refs, no markdown
    headings and no tables. Bullets over paragraphs. No preamble like "Here is…".
    """
)


def _system_prompt(kind: RoadmapKind) -> str:
    common = cleandoc(
        f"""
        You are Susan, reporting on the engineering roadmap for a commercial audience. {SUSAN_VOICE}

        {_SLACK_FORMAT}

        {ROADMAP_DOCTRINE}
        """
    )
    if kind == "status":
        return common + "\n\n" + cleandoc(
            """
            Write the weekly roadmap digest for the window given, grouped by Phase, in this order
            and nothing else. Keep it under one screen.

            *Roadmap — <window>*
            *Shipped* — merged and verified only. Cite issue and PR numbers.
            *Moved but not done* — status changed only. Say what remains for each.
            *Blocked* — name the blocker and who owns unblocking it.
            *Needs a decision from us* — anything waiting on a call we owe someone.

            Omit a section only if it is genuinely empty, and say so in one line if it is.
            """
        )
    if kind == "pack":
        return common + "\n\n" + cleandoc(
            """
            Write the board / investor update. Assume it will be read by people outside
            engineering who will repeat it, so every claim has to survive being checked.

            *Board update — <window>*
            *Shipped since last time* — verified delivery, with issue and PR numbers.
            *In flight* — what is actively moving and when it lands, per the board.
            *Honest read* — every item that is Partial or Done (dev), what is actually true
            today, and what is left. This section exists so we do not overstate; do not soften it.
            *Risks* — ranked, with the named blocker and owner.
            *Asks* — decisions or resources needed from the board.
            """
        )
    if kind == "risks":
        return common + "\n\n" + cleandoc(
            """
            Answer one question: what would stop us handing a working environment to a pilot
            customer?

            Consider every P0 and P1 item that is Blocked, Partial, Done (dev) or Todo.
            Rank by what breaks first, not by priority label alone, and for each give:
            the issue ref, the verbatim Status, what specifically is missing, and the
            dependency or party it waits on.

            Finish with *What I would fix first* — three items, in order, and why that order.
            """
        )
    if kind == "claims":
        return common + "\n\n" + cleandoc(
            """
            Split the board into what is safe to say and what is not.

            *Live today — safe to describe to a customer*
            Only items whose Status is exactly Done. Cite the issue ref for each.
            *Not yet — do not claim*
            Everything that is Partial or Done (dev), with the verbatim Status and one line on
            what is actually true today versus what someone might assume.
            *Say it like this*
            For the two or three most likely to be overstated, give a sentence that is accurate
            and still useful to a salesperson.
            """
        )
    if kind == "customer":
        return common + "\n\n" + cleandoc(
            """
            Answer for the named customer only, using the searched issues and the board.

            *What we committed to* — each commitment, with the issue ref and where it was agreed
            (call, thread, issue comment) when the evidence shows it.
            *Where each piece stands* — verbatim Status from the board; flag anything the board
            and the discussion disagree on.
            *What we are waiting on them for* — their side of the dependency, with dates if named.
            *What I could not find* — gaps, so nobody assumes silence means done.
            """
        )
    return common + "\n\n" + cleandoc(
        """
        Answer the user's question directly from the evidence, leading with the answer rather
        than the method. Cite issue refs throughout. If the question implies a customer promise
        or a date, be explicit about what is and is not supported by the board today, and name
        the specific items that would have to close first.
        """
    )


def _max_tokens(kind: RoadmapKind) -> int:
    default = 6000 if kind == "pack" else 4096
    try:
        val = int((os.environ.get("SUSAN_ROADMAP_MAX_TOKENS") or "").strip() or default)
    except ValueError:
        val = default
    return max(1500, min(16000, val))


async def _load_context(
    kind: RoadmapKind, token: str, *, remainder: str, since_d: str, until_d: str
) -> tuple[Board, str]:
    """Board plus the extra evidence each question needs."""
    board = await load_board(token)
    blocks = [render_board_arithmetic(board), render_board_digest(board)]

    if kind in ("status", "pack", "ask"):
        blocks.append(await load_epic_block(token))
        blocks.append(await load_window_activity(token, since_d, until_d))
    elif kind in ("risks", "claims"):
        blocks.append(await load_epic_block(token))
    elif kind == "customer":
        blocks.append(await load_topic_block(token, remainder))
    return board, assemble_context(blocks)


def _title(kind: RoadmapKind, board: Board, *, range_label: str, subject: str) -> str:
    base = {
        "status": f"Roadmap digest — {range_label}",
        "pack": f"Board update — {range_label}",
        "risks": "Roadmap risk to a pilot handover",
        "claims": "What we can claim today",
        "customer": f"Roadmap commitments — {subject}",
        "ask": f"Roadmap — {subject[:60]}" if subject else "Roadmap",
    }[kind]
    return f"{base} · {board.project.title}"


async def process_roadmap(
    kind: RoadmapKind,
    remainder: str,
    channel: str,
    user: str,
    thread_ts: str | None,
    response_url: str | None,
    *,
    auto_publish: bool = False,
) -> None:
    """Answer a roadmap question privately (or post to channel with --no-approval)."""
    cleaned, flagged_auto_post = strip_weekly_status_auto_post_flags(remainder)
    post_to_channel = auto_publish or flagged_auto_post
    ready, config_err = roadmap_configured()
    if not ready:
        await notify_user_ephemeral(channel, user, config_err or "", None, response_url)
        return

    since_d, until_d, range_label = parse_surface_time_window(
        cleaned if kind in ("status", "pack") else "",
        default_days=roadmap_lookback_days(),
    )

    try:
        token = await get_github_token(user)
    except ValueError as e:
        await notify_user_ephemeral(channel, user, str(e), None, response_url)
        return

    try:
        board, context = await _load_context(
            kind, token, remainder=cleaned, since_d=since_d, until_d=until_d
        )
    except GithubProjectScopeError as e:
        await notify_user_ephemeral(channel, user, str(e), None, response_url)
        return
    except Exception as e:
        logger.exception("Roadmap context load failed kind=%s", kind)
        await notify_user_ephemeral(
            channel, user, f"Susan could not read the roadmap board: {e}", None, response_url
        )
        return

    question = cleaned or {
        "status": "What changed in the last window?",
        "pack": "What goes in the board update?",
        "risks": "What would stop a pilot handover?",
        "claims": "What can we safely claim today?",
        "customer": "What do we owe this customer?",
        "ask": "Summarize the state of the plan.",
    }[kind]
    user_prompt = (
        f"Question: {question}\n"
        f"Window: {range_label}\n"
        f"Board: {board.project.title} (project #{board.project.number}) {board.project.url}\n"
        f"Asked by Slack user <@{user}>\n\n"
        f"--- ROADMAP EVIDENCE ---\n{context}"
    )

    try:
        answer = await call_claude(
            _system_prompt(kind),
            user_prompt,
            max_tokens=_max_tokens(kind),
            action=f"roadmap_{kind}",
            model_route="commercial",
        )
    except Exception as e:
        logger.exception("Roadmap Claude call failed kind=%s", kind)
        await notify_user_ephemeral(channel, user, f"Susan error: {e}", None, response_url)
        return

    answer = markdownish_to_slack_mrkdwn((answer or "").strip())
    if not answer:
        answer = f"_No roadmap answer for {range_label}._"
    header = _title(kind, board, range_label=range_label, subject=cleaned)
    body = f"*{header}*\n{answer}" if not answer.startswith("*") else answer

    if post_to_channel:
        try:
            # Splits long answers across sections; a board pack easily exceeds one message.
            await post_pr_summary_to_channel(channel, thread_ts, header, answer)
            await notify_user_ephemeral(
                channel,
                user,
                f"✓ Posted the *{kind}* roadmap answer to the channel (`--no-approval`).",
                None,
                response_url,
            )
        except Exception as e:
            logger.exception("Roadmap channel post failed")
            await notify_user_ephemeral(
                channel, user, f"Could not post to the channel: {e}", None, response_url
            )
        return

    await notify_user_ephemeral(channel, user, body, None, response_url)


# --- Turning a decision into a board item -----------------------------------

_ADD_SYSTEM = cleandoc(
    f"""
    You are Susan, drafting a roadmap issue so a decision becomes real work on the board.
    {SUSAN_VOICE}

    {ROADMAP_DOCTRINE}

    First check the board for an item that already covers this. If one does, say so instead of
    inventing a duplicate.

    Output ONLY this structure, in this order:

    Duplicate: none
    Title: <short, specific, outcome-shaped>
    Status: <one of the board's Status options>
    Phase: <one of the board's Phase options>
    Priority: <one of the board's Priority options>
    Description:
    *Why this is needed*
    <the decision or gap, and what breaks if we skip it — reference the conversation>
    *What done looks like*
    <acceptance criteria as a checklist, each item independently verifiable>
    *Dependencies*
    <prerequisites, other issue refs, external parties — or "none known">

    If the roadmap already covers it, set `Duplicate:` to the issue ref plus a short reason and
    still fill in the rest as a proposed amendment. Choose Status / Phase / Priority only from
    the option lists given in the evidence — never invent a value. Default Status to the board's
    not-started option unless the conversation shows work has begun.
    """
)


def _parse_add_draft(text: str) -> dict[str, str]:
    """Pull the labelled fields out of the model's draft."""
    out = {"duplicate": "", "title": "", "status": "", "phase": "", "priority": "", "body": ""}
    for key, label in (
        ("duplicate", "Duplicate"),
        ("title", "Title"),
        ("status", "Status"),
        ("phase", "Phase"),
        ("priority", "Priority"),
    ):
        m = re.search(rf"^{label}:\s*(.+)$", text or "", re.M)
        if m:
            out[key] = m.group(1).strip()
    desc = re.search(r"^Description:\s*$", text or "", re.M) or re.search(
        r"^Description:\s*", text or "", re.M
    )
    out["body"] = (text[desc.end() :].strip() if desc else (text or "").strip())
    if out["duplicate"].casefold() in ("none", "no", "n/a", "-"):
        out["duplicate"] = ""
    return out


def _validate_option(board: Board, field_name: str, value: str) -> tuple[str, str | None]:
    """Snap a proposed field value to a real board option; warn when it doesn't fit."""
    options = board.field_options(field_name)
    if not value:
        return "", None
    if not options:
        return value, None
    match = next((o for o in options if o.casefold() == value.casefold()), "")
    if match:
        return match, None
    return value, (
        f"`{field_name}` value `{value}` is not an option on the board "
        f"(options: {', '.join(options)}) — a human will need to set it."
    )


async def process_roadmap_add(
    remainder: str,
    channel: str,
    user: str,
    thread_ts: str | None,
    response_url: str | None,
) -> None:
    """Draft a roadmap issue from a decision and show it before anything is filed."""
    ready, config_err = roadmap_configured()
    if not ready:
        await notify_user_ephemeral(channel, user, config_err or "", None, response_url)
        return
    repo = roadmap_issue_repo()
    if not repo:
        await notify_user_ephemeral(
            channel,
            user,
            "No repo to file roadmap issues in. Set `SUSAN_ROADMAP_ISSUE_REPO` (or "
            "`GITHUB_ISSUES_REPO`) on the server.",
            None,
            response_url,
        )
        return

    try:
        token = await get_github_token(user)
    except ValueError as e:
        await notify_user_ephemeral(channel, user, str(e), None, response_url)
        return

    try:
        board = await load_board(token)
    except GithubProjectScopeError as e:
        await notify_user_ephemeral(channel, user, str(e), None, response_url)
        return
    except Exception as e:
        logger.exception("Roadmap add: board load failed")
        await notify_user_ephemeral(
            channel, user, f"Susan could not read the roadmap board: {e}", None, response_url
        )
        return

    convo = ""
    try:
        convo = await fetch_slack_history(channel, thread_ts, user)
    except Exception as e:
        logger.warning("Roadmap add: Slack history unavailable: %s", e)

    status_field = roadmap_status_field()
    phase_field = roadmap_phase_field()
    priority_field = roadmap_priority_field()
    options_block = "\n".join(
        f"{name} options: {', '.join(board.field_options(name)) or '(free text)'}"
        for name in (status_field, phase_field, priority_field)
    )
    context = assemble_context(
        [
            f"### Board field options\n{options_block}",
            render_board_digest(board),
            f"### Slack conversation\n{convo or '_(no conversation context)_'}",
        ]
    )
    user_prompt = (
        f"The decision to capture: {remainder or '(see the Slack conversation)'}\n"
        f"Target repo for the issue: {repo}\n"
        f"Board: {board.project.title} (project #{board.project.number})\n\n"
        f"--- ROADMAP EVIDENCE ---\n{context}"
    )

    try:
        draft = await call_claude(
            _ADD_SYSTEM,
            user_prompt,
            max_tokens=_max_tokens("add"),
            action="roadmap_add",
            model_route="commercial",
        )
    except Exception as e:
        logger.exception("Roadmap add Claude call failed")
        await notify_user_ephemeral(channel, user, f"Susan error: {e}", None, response_url)
        return

    parsed = _parse_add_draft(draft or "")
    if not parsed["title"]:
        await notify_user_ephemeral(
            channel,
            user,
            "Susan could not draft a roadmap issue from that. Add a sentence describing the "
            "decision, or run it in the thread where it was agreed.",
            None,
            response_url,
        )
        return

    warnings: list[str] = []
    for key, field_name in (
        ("status", status_field),
        ("phase", phase_field),
        ("priority", priority_field),
    ):
        parsed[key], warn = _validate_option(board, field_name, parsed[key])
        if warn:
            warnings.append(warn)

    meta = {
        "repo": repo,
        "title": parsed["title"],
        "body": parsed["body"],
        "status": parsed["status"],
        "phase": parsed["phase"],
        "priority": parsed["priority"],
        "duplicate": parsed["duplicate"],
        "channel_id": channel,
        "thread_ts": thread_ts,
    }
    draft_id = await create_user_draft(user, "roadmap_add", json.dumps(meta, ensure_ascii=False))

    fields_line = " · ".join(
        f"{label}: {parsed[key] or '—'}"
        for key, label in (
            ("status", status_field),
            ("phase", phase_field),
            ("priority", priority_field),
        )
    )
    notes: list[str] = []
    if parsed["duplicate"]:
        notes.append(
            f"⚠️ *Possible duplicate:* {parsed['duplicate']} — check before filing."
        )
    notes.extend(f"⚠️ _{w}_" for w in warnings)
    if board_write_enabled():
        notes.append(
            f"On approval Susan files the issue in `{repo}` *and* adds it to "
            f"*{board.project.title}* with those field values."
        )
    else:
        notes.append(
            f"On approval Susan files the issue in `{repo}`. Adding it to the board is off "
            "(`SUSAN_ROADMAP_BOARD_WRITE`), so the proposed fields go in the issue body for a "
            "human to set."
        )
    preview = f"{parsed['title']}\n\n{fields_line}\n\n{parsed['body']}"
    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Susan preview — roadmap issue*\n_(Only visible to you. Nothing is filed "
                "until you approve.)_\n" + "\n".join(notes),
            },
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"```{preview[:2800]}{'…' if len(preview) > 2800 else ''}```"},
        },
        {
            "type": "actions",
            "block_id": f"susan_roadmap_add_{channel}_{thread_ts or 'none'}",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "✓ File roadmap issue"},
                    "style": "primary",
                    "action_id": "approve_roadmap_add",
                    "value": draft_id,
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "✗ Cancel"},
                    "action_id": "cancel_susan",
                    "value": draft_id,
                },
            ],
        },
    ]
    await notify_user_ephemeral(
        channel, user, "Susan drafted a roadmap issue for your review", blocks, response_url
    )


def _issue_body_with_fields(meta: dict) -> str:
    """Issue body plus the proposed board fields, so the row can be set by hand if needed."""
    body = (meta.get("body") or "").strip()
    proposed = [
        f"{label}: {meta.get(key) or '—'}"
        for key, label in (
            ("status", roadmap_status_field()),
            ("phase", roadmap_phase_field()),
            ("priority", roadmap_priority_field()),
        )
    ]
    lines = [body, "", "---", "Proposed board fields: " + " · ".join(proposed)]
    if meta.get("duplicate"):
        lines.append(f"Possible duplicate flagged when drafting: {meta['duplicate']}")
    lines.append("_Filed from Slack via Susan after human review._")
    return "\n".join(lines)


async def publish_roadmap_issue(meta: dict, slack_user_id: str) -> str:
    """File the approved roadmap issue and, when enabled, put it on the board."""
    repo = (meta.get("repo") or "").strip()
    title = (meta.get("title") or "").strip()
    if not repo or not title:
        return "Roadmap issue not filed — the draft was missing a repo or title."
    token = await get_github_token(slack_user_id)
    issue = await github_create_issue(repo, title, _issue_body_with_fields(meta), token)
    url = issue.get("html_url") or f"{repo} issue"
    node_id = issue.get("node_id") or ""

    if not board_write_enabled():
        return f"Roadmap issue filed: {url} (board row not created — board writes are off)."
    if not node_id:
        return f"Roadmap issue filed: {url} (no node id returned, so it was not added to the board)."

    try:
        board = await load_board(token)
        item_id = await add_issue_to_project(board.project, node_id, token)
        if not item_id:
            return f"Roadmap issue filed: {url} — but GitHub did not return a board item id."
        applied: list[str] = []
        for key, field_name in (
            ("status", roadmap_status_field()),
            ("phase", roadmap_phase_field()),
            ("priority", roadmap_priority_field()),
        ):
            value = (meta.get(key) or "").strip()
            if not value:
                continue
            field = next(
                (f for n, f in board.fields.items() if n.casefold() == field_name.casefold()),
                None,
            )
            if not field or not field.options:
                continue
            try:
                await set_project_single_select(board.project, item_id, field, value, token)
                applied.append(f"{field_name}={value}")
            except Exception as e:
                logger.warning("Roadmap field set failed %s=%s: %s", field_name, value, e)
        suffix = f" with {', '.join(applied)}" if applied else ""
        return f"Roadmap issue filed: {url} — added to {board.project.title}{suffix}."
    except Exception as e:
        logger.exception("Roadmap board write failed after filing issue")
        return (
            f"Roadmap issue filed: {url} — but Susan could not add it to the board ({e}). "
            "Add the row by hand."
        )
