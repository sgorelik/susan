"""Unit tests for roadmap board parsing, honest arithmetic, and issue drafting."""
from __future__ import annotations

import json

from app.config import APPROVE_ACTION_TYPES
from app.github_graphql import BoardItem, ProjectField, ProjectRef
from app.model_routing import COMMERCIAL_ACTIONS
from app.roadmap import (
    ROADMAP_ACKS,
    ROADMAP_DOCTRINE,
    _issue_body_with_fields,
    _parse_add_draft,
    _system_prompt,
    _validate_option,
    parse_roadmap_command,
)
from app.roadmap_context import (
    Board,
    roadmap_configured,
    roadmap_epic_ref,
    roadmap_issue_repo,
    roadmap_owner,
    roadmap_repos,
    render_board_arithmetic,
    render_board_digest,
)
from app.slack_api import detect_action


def _item(
    number: int,
    title: str,
    status: str,
    *,
    phase: str = "W1 prod env",
    priority: str = "P1",
    repo: str = "frontier-one/cloud-infra",
) -> BoardItem:
    return BoardItem(
        title=title,
        kind="issue",
        url=f"https://github.com/{repo}/issues/{number}",
        repo=repo,
        number=number,
        state="OPEN",
        updated_at="2026-08-05T10:00:00Z",
        fields={"Status": status, "Phase": phase, "Priority": priority},
    )


def _board(items: list[BoardItem]) -> Board:
    project = ProjectRef(
        node_id="PVT_1",
        number=4,
        title="Pilot Roadmap",
        url="https://github.com/orgs/frontier-one/projects/4",
    )
    fields = {
        "Status": ProjectField(
            node_id="F_status",
            name="Status",
            options={
                "Todo": "o1",
                "In Progress": "o2",
                "Partial": "o3",
                "Done (dev)": "o4",
                "Blocked": "o5",
                "Done": "o6",
            },
        ),
        "Phase": ProjectField(
            node_id="F_phase", name="Phase", options={"W1 prod env": "p1", "W2 GPU/model": "p2"}
        ),
        "Priority": ProjectField(
            node_id="F_prio", name="Priority", options={"P0": "r0", "P1": "r1", "P2": "r2"}
        ),
    }
    return Board(project, items, fields)


# --- Command parsing --------------------------------------------------------


def test_parse_roadmap_command_kinds() -> None:
    assert parse_roadmap_command("board status") == ("status", "")
    assert parse_roadmap_command("board status last 14 days") == ("status", "last 14 days")
    assert parse_roadmap_command("state of the plan") == ("status", "")
    assert parse_roadmap_command("board pack") == ("pack", "")
    assert parse_roadmap_command("board risks") == ("risks", "")
    assert parse_roadmap_command("what can i say") == ("claims", "")
    assert parse_roadmap_command("customer ask Augur") == ("customer", "Augur")
    assert parse_roadmap_command("what do we owe Augur") == ("customer", "Augur")
    assert parse_roadmap_command("roadmap is streaming live in the UK?") == (
        "ask",
        "is streaming live in the UK?",
    )


def test_parse_roadmap_add_wins_over_generic_ask() -> None:
    assert parse_roadmap_command("roadmap add continuous model delivery") == (
        "add",
        "continuous model delivery",
    )
    assert parse_roadmap_command("board add GPU quota follow-up") == (
        "add",
        "GPU quota follow-up",
    )


def test_parse_roadmap_accepts_the_old_skill_names() -> None:
    """People arrive from the Claude manual typing /board-status and /customer-ask."""
    assert parse_roadmap_command("board-status") == ("status", "")
    assert parse_roadmap_command("board-status last 14 days") == ("status", "last 14 days")
    assert parse_roadmap_command("/board-pack") == ("pack", "")
    assert parse_roadmap_command("customer-ask Augur") == ("customer", "Augur")
    assert parse_roadmap_command("roadmap-add continuous delivery") == (
        "add",
        "continuous delivery",
    )
    assert parse_roadmap_command("board_status") == ("status", "")


def test_hyphens_survive_in_the_remainder() -> None:
    """Normalizing the prefix must not rewrite the argument (repo and customer names)."""
    assert parse_roadmap_command("customer-ask f1-asgardOS") == ("customer", "f1-asgardOS")


def test_parse_roadmap_bare_prefix_is_the_weekly_digest() -> None:
    assert parse_roadmap_command("board") == ("status", "")
    assert parse_roadmap_command("roadmap") == ("status", "")


def test_parse_roadmap_command_ignores_other_commands() -> None:
    for text in ("weekly status", "surface failures", "create issue in org/repo", "customer"):
        assert parse_roadmap_command(text) is None


def test_roadmap_commands_are_not_keyword_actions() -> None:
    """Roadmap phrasing must reach the explicit parser, not detect_action."""
    for text in ("board status", "roadmap add a thing", "customer ask Augur"):
        assert detect_action(text) is None


def test_every_kind_has_an_ack() -> None:
    for kind in ("status", "pack", "risks", "claims", "customer", "ask", "add"):
        assert ROADMAP_ACKS[kind].strip()


def test_roadmap_actions_are_commercial_and_approvable() -> None:
    for kind in ("status", "pack", "risks", "claims", "customer", "ask", "add"):
        assert f"roadmap_{kind}" in COMMERCIAL_ACTIONS
    assert "roadmap_add" in APPROVE_ACTION_TYPES


# --- The doctrine that keeps status honest ----------------------------------


def test_doctrine_forbids_rounding_up_partial_and_done_dev() -> None:
    assert "Partial" in ROADMAP_DOCTRINE and "Done (dev)" in ROADMAP_DOCTRINE
    assert "Never round them up." in ROADMAP_DOCTRINE
    assert "verbatim" in ROADMAP_DOCTRINE
    assert "repo#number" in ROADMAP_DOCTRINE


def test_every_prompt_carries_the_doctrine() -> None:
    for kind in ("status", "pack", "risks", "claims", "customer", "ask"):
        prompt = _system_prompt(kind)  # type: ignore[arg-type]
        assert "Never round them up." in prompt
        assert "read-only" in prompt.casefold()


# --- Board rendering and arithmetic ----------------------------------------


def test_board_arithmetic_counts_only_done_as_done() -> None:
    board = _board(
        [
            _item(1, "Prod VPC", "Done"),
            _item(2, "GPU node", "Done (dev)"),
            _item(3, "Guardrails", "Partial", priority="P0"),
            _item(4, "Seqera pilot", "Blocked", priority="P0"),
            _item(5, "Runbook", "Todo", priority="P2"),
        ]
    )
    text = render_board_arithmetic(board)

    assert "Total items: 5" in text
    assert "Complete and verified (Status exactly 'Done'): 1 of 5" in text
    # Partial + Done (dev) are the two that get overstated — named, with refs.
    assert "overstated (Partial / Done (dev)): 2" in text
    assert "cloud-infra#2 (Done (dev))" in text
    assert "cloud-infra#3 (Partial)" in text
    assert "Blocked: 1 — cloud-infra#4 (Blocked)" in text
    # P1 Done (dev), P0 Partial and P0 Blocked are not done; the P1 Done and P2 Todo are excluded.
    assert "P0/P1 not done: 3" in text
    assert "cloud-infra#5" not in text.split("P0/P1 not done:")[1]


def test_board_digest_groups_by_phase_with_citable_refs() -> None:
    board = _board(
        [
            _item(10, "Prod VPC", "Done", phase="W1 prod env"),
            _item(20, "vLLM on H100", "Partial", phase="W2 GPU/model"),
        ]
    )
    digest = render_board_digest(board)

    assert "Board: Pilot Roadmap (project #4) — 2 items" in digest
    assert "#### Phase: W1 prod env (1 item)" in digest
    assert "#### Phase: W2 GPU/model (1 item)" in digest
    assert "- cloud-infra#20 [Status: Partial] [P1] vLLM on H100" in digest


def test_board_digest_orders_status_by_pipeline_not_alphabet() -> None:
    board = _board(
        [
            _item(1, "Done thing", "Done"),
            _item(2, "Todo thing", "Todo"),
            _item(3, "Blocked thing", "Blocked"),
        ]
    )
    lines = [ln for ln in render_board_digest(board).splitlines() if ln.startswith("- ")]
    assert [ln.split()[1] for ln in lines] == [
        "cloud-infra#2",  # Todo
        "cloud-infra#3",  # Blocked
        "cloud-infra#1",  # Done last
    ]


def test_board_item_ref_and_field_lookup_is_case_insensitive() -> None:
    item = _item(231, "Master epic", "In Progress")
    assert item.ref == "cloud-infra#231"
    assert item.project_field("status") == "In Progress"
    assert item.project_field("nonexistent") == ""
    draft = BoardItem(title="Untracked idea", kind="draft")
    assert draft.ref == "(draft item, no issue)"


# --- Configuration resolution ----------------------------------------------


def test_config_resolution_from_env(monkeypatch) -> None:
    monkeypatch.setenv("SUSAN_ROADMAP_REPOS", "Frontier-One/cloud-infra,Frontier-One/f1-asgardOS")
    monkeypatch.delenv("SUSAN_ROADMAP_ORG", raising=False)
    monkeypatch.setenv("SUSAN_ROADMAP_PROJECT", "Pilot Roadmap")
    monkeypatch.setenv("SUSAN_ROADMAP_EPIC", "cloud-infra#231")
    monkeypatch.delenv("SUSAN_ROADMAP_ISSUE_REPO", raising=False)
    monkeypatch.delenv("GITHUB_ISSUES_REPO", raising=False)

    assert roadmap_repos() == ["frontier-one/cloud-infra", "frontier-one/f1-asgardos"]
    assert roadmap_owner() == "frontier-one"  # inferred from the first repo
    # Short epic names resolve against the configured repos.
    assert roadmap_epic_ref() == ("frontier-one/cloud-infra", 231)
    assert roadmap_issue_repo() == "frontier-one/cloud-infra"
    assert roadmap_configured() == (True, None)


def test_roadmap_not_configured_explains_what_to_set(monkeypatch) -> None:
    monkeypatch.setenv("SUSAN_ROADMAP_REPOS", "Frontier-One/cloud-infra")
    monkeypatch.delenv("SUSAN_ROADMAP_ORG", raising=False)
    monkeypatch.delenv("SUSAN_ROADMAP_PROJECT", raising=False)
    ready, err = roadmap_configured()
    assert not ready
    assert "SUSAN_ROADMAP_PROJECT" in (err or "")


def test_epic_ref_requires_a_number(monkeypatch) -> None:
    monkeypatch.setenv("SUSAN_ROADMAP_EPIC", "cloud-infra")
    assert roadmap_epic_ref() is None
    monkeypatch.setenv("SUSAN_ROADMAP_EPIC", "Frontier-One/cloud-infra#231")
    assert roadmap_epic_ref() == ("frontier-one/cloud-infra", 231)


# --- roadmap add: drafting and validation ----------------------------------


_DRAFT = """Duplicate: none
Title: Continuous delivery path for model and container updates
Status: Todo
Phase: W2 GPU/model
Priority: P1
Description:
*Why this is needed*
Agreed in standup on 6 August: customer environments have no push path.

*What done looks like*
- [ ] Pipeline promotes a signed image to a customer environment
"""


def test_parse_add_draft_splits_fields_from_body() -> None:
    parsed = _parse_add_draft(_DRAFT)
    assert parsed["title"] == "Continuous delivery path for model and container updates"
    assert parsed["status"] == "Todo"
    assert parsed["phase"] == "W2 GPU/model"
    assert parsed["priority"] == "P1"
    assert parsed["duplicate"] == ""  # "none" normalizes to empty
    assert parsed["body"].startswith("*Why this is needed*")
    assert "Title:" not in parsed["body"]


def test_parse_add_draft_keeps_a_flagged_duplicate() -> None:
    parsed = _parse_add_draft("Duplicate: cloud-infra#188 already covers image promotion\nTitle: X")
    assert parsed["duplicate"].startswith("cloud-infra#188")


def test_validate_option_snaps_case_and_warns_on_invented_values() -> None:
    board = _board([_item(1, "x", "Todo")])
    value, warn = _validate_option(board, "Status", "done (DEV)")
    assert value == "Done (dev)" and warn is None

    value, warn = _validate_option(board, "Status", "Nearly there")
    assert value == "Nearly there"
    assert warn is not None and "not an option" in warn

    assert _validate_option(board, "Status", "") == ("", None)


# --- End-to-end command flow (GitHub and Claude stubbed) --------------------


def _stub_roadmap_flow(monkeypatch, *, answer: str = "*Roadmap*\n• cloud-infra#3 is Partial"):
    """Wire process_roadmap to a fake board, fake Claude, and captured Slack output."""
    import app.roadmap as rm

    board = _board([_item(3, "Guardrails", "Partial", priority="P0")])
    captured: dict[str, object] = {}

    async def fake_token(_user: str) -> str:
        return "tok"

    async def fake_load_board(_token: str) -> Board:
        return board

    async def fake_epic(_token: str, **_kw: object) -> str:
        return "### Plan of record: cloud-infra#231 — Pilot roadmap epic"

    async def fake_activity(_token: str, since: str, until: str) -> str:
        return f"### Activity {since} → {until}"

    async def fake_claude(system: str, user: str, **_kw: object) -> str:
        captured["system"] = system
        captured["user"] = user
        return answer

    async def fake_ephemeral(channel, user, text, blocks, response_url, **_kw):
        captured["ephemeral"] = text

    async def fake_channel_post(channel, thread_ts, title, body):
        captured["channel_post"] = f"{title}\n{body}"

    monkeypatch.setattr(rm, "get_github_token", fake_token)
    monkeypatch.setattr(rm, "load_board", fake_load_board)
    monkeypatch.setattr(rm, "load_epic_block", fake_epic)
    monkeypatch.setattr(rm, "load_window_activity", fake_activity)
    monkeypatch.setattr(rm, "call_claude", fake_claude)
    monkeypatch.setattr(rm, "notify_user_ephemeral", fake_ephemeral)
    monkeypatch.setattr(rm, "post_pr_summary_to_channel", fake_channel_post)
    monkeypatch.setenv("SUSAN_ROADMAP_ORG", "frontier-one")
    monkeypatch.setenv("SUSAN_ROADMAP_PROJECT", "Pilot Roadmap")
    return captured


async def test_board_status_answers_privately_with_board_evidence(monkeypatch) -> None:
    from app.roadmap import process_roadmap

    captured = _stub_roadmap_flow(monkeypatch)
    await process_roadmap("status", "last 7 days", "C1", "U1", None, None)

    # Private by default — nothing posted to the channel.
    assert "channel_post" not in captured
    assert "cloud-infra#3 is Partial" in str(captured["ephemeral"])

    prompt = str(captured["user"])
    assert "Board arithmetic" in prompt
    assert "cloud-infra#3 [Status: Partial] [P0]" in prompt
    assert "Plan of record: cloud-infra#231" in prompt
    assert "### Activity" in prompt
    assert "Never round them up." in str(captured["system"])


async def test_no_approval_posts_the_answer_to_the_channel(monkeypatch) -> None:
    from app.roadmap import process_roadmap

    captured = _stub_roadmap_flow(monkeypatch)
    await process_roadmap("status", "last 7 days --no-approval", "C1", "U1", None, None)

    assert "cloud-infra#3 is Partial" in str(captured["channel_post"])
    assert "Posted" in str(captured["ephemeral"])


async def test_scheduled_run_posts_without_the_flag(monkeypatch) -> None:
    from app.roadmap import process_roadmap

    captured = _stub_roadmap_flow(monkeypatch)
    await process_roadmap("status", "last 7 days", "C1", "U1", None, None, auto_publish=True)

    assert "channel_post" in captured


async def test_unconfigured_board_explains_itself_and_calls_nothing(monkeypatch) -> None:
    from app.roadmap import process_roadmap

    captured = _stub_roadmap_flow(monkeypatch)
    monkeypatch.delenv("SUSAN_ROADMAP_PROJECT", raising=False)
    await process_roadmap("status", "", "C1", "U1", None, None)

    assert "SUSAN_ROADMAP_PROJECT" in str(captured["ephemeral"])
    assert "system" not in captured  # no model call on a config error


async def test_missing_read_project_scope_is_reported_not_swallowed(monkeypatch) -> None:
    import app.roadmap as rm
    from app.github_graphql import GithubProjectScopeError
    from app.roadmap import process_roadmap

    captured = _stub_roadmap_flow(monkeypatch)

    async def scope_error(_token: str) -> Board:
        raise GithubProjectScopeError("needs read:project — run /susan connect github")

    monkeypatch.setattr(rm, "load_board", scope_error)
    await process_roadmap("status", "", "C1", "U1", None, None)

    assert "read:project" in str(captured["ephemeral"])


async def test_roadmap_add_previews_and_files_nothing_yet(monkeypatch) -> None:
    """The whole point of `roadmap add`: a draft you approve, not an issue you discover."""
    import db
    import app.roadmap as rm
    from app.roadmap import process_roadmap_add

    await db.init_db()
    captured = _stub_roadmap_flow(monkeypatch, answer=_DRAFT)
    monkeypatch.setenv("SUSAN_ROADMAP_ISSUE_REPO", "frontier-one/cloud-infra")
    monkeypatch.delenv("SUSAN_ROADMAP_BOARD_WRITE", raising=False)

    async def fake_history(_channel, _thread, _user) -> str:
        return "U1: we have no push path into customer environments"

    async def filing_is_a_bug(*_a: object, **_k: object) -> dict:
        raise AssertionError("roadmap add must not file an issue before approval")

    blocks_seen: dict[str, object] = {}

    async def capture_blocks(channel, user, text, blocks, response_url, **_kw):
        blocks_seen["blocks"] = blocks

    monkeypatch.setattr(rm, "fetch_slack_history", fake_history)
    monkeypatch.setattr(rm, "github_create_issue", filing_is_a_bug)
    monkeypatch.setattr(rm, "notify_user_ephemeral", capture_blocks)

    await process_roadmap_add("continuous model delivery", "C1", "U1", None, None)

    blocks = blocks_seen["blocks"]
    assert isinstance(blocks, list)
    buttons = blocks[-1]["elements"]
    assert buttons[0]["action_id"] == "approve_roadmap_add"
    assert buttons[1]["action_id"] == "cancel_susan"
    draft_id = buttons[0]["value"]

    row = await db.get_user_draft(draft_id, "U1")
    assert row is not None and row["kind"] == "roadmap_add"
    meta = json.loads(row["content"])
    assert meta["title"].startswith("Continuous delivery path")
    assert meta["status"] == "Todo" and meta["phase"] == "W2 GPU/model"
    assert meta["repo"] == "frontier-one/cloud-infra"

    # The Slack conversation reached the model, so "as agreed in standup" has context.
    assert "no push path into customer environments" in str(captured["user"])


async def test_publish_roadmap_issue_files_and_reports_the_url(monkeypatch) -> None:
    import app.roadmap as rm
    from app.roadmap import publish_roadmap_issue

    filed: dict[str, object] = {}

    async def fake_token(_user: str) -> str:
        return "tok"

    async def fake_create(repo, title, body, token, **_kw) -> dict:
        filed.update({"repo": repo, "title": title, "body": body})
        return {"html_url": f"https://github.com/{repo}/issues/9", "node_id": "I_9"}

    monkeypatch.setattr(rm, "get_github_token", fake_token)
    monkeypatch.setattr(rm, "github_create_issue", fake_create)
    monkeypatch.delenv("SUSAN_ROADMAP_BOARD_WRITE", raising=False)

    result = await publish_roadmap_issue(
        {
            "repo": "frontier-one/cloud-infra",
            "title": "Continuous delivery path",
            "body": "*Why this is needed*\nNo push path.",
            "status": "Todo",
            "phase": "W2 GPU/model",
            "priority": "P1",
        },
        "U1",
    )
    assert "issues/9" in result
    assert "board row not created" in result  # board writes are off by default
    assert "Proposed board fields" in str(filed["body"])


async def test_publish_roadmap_issue_refuses_an_incomplete_draft() -> None:
    from app.roadmap import publish_roadmap_issue

    result = await publish_roadmap_issue({"repo": "", "title": ""}, "U1")
    assert "not filed" in result


def test_issue_body_carries_proposed_fields_for_a_human(monkeypatch) -> None:
    monkeypatch.delenv("SUSAN_ROADMAP_STATUS_FIELD", raising=False)
    body = _issue_body_with_fields(
        {
            "body": "*Why this is needed*\nNo push path.",
            "status": "Todo",
            "phase": "W2 GPU/model",
            "priority": "P1",
            "duplicate": "cloud-infra#188",
        }
    )
    assert "Proposed board fields: Status: Todo · Phase: W2 GPU/model · Priority: P1" in body
    assert "cloud-infra#188" in body
    assert "after human review" in body
