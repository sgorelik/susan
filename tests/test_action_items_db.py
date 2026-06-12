"""DB tests for action item persistence."""
from __future__ import annotations

import pytest

import db


@pytest.mark.asyncio
async def test_action_items_upsert_and_status() -> None:
    await db.init_db()
    channel = "C-action-test"

    saved = await db.upsert_action_items(
        channel,
        [
            {
                "text": "Ship feature X",
                "assignee_slack_id": "U111",
                "status": "open",
                "source": "slack",
            }
        ],
    )
    assert len(saved) == 1
    item_id = saved[0]["id"]

    active = await db.list_active_action_items(channel)
    assert len(active) == 1
    assert active[0]["text"] == "Ship feature X"

    updated = await db.update_action_item_status(
        item_id, channel, "done", note="merged Friday", updated_by="U222"
    )
    assert updated is not None
    assert updated["status"] == "done"

    active_after = await db.list_active_action_items(channel)
    assert active_after == []


@pytest.mark.asyncio
async def test_digest_for_thread_lookup() -> None:
    await db.init_db()
    channel = "C-digest-test"
    digest_id = await db.create_action_item_digest(
        channel,
        message_ts="1111.2222",
        thread_root_ts="1111.2222",
        created_by="U1",
        range_label="last week",
        since_d="2026-01-01",
        until_d="2026-01-07",
    )
    assert digest_id
    found = await db.get_digest_for_thread(channel, "1111.2222")
    assert found is not None
    assert found["id"] == digest_id


@pytest.mark.asyncio
async def test_action_items_registry_round_trip() -> None:
    await db.init_db()
    await db.set_action_items_registry("sheet-xyz", "U-owner")
    reg = await db.get_action_items_registry()
    assert reg is not None
    assert reg["spreadsheet_id"] == "sheet-xyz"
    assert reg["created_by_slack_user_id"] == "U-owner"
    await db.upsert_channel_sheet_tab("C1", "team-tech", 12345, "sheet-xyz")
    tab = await db.get_channel_sheet_tab("C1")
    assert tab is not None
    assert tab["tab_title"] == "team-tech"
    assert tab["sheet_gid"] == 12345
