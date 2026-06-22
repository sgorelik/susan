"""Google Sheets ledger for action items — one spreadsheet, one tab per Slack channel."""
from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import quote

import httpx

from db import (
    ACTION_ITEM_ACTIVE_STATUSES,
    ACTION_ITEM_TERMINAL_STATUSES,
    get_action_items_registry,
    list_action_items_for_sheet,
    set_action_items_registry,
    upsert_action_items,
    upsert_channel_sheet_tab,
    get_channel_sheet_tab,
    user_has_google_tokens,
)
from db import get_valid_access_token

from app.config import logger
from app.slack_api import (
    resolve_slack_user_from_sheet_cell,
    slack_api_conversation_channel_name,
    slack_build_user_lookup,
    slack_fetch_workspace_members,
    slack_members_by_id,
    slack_user_label_from_member,
)

SHEETS_API = "https://sheets.googleapis.com/v4/spreadsheets"
SHEET_HEADERS = [
    "id",
    "task",
    "assignee",
    "status",
    "status_note",
    "source",
    "created_at",
    "updated_at",
    "updated_by",
]
_DEFAULT_TITLE = "Susan Action Items"


def spreadsheet_url(spreadsheet_id: str, gid: int | None = None) -> str:
    base = f"https://docs.google.com/spreadsheets/d/{spreadsheet_id}/edit"
    if gid is not None:
        return f"{base}#gid={gid}"
    return base


def sanitize_sheet_tab_title(channel_name: str | None, channel_id: str) -> str:
    """Sheet tab title from Slack channel name (falls back to channel id)."""
    named = (channel_name or "").strip().lstrip("#")
    if named:
        cleaned = re.sub(r"[\[\]*?:/\\]", "", named).strip()
        cleaned = cleaned[:78] or channel_id[:12]
        return f"#{cleaned}" if cleaned and not cleaned.startswith("#") else cleaned
    return channel_id[:12]


def _a1_tab(tab_title: str) -> str:
    """Quote tab name for A1 notation."""
    escaped = tab_title.replace("'", "''")
    return f"'{escaped}'"


async def _sheets_request(
    method: str,
    path: str,
    token: str,
    *,
    json_body: dict | None = None,
    params: dict | None = None,
) -> dict:
    url = f"{SHEETS_API}{path}"
    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.request(
            method,
            url,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=json_body,
            params=params,
        )
    try:
        data = r.json()
    except Exception:
        data = {"raw": r.text}
    if r.status_code >= 400:
        raise RuntimeError(f"Google Sheets API {r.status_code}: {data}")
    return data


async def _create_spreadsheet(token: str, title: str) -> tuple[str, int]:
    """Create workbook with a README tab; return (spreadsheet_id, readme_gid)."""
    body = {
        "properties": {"title": title},
        "sheets": [
            {
                "properties": {
                    "title": "README",
                    "gridProperties": {"frozenRowCount": 1},
                }
            }
        ],
    }
    data = await _sheets_request("POST", "", token, json_body=body)
    sid = data.get("spreadsheetId")
    if not sid:
        raise RuntimeError(f"Sheets create failed: {data}")
    readme_gid = 0
    for sh in data.get("sheets") or []:
        props = sh.get("properties") or {}
        if props.get("title") == "README":
            readme_gid = int(props.get("sheetId", 0))
    readme_rows = [
        SHEET_HEADERS,
        [
            "(Susan)",
            "One tab per Slack channel (#name). Assignee/Updated by are people names — edit freely; Susan maps names back on sync.",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ],
    ]
    await _sheets_request(
        "PUT",
        f"/{sid}/values/{quote(_a1_tab('README') + '!A1', safe='')}",
        token,
        params={"valueInputOption": "RAW"},
        json_body={"range": f"{_a1_tab('README')}!A1", "values": readme_rows},
    )
    return sid, readme_gid


async def _add_channel_tab(token: str, spreadsheet_id: str, tab_title: str) -> int:
    """Add a channel tab with header row; return sheet gid."""
    data = await _sheets_request(
        "POST",
        f"/{spreadsheet_id}:batchUpdate",
        token,
        json_body={
            "requests": [
                {
                    "addSheet": {
                        "properties": {
                            "title": tab_title,
                            "gridProperties": {"frozenRowCount": 1},
                        }
                    }
                }
            ]
        },
    )
    replies = data.get("replies") or []
    gid = int((replies[0].get("addSheet") or {}).get("properties", {}).get("sheetId", 0))
    await _sheets_request(
        "PUT",
        f"/{spreadsheet_id}/values/{quote(_a1_tab(tab_title) + '!A1', safe='')}",
        token,
        params={"valueInputOption": "RAW"},
        json_body={"range": f"{_a1_tab(tab_title)}!A1", "values": [SHEET_HEADERS]},
    )
    return gid


async def _get_tab_gid(token: str, spreadsheet_id: str, tab_title: str) -> int | None:
    meta = await _sheets_request("GET", f"/{spreadsheet_id}", token, params={"fields": "sheets.properties"})
    for sh in meta.get("sheets") or []:
        props = sh.get("properties") or {}
        if props.get("title") == tab_title:
            return int(props.get("sheetId", 0))
    return None


async def ensure_action_items_spreadsheet(slack_user_id: str) -> tuple[str, bool]:
    """Return (spreadsheet_id, created_new). Uses env or DB, else creates in user's Drive."""
    env_id = (os.environ.get("ACTION_ITEMS_SPREADSHEET_ID") or "").strip()
    if env_id:
        reg = await get_action_items_registry()
        if not reg or reg.get("spreadsheet_id") != env_id:
            await set_action_items_registry(env_id, slack_user_id)
        return env_id, False

    reg = await get_action_items_registry()
    if reg and reg.get("spreadsheet_id"):
        return reg["spreadsheet_id"], False

    token = await get_valid_access_token(slack_user_id)
    title = (os.environ.get("ACTION_ITEMS_SPREADSHEET_TITLE") or _DEFAULT_TITLE).strip() or _DEFAULT_TITLE
    sid, _ = await _create_spreadsheet(token, title)
    await set_action_items_registry(sid, slack_user_id)
    logger.info("Created action items spreadsheet %s for user=%s", sid, slack_user_id)
    return sid, True


async def ensure_channel_tab(
    slack_user_id: str,
    spreadsheet_id: str,
    channel_id: str,
    *,
    channel_name: str | None = None,
) -> tuple[str, int]:
    """Ensure channel tab exists; return (tab_title, gid)."""
    existing = await get_channel_sheet_tab(channel_id)
    if existing and existing.get("tab_title"):
        tab_title = existing["tab_title"]
    else:
        name = channel_name or await slack_api_conversation_channel_name(channel_id)
        tab_title = sanitize_sheet_tab_title(name, channel_id)

    if existing and existing.get("tab_title") == tab_title and existing.get("sheet_gid"):
        return tab_title, int(existing["sheet_gid"])

    token = await get_valid_access_token(slack_user_id)
    gid = await _get_tab_gid(token, spreadsheet_id, tab_title)
    if gid is None:
        gid = await _add_channel_tab(token, spreadsheet_id, tab_title)
    await upsert_channel_sheet_tab(channel_id, tab_title, gid, spreadsheet_id)
    return tab_title, gid


def _parse_sheet_row(row: list[Any]) -> dict | None:
    if not row:
        return None
    padded = list(row) + [""] * max(0, len(SHEET_HEADERS) - len(row))
    vals = {SHEET_HEADERS[i]: (padded[i] or "").strip() for i in range(len(SHEET_HEADERS))}
    if vals["id"].lower() == "id" or vals["task"].lower() == "task":
        return None
    if not vals["task"]:
        return None
    # Legacy sheets used assignee_slack_id / updated_by_slack_id headers in the same columns.
    if len(row) >= 3 and not vals["assignee"] and isinstance(row[2], str):
        vals["assignee"] = row[2].strip()
    if len(row) >= 9 and not vals["updated_by"] and isinstance(row[8], str):
        vals["updated_by"] = row[8].strip()
    return vals


def _status_ok(status: str) -> bool:
    s = status.strip().lower()
    return s in ACTION_ITEM_ACTIVE_STATUSES | ACTION_ITEM_TERMINAL_STATUSES


async def import_sheet_rows_to_db(
    channel_id: str,
    rows: list[list[Any]],
    *,
    user_lookup: dict[str, str] | None = None,
) -> int:
    """Apply sheet rows to DB (sheet wins on edits). Returns rows applied."""
    lookup = user_lookup
    if lookup is None:
        lookup = slack_build_user_lookup(await slack_fetch_workspace_members())
    applied = 0
    for row in rows[1:]:
        parsed = _parse_sheet_row(row)
        if not parsed:
            continue
        status = parsed["status"].lower() or "open"
        if not _status_ok(status):
            status = "open"
        assignee_id = resolve_slack_user_from_sheet_cell(parsed["assignee"], lookup)
        updated_by_id = resolve_slack_user_from_sheet_cell(parsed["updated_by"], lookup)
        payload: dict = {
            "text": parsed["task"],
            "assignee_slack_id": assignee_id,
            "status": status,
            "status_note": parsed["status_note"] or None,
            "source": parsed["source"] or "sheet",
            "sync_from_sheet": True,
        }
        if updated_by_id:
            payload["updated_by_slack_user_id"] = updated_by_id
        if parsed["id"]:
            payload["id"] = parsed["id"]
        await upsert_action_items(channel_id, [payload])
        applied += 1
    return applied


async def sync_sheet_to_db(slack_user_id: str, channel_id: str) -> int:
    reg = await get_action_items_registry()
    if not reg:
        return 0
    tab = await get_channel_sheet_tab(channel_id)
    if not tab:
        return 0
    token = await get_valid_access_token(slack_user_id)
    tab_title = tab["tab_title"]
    range_a1 = f"{_a1_tab(tab_title)}!A1:I1000"
    data = await _sheets_request(
        "GET",
        f"/{reg['spreadsheet_id']}/values/{quote(range_a1, safe='')}",
        token,
    )
    rows = data.get("values") or []
    if len(rows) <= 1:
        return 0
    lookup = slack_build_user_lookup(await slack_fetch_workspace_members())
    return await import_sheet_rows_to_db(channel_id, rows, user_lookup=lookup)


async def sync_db_to_sheet(slack_user_id: str, channel_id: str) -> None:
    reg = await get_action_items_registry()
    if not reg:
        return
    tab = await get_channel_sheet_tab(channel_id)
    if not tab:
        return
    items = await list_action_items_for_sheet(channel_id)
    members_by_id = await slack_members_by_id()

    def label(uid: str | None) -> str:
        if not uid:
            return ""
        m = members_by_id.get(uid.strip().upper())
        if m:
            return slack_user_label_from_member(m)
        return uid

    values = [SHEET_HEADERS]
    for it in items:
        values.append(
            [
                it["id"],
                it["text"],
                label(it.get("assignee_slack_id")),
                it.get("status") or "open",
                it.get("status_note") or "",
                it.get("source") or "",
                it.get("created_at") or "",
                it.get("updated_at") or "",
                label(it.get("updated_by_slack_user_id")),
            ]
        )
    token = await get_valid_access_token(slack_user_id)
    tab_title = tab["tab_title"]
    range_a1 = f"{_a1_tab(tab_title)}!A1"
    await _sheets_request(
        "PUT",
        f"/{reg['spreadsheet_id']}/values/{quote(range_a1, safe='')}",
        token,
        params={"valueInputOption": "RAW"},
        json_body={"range": range_a1, "values": values},
    )


def format_google_sheets_user_error(exc: BaseException) -> str:
    """Short Slack-friendly message for common GCP API-not-enabled errors."""
    raw = str(exc)
    if "SERVICE_DISABLED" in raw or "has not been used in project" in raw:
        if "sheets.googleapis.com" in raw or "Google Sheets API" in raw:
            return (
                "Google *Sheets API* is off for your OAuth GCP project. "
                "Enable it: https://console.developers.google.com/apis/api/sheets.googleapis.com/overview "
                "(pick the same project as your `GOOGLE_CLIENT_ID`). Also enable *Google Drive API*, "
                "wait 2–5 minutes, then run `/susan connect google` again."
            )
        if "drive.googleapis.com" in raw or "Google Drive API" in raw:
            return (
                "Google *Drive API* is off for your OAuth GCP project. "
                "Enable it: https://console.developers.google.com/apis/api/drive.googleapis.com/overview "
                "then `/susan connect google` again."
            )
    return (
        "Google Sheet sync failed — enable *Sheets* and *Drive* APIs in the GCP project "
        "that owns your OAuth client, then `/susan connect google` again."
    )


async def sync_action_items_sheet(
    slack_user_id: str,
    channel_id: str,
    *,
    channel_name: str | None = None,
) -> str | None:
    """Ensure spreadsheet + tab, import sheet edits, export DB. Returns tab URL or None."""
    if not await user_has_google_tokens(slack_user_id):
        return None
    try:
        spreadsheet_id, _ = await ensure_action_items_spreadsheet(slack_user_id)
        tab_title, gid = await ensure_channel_tab(
            slack_user_id, spreadsheet_id, channel_id, channel_name=channel_name
        )
        await sync_sheet_to_db(slack_user_id, channel_id)
        await sync_db_to_sheet(slack_user_id, channel_id)
        return spreadsheet_url(spreadsheet_id, gid)
    except Exception as e:
        logger.exception("Action items sheet sync failed")
        raise RuntimeError(format_google_sheets_user_error(e)) from e


async def sync_sheet_after_status_updates(
    slack_user_id: str,
    channel_id: str,
) -> None:
    """Push DB changes to sheet after Slack thread status replies."""
    if not await user_has_google_tokens(slack_user_id):
        return
    try:
        await sync_db_to_sheet(slack_user_id, channel_id)
    except Exception as e:
        logger.warning("Sheet push after status update failed: %s", e)
