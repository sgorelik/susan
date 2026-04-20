"""Google Drive scan for weekly status (linked folders/files)."""
from __future__ import annotations

import json
import os
import re
from collections.abc import Sequence

import httpx

from db import get_valid_access_token, user_has_google_tokens

from app.config import logger

GOOGLE_DRIVE_FOLDER_MIME = "application/vnd.google-apps.folder"
_DRIVE_DOC_URL_RE = re.compile(
    r"https://docs\.google\.com/(?:document|spreadsheets|presentation)/d/([a-zA-Z0-9_-]+)",
    re.I,
)
_DRIVE_FOLDER_URL_RE = re.compile(
    r"https://drive\.google\.com/drive/(?:u/\d+/)?folders/([a-zA-Z0-9_-]+)",
    re.I,
)
_DRIVE_FILE_URL_RE = re.compile(r"https://drive\.google\.com/file/d/([a-zA-Z0-9_-]+)", re.I)
_DRIVE_OPEN_ID_RE = re.compile(r"[?&]id=([a-zA-Z0-9_-]{10,})", re.I)


def extract_google_urls_from_slack_transcript(text: str) -> list[str]:
    """Bare and Slack-wrapped https URLs (deduped)."""
    seen: set[str] = set()
    out: list[str] = []
    for m in re.finditer(r"<(https://[^>|]+)(?:\|[^>]*)?>", text or ""):
        u = m.group(1).replace("&amp;", "&").strip()
        if u not in seen:
            seen.add(u)
            out.append(u)
    for m in re.finditer(r"(https://[^\s<>\[\]()]+)", text or ""):
        u = m.group(1).rstrip(").,;]}\"'")
        u = u.replace("&amp;", "&")
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def parse_google_drive_targets_from_urls(urls: list[str]) -> tuple[list[str], list[str]]:
    """(folder_ids, file_ids) from Google Drive/Docs URLs in channel text."""
    folders: list[str] = []
    files: list[str] = []
    f_seen: set[str] = set()
    d_seen: set[str] = set()
    for raw in urls:
        low = raw.lower()
        if any(x in low for x in ("document/d/", "spreadsheets/d/", "presentation/d/")):
            m = _DRIVE_DOC_URL_RE.search(raw)
            if m:
                fid = m.group(1)
                if fid not in d_seen:
                    d_seen.add(fid)
                    files.append(fid)
            continue
        m = _DRIVE_FOLDER_URL_RE.search(raw)
        if m:
            fid = m.group(1)
            if fid not in f_seen:
                f_seen.add(fid)
                folders.append(fid)
            continue
        m = _DRIVE_FILE_URL_RE.search(raw)
        if m:
            fid = m.group(1)
            if fid not in d_seen:
                d_seen.add(fid)
                files.append(fid)
            continue
        if "drive.google.com" in low:
            m = _DRIVE_OPEN_ID_RE.search(raw)
            if m:
                fid = m.group(1)
                if fid not in d_seen:
                    d_seen.add(fid)
                    files.append(fid)
    return folders, files


def _drive_window_utc(since_d: str, until_d: str) -> tuple[object, object]:
    from datetime import datetime, timezone

    start = datetime.strptime(since_d, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    end = datetime.strptime(until_d, "%Y-%m-%d").replace(
        hour=23, minute=59, second=59, microsecond=999999, tzinfo=timezone.utc
    )
    return start, end


def _drive_modified_in_window(mod_iso: str | None, start: object, end: object) -> bool:
    from datetime import datetime as dt

    if not mod_iso:
        return False
    try:
        t = dt.fromisoformat(mod_iso.replace("Z", "+00:00"))
    except ValueError:
        return False
    return start <= t <= end


def _drive_mime_label(mime: str) -> str:
    if "document" in mime:
        return "Google Doc"
    if "spreadsheet" in mime:
        return "Sheet"
    if "presentation" in mime:
        return "Slides"
    if mime == GOOGLE_DRIVE_FOLDER_MIME:
        return "Folder"
    return "File"


class _WeeklyDriveBudget:
    __slots__ = ("max_calls", "max_hits", "calls", "hits")

    def __init__(self, max_calls: int, max_hits: int) -> None:
        self.max_calls = max_calls
        self.max_hits = max_hits
        self.calls = 0
        self.hits = 0

    def take_call(self) -> bool:
        if self.calls >= self.max_calls:
            return False
        self.calls += 1
        return True

    def take_hit(self) -> bool:
        if self.hits >= self.max_hits:
            return False
        self.hits += 1
        return True


async def _drive_list_children_page(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    folder_id: str,
    page_token: str | None,
) -> tuple[list[dict], str | None]:
    params: dict[str, str] = {
        "q": f"'{folder_id}' in parents and trashed = false",
        "fields": "nextPageToken, files(id,name,mimeType,modifiedTime,webViewLink)",
        "pageSize": "100",
        "supportsAllDrives": "true",
        "includeItemsFromAllDrives": "true",
    }
    if page_token:
        params["pageToken"] = page_token
    r = await client.get(
        "https://www.googleapis.com/drive/v3/files",
        headers=headers,
        params=params,
    )
    if r.status_code != 200:
        logger.warning(
            "Drive files.list failed: status=%s folder=%s body=%s",
            r.status_code,
            folder_id,
            (r.text or "")[:400],
        )
        return [], None
    data = r.json()
    return data.get("files") or [], data.get("nextPageToken")


async def _drive_get_file_meta(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    file_id: str,
) -> dict | None:
    r = await client.get(
        f"https://www.googleapis.com/drive/v3/files/{file_id}",
        headers=headers,
        params={
            "fields": "id,name,mimeType,modifiedTime,webViewLink",
            "supportsAllDrives": "true",
        },
    )
    if r.status_code != 200:
        return None
    return r.json()


async def _drive_walk_folder(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    folder_id: str,
    depth: int,
    max_depth: int,
    start: object,
    end: object,
    budget: _WeeklyDriveBudget,
    out: dict[str, dict],
) -> None:
    if depth > max_depth:
        return
    page_token: str | None = None
    while budget.take_call():
        batch, page_token = await _drive_list_children_page(
            client, headers, folder_id, page_token
        )
        for f in batch:
            mid = f.get("mimeType") or ""
            fid = f.get("id")
            if not fid:
                continue
            if mid == GOOGLE_DRIVE_FOLDER_MIME:
                await _drive_walk_folder(
                    client,
                    headers,
                    fid,
                    depth + 1,
                    max_depth,
                    start,
                    end,
                    budget,
                    out,
                )
            else:
                mod = f.get("modifiedTime")
                if _drive_modified_in_window(mod, start, end) and fid not in out:
                    if budget.take_hit():
                        out[fid] = {
                            "name": (f.get("name") or fid).replace("\n", " "),
                            "mimeType": mid,
                            "modifiedTime": mod or "",
                            "webViewLink": f.get("webViewLink")
                            or f"https://drive.google.com/file/d/{fid}/view",
                        }
        if not page_token:
            break


async def _drive_process_linked_id(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    file_id: str,
    start: object,
    end: object,
    budget: _WeeklyDriveBudget,
    out: dict[str, dict],
    max_depth: int,
) -> None:
    if not budget.take_call():
        return
    meta = await _drive_get_file_meta(client, headers, file_id)
    if not meta:
        return
    mid = meta.get("mimeType") or ""
    if mid == GOOGLE_DRIVE_FOLDER_MIME:
        await _drive_walk_folder(
            client, headers, file_id, 0, max_depth, start, end, budget, out
        )
        return
    mod = meta.get("modifiedTime")
    if _drive_modified_in_window(mod, start, end) and file_id not in out:
        if budget.take_hit():
            out[file_id] = {
                "name": (meta.get("name") or file_id).replace("\n", " "),
                "mimeType": mid,
                "modifiedTime": mod or "",
                "webViewLink": meta.get("webViewLink")
                or f"https://drive.google.com/file/d/{file_id}/view",
            }


async def weekly_status_drive_activity_block(
    slack_user_id: str,
    since_d: str,
    until_d: str,
    slack_digest: str,
    *,
    extra_google_urls: Sequence[str] | None = None,
) -> str:
    """Facts for Claude: Drive files under linked folders / linked files modified in the status window.

    ``extra_google_urls`` adds Google Docs/Drive links (e.g. from Slack *channel bookmarks*)
    in addition to URLs parsed from ``slack_digest``.
    """
    urls = [u for u in extract_google_urls_from_slack_transcript(slack_digest) if "google.com" in u.lower()]
    seen: set[str] = set(urls)
    for raw in extra_google_urls or ():
        u = (raw or "").strip()
        if not u or "google.com" not in u.lower():
            continue
        key = u.split("?", 1)[0] if "drive.google.com" in u.lower() else u
        if key not in seen:
            seen.add(key)
            urls.append(u)

    folders, file_ids = parse_google_drive_targets_from_urls(urls)
    if not folders and not file_ids:
        return ""

    max_folders = max(0, min(25, int(os.environ.get("WEEKLY_DRIVE_MAX_FOLDERS", "10"))))
    max_depth = max(0, min(30, int(os.environ.get("WEEKLY_DRIVE_MAX_DEPTH", "12"))))
    max_hits = max(5, min(500, int(os.environ.get("WEEKLY_DRIVE_MAX_FILES_REPORTED", "120"))))
    max_calls = max(10, min(300, int(os.environ.get("WEEKLY_DRIVE_MAX_API_CALLS", "100"))))
    folders = folders[:max_folders]

    src_note = "URLs from channel messages and channel bookmarks"
    header = (
        "\n---\n### Google Drive "
        f"({src_note}; modifiedTime in UTC within the reporting window)\n"
        f"_Window: {since_d} through {until_d}._\n"
    )

    if not await user_has_google_tokens(slack_user_id):
        return (
            header
            + "Google Drive links appear in the transcript, but Google is not connected for this user. "
            "Run `/susan connect google` so weekly status can summarize file changes (requires Drive metadata scope).\n"
        )

    start, end = _drive_window_utc(since_d, until_d)
    budget = _WeeklyDriveBudget(max_calls, max_hits)
    out: dict[str, dict] = {}
    err: str | None = None

    try:
        token = await get_valid_access_token(slack_user_id)
    except ValueError as e:
        return header + f"(Could not use Google token: {e})\n"

    headers = {"Authorization": f"Bearer {token}"}
    try:
        async with httpx.AsyncClient(timeout=45) as client:
            for fid in folders:
                await _drive_walk_folder(
                    client, headers, fid, 0, max_depth, start, end, budget, out
                )
            for fid in file_ids:
                await _drive_process_linked_id(
                    client, headers, fid, start, end, budget, out, max_depth
                )
    except Exception as e:
        logger.exception("weekly Drive scan failed")
        err = str(e)

    lines = [header]
    if err:
        lines.append(f"_Drive API error: {err}_\n")
    if any(
        x in (err or "").lower()
        for x in ("403", "insufficient", "permission", "access_not_configured")
    ):
        lines.append(
            "If this is a scope issue, ensure the Slack app’s Google OAuth includes "
            "`drive.metadata.readonly`, then revoke and run `/susan connect google` again.\n"
        )

    items = sorted(out.values(), key=lambda x: x.get("modifiedTime") or "")
    if not items and not err:
        lines.append(
            "(No files found with modifiedTime in this window under linked folders/files, "
            "or nothing is accessible to the connected Google account.)\n"
        )
    else:
        for it in items:
            mt = (it.get("modifiedTime") or "")[:19].replace("T", " ")
            lines.append(
                f"- {it['name']} ({_drive_mime_label(it.get('mimeType', ''))}) — modified {mt} UTC — {it.get('webViewLink', '')}"
            )
        lines.append("")
    return "\n".join(lines)
