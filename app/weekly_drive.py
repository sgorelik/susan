"""Google Drive scan for weekly status (linked folders/files)."""
from __future__ import annotations

import json
import os
import re
from collections.abc import Sequence

import httpx

from db import get_valid_access_token, user_has_google_tokens

from app.config import logger

GOOGLE_DRIVE_DOC_MIME = "application/vnd.google-apps.document"
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


def extract_plain_text_from_google_doc(doc: dict) -> str:
    """Flatten Google Docs API document JSON to plain text (paragraphs + tables)."""
    parts: list[str] = []

    def walk(elements: list) -> None:
        for el in elements or []:
            if not isinstance(el, dict):
                continue
            if "paragraph" in el:
                for pe in el["paragraph"].get("elements") or []:
                    if not isinstance(pe, dict):
                        continue
                    tr = pe.get("textRun")
                    if isinstance(tr, dict) and tr.get("content"):
                        parts.append(str(tr["content"]))
            elif "table" in el:
                for row in el["table"].get("tableRows") or []:
                    if not isinstance(row, dict):
                        continue
                    for cell in row.get("tableCells") or []:
                        if isinstance(cell, dict):
                            walk(cell.get("content") or [])
            elif "tableOfContents" in el:
                walk(el["tableOfContents"].get("content") or [])

    walk((doc.get("body") or {}).get("content") or [])
    return "".join(parts).strip()


def _merge_google_urls_for_scan(
    slack_digest: str,
    extra_google_urls: Sequence[str] | None,
) -> list[str]:
    urls = [
        u for u in extract_google_urls_from_slack_transcript(slack_digest) if "google.com" in u.lower()
    ]
    seen: set[str] = set(urls)
    for raw in extra_google_urls or ():
        u = (raw or "").strip()
        if not u or "google.com" not in u.lower():
            continue
        key = u.split("?", 1)[0] if "drive.google.com" in u.lower() else u
        if key not in seen:
            seen.add(key)
            urls.append(u)
    return urls


async def _drive_collect_doc_ids_in_folder(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    folder_id: str,
    depth: int,
    max_depth: int,
    budget: _WeeklyDriveBudget,
    out: set[str],
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
                await _drive_collect_doc_ids_in_folder(
                    client, headers, fid, depth + 1, max_depth, budget, out
                )
            elif mid == GOOGLE_DRIVE_DOC_MIME:
                out.add(fid)
        if not page_token:
            break


async def _fetch_google_doc_plain_text(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    doc_id: str,
) -> tuple[str, str]:
    """Return (title, plain_text) for a Google Doc."""
    meta = await _drive_get_file_meta(client, headers, doc_id)
    title = (meta.get("name") if meta else None) or doc_id
    link = (
        (meta.get("webViewLink") if meta else None)
        or f"https://docs.google.com/document/d/{doc_id}/edit"
    )
    r = await client.get(
        f"https://docs.googleapis.com/v1/documents/{doc_id}",
        headers=headers,
    )
    if r.status_code != 200:
        logger.warning(
            "Google Docs get failed doc=%s status=%s body=%s",
            doc_id,
            r.status_code,
            (r.text or "")[:300],
        )
        return title, f"_(Could not read doc body: HTTP {r.status_code})_"
    text = extract_plain_text_from_google_doc(r.json())
    if not text:
        text = "_(empty document)_"
    return title, f"{text}\n\nLink: {link}"


async def action_items_google_docs_block(
    slack_user_id: str,
    slack_digest: str,
    *,
    extra_google_urls: Sequence[str] | None = None,
) -> str:
    """Fetch full text of Google Docs linked in Slack/bookmarks (for action-item extraction)."""
    urls = _merge_google_urls_for_scan(slack_digest, extra_google_urls)
    folders, file_ids = parse_google_drive_targets_from_urls(urls)
    if not folders and not file_ids:
        return ""

    max_folders = max(0, min(10, int(os.environ.get("ACTION_ITEMS_MAX_DRIVE_FOLDERS", "5"))))
    max_depth = max(0, min(20, int(os.environ.get("ACTION_ITEMS_DRIVE_FOLDER_DEPTH", "8"))))
    max_docs = max(1, min(20, int(os.environ.get("ACTION_ITEMS_MAX_GOOGLE_DOCS", "8"))))
    max_chars_per_doc = max(
        1000, min(50_000, int(os.environ.get("ACTION_ITEMS_GOOGLE_DOC_MAX_CHARS", "8000")))
    )
    max_calls = max(10, min(200, int(os.environ.get("ACTION_ITEMS_DRIVE_MAX_API_CALLS", "60"))))

    if not await user_has_google_tokens(slack_user_id):
        return (
            "### Google Docs (linked in channel)\n"
            "_Google Docs links appear in Slack, but Google is not connected. "
            "Run `/susan connect google` to read doc content for action items._"
        )

    try:
        token = await get_valid_access_token(slack_user_id)
    except ValueError as e:
        return f"### Google Docs\n_(Could not use Google token: {e})_"

    doc_ids: set[str] = set()
    budget = _WeeklyDriveBudget(max_calls, max_docs * 2)
    headers = {"Authorization": f"Bearer {token}"}

    try:
        async with httpx.AsyncClient(timeout=60) as client:
            for fid in file_ids[:max_docs]:
                if not budget.take_call():
                    break
                meta = await _drive_get_file_meta(client, headers, fid)
                if not meta:
                    continue
                mid = meta.get("mimeType") or ""
                if mid == GOOGLE_DRIVE_DOC_MIME:
                    doc_ids.add(fid)
                elif mid == GOOGLE_DRIVE_FOLDER_MIME:
                    await _drive_collect_doc_ids_in_folder(
                        client, headers, fid, 0, max_depth, budget, doc_ids
                    )

            for folder_id in folders[:max_folders]:
                await _drive_collect_doc_ids_in_folder(
                    client, headers, folder_id, 0, max_depth, budget, doc_ids
                )

            picked = list(doc_ids)[:max_docs]
            if not picked:
                return (
                    "### Google Docs (linked in channel)\n"
                    "_(No Google Docs found at linked URLs/folders, or nothing is accessible "
                    "to the connected Google account.)_"
                )

            sections: list[str] = [
                "### Google Docs (linked in channel messages or bookmarks)\n"
                "_Extract open tasks, checklists, and owner columns from these documents._"
            ]
            docs_written = 0
            for doc_id in picked:
                if not budget.take_call():
                    sections.append(
                        f"_…{len(picked) - docs_written} further doc(s) omitted (API budget)._"
                    )
                    break
                title, body = await _fetch_google_doc_plain_text(client, headers, doc_id)
                if len(body) > max_chars_per_doc:
                    body = body[: max_chars_per_doc - 40] + "\n…_(doc truncated)_"
                sections.append(f"#### {title}\n{body}")
                docs_written += 1
            return "\n\n".join(sections)
    except Exception as e:
        logger.exception("action items Google Docs fetch failed")
        return f"### Google Docs\n_(Could not read linked docs: {e})_"
