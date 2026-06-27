"""Sales call prep: internal docs + Granola + company research for Frontier One (F1)."""
from __future__ import annotations

import asyncio
import json
import os
import re
from datetime import datetime, timedelta, timezone
from inspect import cleandoc
from typing import Any

import httpx

from app.claude_client import call_claude
from app.config import logger
from app.granola_summarize import collect_granola_notes_matching_terms
from app.slack_api import (
    markdownish_to_slack_mrkdwn,
    notify_user_ephemeral,
    post_ephemeral,
    post_message,
    post_slack_delayed_response,
    resolve_slack_post_channel,
)
from app.weekly_drive import (
    GOOGLE_DRIVE_DOC_MIME,
    GOOGLE_DRIVE_FOLDER_MIME,
    _WeeklyDriveBudget,
    _drive_get_file_meta,
    _drive_list_children_page,
    _fetch_google_doc_plain_text,
    parse_google_drive_targets_from_urls,
)
from db import get_granola_token, get_valid_access_token, user_has_google_tokens, user_has_granola_tokens

_SALES_PREP_CMD_RE = re.compile(
    r"^prep\s+(?:me\s+)?for\s+(?:a\s+)?sales\s+call\s+with\s+(.+)$",
    re.I,
)
_SALES_PREP_ALT_RE = re.compile(
    r"^(?:sales\s+prep|prep\s+sales(?:\s+call)?)\s+(?:for\s+(?:a\s+call\s+with\s+)?)?(.+)$",
    re.I,
)

_INTERNAL_DOC_KEYWORDS = (
    "sales",
    "gtm",
    "go-to-market",
    "frontier",
    "f1",
    "qualification",
    "qual",
    "scoping",
    "scope",
    "deck",
    "pitch",
    "product",
    "positioning",
    "competitive",
    "inference",
    "sovereign",
    "proposal",
    "rfp",
    "customer",
    "prospect",
    "discovery",
    "demo",
    "pricing",
    "battlecard",
    "one-pager",
    "one pager",
    "case study",
    "meeting notes",
    "call notes",
)

GOOGLE_DRIVE_SLIDES_MIME = "application/vnd.google-apps.presentation"

_SALES_DRIVE_MIME_QUERY = (
    "(mimeType = 'application/vnd.google-apps.document' "
    "or mimeType = 'application/vnd.google-apps.presentation')"
)

_F1_CONTEXT = cleandoc(
    """
    Frontier One (F1) provides secure, sovereign AI inference infrastructure for enterprises
    and governments that cannot rely on hyperscaler public clouds. Key themes:
    - Secure / air-gapped / sovereign inference (on-prem, private cloud, regulated sectors)
    - Regulatory compliance (GDPR, sector-specific: finance, defence, healthcare, public sector)
    - Alternative to or complement for AWS/GCP/Azure and neo-clouds (CoreWeave, Lambda, etc.)
    - GPU inference at scale with data residency and auditability
  """
)


def _normalize_prep_target(raw: str) -> str:
    s = (raw or "").strip()
    if s.lower().startswith("with "):
        s = s[5:].strip()
    return s


def parse_sales_prep_command(text: str) -> str | None:
    """If text is a sales-prep command, return the company/contact target; else None."""
    raw = (text or "").strip()
    if not raw:
        return None
    for pat in (_SALES_PREP_CMD_RE, _SALES_PREP_ALT_RE):
        m = pat.match(raw)
        if m:
            target = _normalize_prep_target(m.group(1))
            return target if target else None
    return None


def extract_search_terms(target: str) -> list[str]:
    """Build deduped search terms from a free-text sales target."""
    target = (target or "").strip()
    if not target:
        return []
    terms: list[str] = []
    seen: set[str] = set()

    def add(term: str) -> None:
        t = term.strip()
        if not t:
            return
        key = t.lower()
        if key not in seen:
            seen.add(key)
            terms.append(t)

    add(target)
    for sep in (" at ", " from ", " — ", " - ", ","):
        if sep in target:
            for part in target.split(sep):
                add(part)
    # Significant tokens (skip very short words unless they look like acronyms).
    for word in re.findall(r"[A-Za-z0-9][\w.-]*", target):
        if len(word) >= 4 or (len(word) >= 2 and word.isupper()):
            add(word)
    return terms


def _env_csv_ids(name: str) -> list[str]:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return []
    return [x.strip() for x in raw.split(",") if x.strip()]


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int((os.environ.get(name) or str(default)).strip())))
    except ValueError:
        return default


def doc_name_relevance_score(name: str, search_terms: list[str]) -> int:
    """Higher = more likely a sales/GTM/F1 doc or prospect-specific file."""
    low = (name or "").lower()
    if not low:
        return 0
    score = 0
    for term in search_terms:
        t = term.lower()
        if len(t) >= 2 and t in low:
            score += 12
    for kw in _INTERNAL_DOC_KEYWORDS:
        if kw in low:
            score += 4
    return score


def is_sales_relevant_filename(name: str, search_terms: list[str]) -> bool:
    return doc_name_relevance_score(name, search_terms) > 0


async def _drive_list_accessible_files_page(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    page_token: str | None,
) -> tuple[list[dict], str | None]:
    """One page of Google Docs + Slides the connected user can see."""
    params: dict[str, str] = {
        "q": f"trashed = false and {_SALES_DRIVE_MIME_QUERY}",
        "fields": "nextPageToken, files(id,name,mimeType,modifiedTime,webViewLink)",
        "pageSize": "100",
        "supportsAllDrives": "true",
        "includeItemsFromAllDrives": "true",
        "orderBy": "modifiedTime desc",
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
            "sales prep Drive files.list failed: status=%s body=%s",
            r.status_code,
            (r.text or "")[:400],
        )
        return [], None
    data = r.json()
    return data.get("files") or [], data.get("nextPageToken")


async def _discover_relevant_drive_files(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    search_terms: list[str],
    budget: _WeeklyDriveBudget,
    max_list: int,
    *,
    stop_after_candidates: int,
) -> list[dict]:
    """Scan accessible Drive; return Docs/Slides whose names look sales- or prospect-related."""
    candidates: list[dict] = []
    page_token: str | None = None
    listed = 0
    pages = 0
    max_pages = max(1, min(20, (max_list + 99) // 100))
    while listed < max_list and budget.take_call() and pages < max_pages:
        pages += 1
        batch, page_token = await _drive_list_accessible_files_page(
            client, headers, page_token
        )
        for f in batch:
            listed += 1
            name = (f.get("name") or "").replace("\n", " ")
            if not is_sales_relevant_filename(name, search_terms):
                continue
            score = doc_name_relevance_score(name, search_terms)
            candidates.append(
                {
                    "id": f.get("id"),
                    "name": name,
                    "mimeType": f.get("mimeType") or "",
                    "modifiedTime": f.get("modifiedTime") or "",
                    "webViewLink": f.get("webViewLink")
                    or f"https://drive.google.com/file/d/{f.get('id')}/view",
                    "_score": score,
                }
            )
            if len(candidates) >= stop_after_candidates:
                break
            if listed >= max_list:
                break
        if len(candidates) >= stop_after_candidates:
            break
        if not page_token:
            break
    candidates.sort(
        key=lambda x: (x["_score"], x.get("modifiedTime") or ""),
        reverse=True,
    )
    return candidates


async def _collect_extra_doc_ids_from_paths(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    folder_ids: list[str],
    file_ids: list[str],
    search_terms: list[str],
    budget: _WeeklyDriveBudget,
    max_depth: int,
    out: dict[str, dict],
) -> None:
    """Optional env-configured folders/files — always consider; include if name matches or forced."""
    for fid in file_ids:
        if not budget.take_call():
            break
        meta = await _drive_get_file_meta(client, headers, fid)
        if not meta:
            continue
        mid = meta.get("mimeType") or ""
        name = (meta.get("name") or fid).replace("\n", " ")
        if mid == GOOGLE_DRIVE_FOLDER_MIME:
            await _walk_folder_into_candidates(
                client, headers, fid, 0, max_depth, budget, search_terms, out, force=False
            )
        elif mid in (GOOGLE_DRIVE_DOC_MIME, GOOGLE_DRIVE_SLIDES_MIME):
            out[fid] = {
                "id": fid,
                "name": name,
                "mimeType": mid,
                "modifiedTime": meta.get("modifiedTime") or "",
                "webViewLink": meta.get("webViewLink")
                or f"https://drive.google.com/file/d/{fid}/view",
                "_score": doc_name_relevance_score(name, search_terms) + 100,
            }

    for folder_id in folder_ids:
        await _walk_folder_into_candidates(
            client, headers, folder_id, 0, max_depth, budget, search_terms, out, force=False
        )


async def _walk_folder_into_candidates(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    folder_id: str,
    depth: int,
    max_depth: int,
    budget: _WeeklyDriveBudget,
    search_terms: list[str],
    out: dict[str, dict],
    *,
    force: bool,
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
            name = (f.get("name") or "").replace("\n", " ")
            if not fid:
                continue
            if mid == GOOGLE_DRIVE_FOLDER_MIME:
                await _walk_folder_into_candidates(
                    client, headers, fid, depth + 1, max_depth, budget, search_terms, out, force=force
                )
            elif mid in (GOOGLE_DRIVE_DOC_MIME, GOOGLE_DRIVE_SLIDES_MIME):
                if force or is_sales_relevant_filename(name, search_terms):
                    out[fid] = {
                        "id": fid,
                        "name": name,
                        "mimeType": mid,
                        "modifiedTime": f.get("modifiedTime") or "",
                        "webViewLink": f.get("webViewLink")
                        or f"https://drive.google.com/file/d/{fid}/view",
                        "_score": doc_name_relevance_score(name, search_terms),
                    }
        if not page_token:
            break


async def gather_internal_docs_block(slack_user_id: str, target: str) -> str:
    """Load sales/GTM/F1 docs by scanning accessible Drive and matching file names."""
    search_terms = extract_search_terms(target)
    folder_entries = _env_csv_ids("SALES_PREP_DRIVE_FOLDER_IDS")
    file_entries = _env_csv_ids("SALES_PREP_DRIVE_FILE_IDS")
    folder_ids, _ = parse_google_drive_targets_from_urls(
        [e for e in folder_entries if e.startswith("http")]
    )
    file_ids, extra_folders = parse_google_drive_targets_from_urls(
        [e for e in file_entries if e.startswith("http")]
    )
    folder_ids = folder_ids + [e for e in folder_entries if not e.startswith("http")] + extra_folders
    file_ids = file_ids + [e for e in file_entries if not e.startswith("http")]
    folder_ids = list(dict.fromkeys(folder_ids))
    file_ids = list(dict.fromkeys(file_ids))

    header = (
        "### Internal sales & product documentation (Google Drive)\n"
        "_Scans your accessible Drive for Docs/Slides whose names look sales-, GTM-, F1-, "
        "or prospect-related (e.g. *sales*, *gtm*, *frontier*, *f1*, *qualification*, "
        "*scoping*, *deck*, *pitch*, or the prospect name)._ \n"
    )
    if not await user_has_google_tokens(slack_user_id):
        return (
            header
            + "_Google is not connected. Run `/susan connect google` to load internal docs._\n"
        )

    max_list = _env_int("SALES_PREP_DRIVE_MAX_LIST", 100, 30, 5000)
    max_folders = _env_int("SALES_PREP_MAX_FOLDERS", 8, 1, 20)
    max_depth = _env_int("SALES_PREP_DRIVE_DEPTH", 10, 1, 25)
    max_docs = _env_int("SALES_PREP_MAX_DOCS", 12, 1, 30)
    max_slides = _env_int("SALES_PREP_MAX_SLIDES", 8, 0, 20)
    max_chars = _env_int("SALES_PREP_DOC_MAX_CHARS", 12_000, 2000, 50_000)
    max_calls = _env_int("SALES_PREP_DRIVE_MAX_API_CALLS", 120, 10, 400)

    try:
        token = await get_valid_access_token(slack_user_id)
    except ValueError as e:
        return header + f"_(Could not use Google token: {e})_\n"

    budget = _WeeklyDriveBudget(max_calls, max_docs + max_slides + 20)
    headers = {"Authorization": f"Bearer {token}"}
    sections: list[str] = [header]

    try:
        async with httpx.AsyncClient(timeout=60) as client:
            by_id: dict[str, dict] = {}
            stop_after = max(max_docs + max_slides, 15) * 2

            discovered = await _discover_relevant_drive_files(
                client,
                headers,
                search_terms,
                budget,
                max_list,
                stop_after_candidates=stop_after,
            )
            for item in discovered:
                fid = item.get("id")
                if fid:
                    by_id[fid] = item

            if folder_ids or file_ids:
                await _collect_extra_doc_ids_from_paths(
                    client,
                    headers,
                    folder_ids[:max_folders],
                    file_ids,
                    search_terms,
                    budget,
                    max_depth,
                    by_id,
                )

            ranked = sorted(
                by_id.values(),
                key=lambda x: (x.get("_score", 0), x.get("modifiedTime") or ""),
                reverse=True,
            )
            if not ranked:
                sections.append(
                    "_(No sales-related Docs or Slides found by file name in your accessible Drive. "
                    "Try a broader prospect name or add files whose titles include sales/GTM/F1 keywords.)_\n"
                )
                return "\n".join(sections)

            slides = [f for f in ranked if f.get("mimeType") == GOOGLE_DRIVE_SLIDES_MIME][:max_slides]
            docs = [f for f in ranked if f.get("mimeType") == GOOGLE_DRIVE_DOC_MIME][:max_docs]

            if slides:
                sections.append(
                    f"#### Slide decks ({len(slides)} matched by name — open for visuals)\n"
                    + "\n".join(
                        f"- {s['name']} — <{s['webViewLink']}|open deck>"
                        for s in slides
                    )
                )

            for item in docs:
                if not budget.take_call():
                    sections.append("_…further docs omitted (API budget)._")
                    break
                doc_id = item["id"]
                title, body = await _fetch_google_doc_plain_text(client, headers, doc_id)
                if len(body) > max_chars:
                    body = body[: max_chars - 40] + "\n…_(doc truncated)_"
                sections.append(f"#### {title}\n{body}")

            if not docs and slides:
                sections.append(
                    "_Matched slide decks only (no Google Doc bodies). Deck content is linked above._"
                )
    except Exception as e:
        logger.exception("sales prep Drive fetch failed")
        sections.append(f"_(Drive error: {e})_")

    return "\n\n".join(sections)


async def gather_granola_block(slack_user_id: str, target: str) -> str:
    """Prior Granola meetings mentioning the prospect or company."""
    terms = extract_search_terms(target)
    header = "### Prior meetings (Granola)\n"
    if not await user_has_granola_tokens(slack_user_id):
        return header + "_Granola not connected — optional but useful for prior call context._\n"

    lookback = _env_int("SALES_PREP_GRANOLA_LOOKBACK_DAYS", 180, 7, 730)
    today = datetime.now(timezone.utc).date()
    since_d = (today - timedelta(days=lookback)).isoformat()
    until_d = today.isoformat()
    max_notes = _env_int("SALES_PREP_GRANOLA_MAX_NOTES", 5, 1, 20)
    max_pages = _env_int("SALES_PREP_GRANOLA_MAX_LIST_PAGES", 4, 1, 15)

    try:
        token = await get_granola_token(slack_user_id)
        matched, scanned = await collect_granola_notes_matching_terms(
            token,
            since_d,
            until_d,
            terms,
            max_detail_fetch=max_notes,
            max_list_pages=max_pages,
        )
    except Exception as e:
        logger.warning("sales prep Granola fetch failed: %s", e)
        return header + f"_(Could not load Granola notes: {e})_\n"

    if not matched:
        return (
            header
            + f"_No Granola notes in the last {lookback} days mention "
            f"{target!r} (scanned {scanned} note titles)._ \n"
        )

    max_chars = _env_int("SALES_PREP_GRANOLA_MAX_CHARS", 6000, 500, 30_000)
    lines = [header, f"_Matched {len(matched)} note(s) for {target!r}:_\n"]
    total = 0
    for note in matched:
        title = (note.get("title") or "Untitled").strip()
        when = (note.get("created_at") or note.get("updated_at") or "")[:10]
        summary = (
            note.get("summary_markdown")
            or note.get("summary_text")
            or note.get("summary")
            or note.get("notes_markdown")
            or ""
        ).strip()
        block = f"#### {title} ({when})\n{summary}"
        if total + len(block) > max_chars:
            lines.append("_…further Granola notes omitted (size cap)._")
            break
        lines.append(block)
        total += len(block)
    return "\n\n".join(lines)


def _cap_sales_prep_context(
    internal_docs: str, granola_block: str, max_total: int
) -> tuple[str, str]:
    """Keep Claude prompt within a bounded size so Opus calls finish reliably."""
    internal_docs = internal_docs or ""
    granola_block = granola_block or ""
    combined = len(internal_docs) + len(granola_block)
    if combined <= max_total:
        return internal_docs, granola_block
    # Preserve granola (usually smaller); trim internal docs from the middle.
    granola_budget = min(len(granola_block), max_total // 4)
    docs_budget = max_total - granola_budget
    if len(granola_block) > granola_budget:
        granola_block = granola_block[: granola_budget - 40] + "\n…_(granola truncated)_"
    if len(internal_docs) > docs_budget:
        keep = max(2000, docs_budget - 80)
        internal_docs = (
            internal_docs[: keep // 2]
            + "\n\n…_(middle of internal docs omitted for size)_\n\n"
            + internal_docs[-(keep - keep // 2) :]
        )
    return internal_docs, granola_block


_COMMERCIAL_PREP_FOOTER = "Prepared with Claude Opus via Susan"


async def _prep_notify(
    channel_id: str,
    slack_user_id: str,
    text: str,
    response_url: str | None,
    *,
    commercial_footer: str | None = None,
    blocks: list[dict] | None = None,
) -> None:
    """Ephemeral sales-prep message — never shows the F1 sovereign attribution."""
    await notify_user_ephemeral(
        channel_id,
        slack_user_id,
        text,
        blocks,
        response_url,
        skip_sovereign_attribution=True,
        commercial_footer=commercial_footer,
    )


async def _sales_prep_progress(
    response_url: str | None,
    channel_id: str,
    slack_user_id: str,
    message: str,
) -> None:
    """Best-effort status ping so the user knows Susan is still working."""
    logger.info("sales prep progress: %s", message)
    if response_url:
        try:
            await post_slack_delayed_response(
                response_url,
                {"response_type": "ephemeral", "text": message},
                skip_sovereign_attribution=True,
            )
            return
        except Exception as e:
            logger.warning("sales prep progress via response_url failed: %s", e)
    try:
        await post_ephemeral(
            channel_id, slack_user_id, message, skip_sovereign_attribution=True
        )
    except Exception as e:
        logger.warning("sales prep progress ephemeral failed: %s", e)


def _parse_prep_response(raw: str) -> dict[str, Any]:
    """Parse Claude JSON: Slack TLDR, talking points, action items, detail sections."""
    text = (raw or "").strip()
    fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if fence:
        text = fence.group(1).strip()
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("expected JSON object")

    tldr = str(data.get("tldr_slack") or data.get("tldr") or "").strip()
    if not tldr:
        raise ValueError("missing tldr_slack")

    talking_points = _parse_string_list(data.get("talking_points"))
    action_items = _parse_string_list(data.get("action_items"))
    if not talking_points:
        raise ValueError("missing talking_points")
    if not action_items:
        raise ValueError("missing action_items")

    sections_raw = data.get("sections") or data.get("topics") or []
    if not isinstance(sections_raw, list) or not sections_raw:
        raise ValueError("missing sections")
    sections: list[dict[str, str]] = []
    for s in sections_raw:
        if not isinstance(s, dict):
            continue
        title = str(s.get("title") or "").strip()
        body = str(s.get("body") or "").strip()
        if title and body:
            sections.append({"title": title, "body": body})
    if not sections:
        raise ValueError("no valid sections")

    return {
        "tldr_slack": tldr,
        "talking_points": talking_points,
        "action_items": action_items,
        "sections": sections,
    }


def _parse_string_list(raw: Any) -> list[str]:
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    for item in raw:
        s = str(item or "").strip()
        if s:
            out.append(s)
    return out


def _strip_slack_mrkdwn_for_doc(text: str) -> str:
    """Rough conversion of Slack mrkdwn to readable plain text for Google Docs."""
    s = (text or "").strip()
    s = re.sub(r"<(https?://[^>|]+)\|([^>]+)>", r"\2 (\1)", s)
    s = re.sub(r"<(https?://[^>]+)>", r"\1", s)
    s = re.sub(r"\*([^*]+)\*", r"\1", s)
    s = re.sub(r"_([^_]+)_", r"\1", s)
    return s.strip()


def format_sales_prep_doc_content(target: str, parsed: dict[str, Any]) -> str:
    """Build a scannable Google Doc body with marked talking points and action items."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    lines: list[str] = [
        f"Sales Call Prep — {target}",
        f"Prepared by Susan · {today} UTC",
        "",
        "—" * 40,
        "",
        "TL;DR",
        _strip_slack_mrkdwn_for_doc(parsed["tldr_slack"]),
        "",
        "▸ TALKING POINTS",
        "Use these on the call — in order of priority.",
        "",
    ]
    for i, point in enumerate(parsed["talking_points"], 1):
        lines.append(f"{i}. {_strip_slack_mrkdwn_for_doc(point)}")
    lines.extend(
        [
            "",
            "▸ ACTION ITEMS",
            "Before, during, and after the call.",
            "",
        ]
    )
    for item in parsed["action_items"]:
        lines.append(f"☐ {_strip_slack_mrkdwn_for_doc(item)}")
    lines.extend(["", "—" * 40, "", "DETAILED BRIEF", ""])
    for section in parsed["sections"]:
        lines.append(section["title"].upper())
        lines.append("")
        lines.append(_strip_slack_mrkdwn_for_doc(section["body"]))
        lines.append("")
        lines.append("—" * 40)
        lines.append("")
    return "\n".join(lines).strip() + "\n"


def format_sales_prep_slack_payload(
    target: str, parsed: dict[str, Any], doc_url: str
) -> tuple[str, list[dict]]:
    """Slack TLDR + Google Doc link using Block Kit mrkdwn (links render reliably)."""
    tldr = markdownish_to_slack_mrkdwn(parsed["tldr_slack"]).strip()
    max_tldr = 2800
    if len(tldr) > max_tldr:
        tldr = tldr[: max_tldr - 1].rstrip() + "…"

    title = f"*Sales prep — {target}*"
    link_mrkdwn = f"<{doc_url}|Open full brief in Google Docs>"
    link_plain = doc_url.strip()

    blocks: list[dict] = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"{title}\n\n{link_mrkdwn}\n{link_plain}",
            },
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": tldr or "_No summary generated._"},
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "_Full brief includes talking points, action items, and F1 fit._",
                }
            ],
        },
    ]
    fallback = f"Sales prep — {target}\n{link_plain}\n\n{tldr}"
    return fallback, blocks


def format_sales_prep_slack_message(target: str, parsed: dict[str, Any], doc_url: str) -> str:
    """Plain-text fallback (notifications); prefer ``format_sales_prep_slack_payload`` for posting."""
    fallback, _ = format_sales_prep_slack_payload(target, parsed, doc_url)
    return fallback


async def _create_sales_prep_google_doc(
    target: str, parsed: dict[str, Any], slack_user_id: str
) -> tuple[str | None, str | None]:
    from app.google_workspace import create_google_doc_titled

    title = f"Sales prep — {target}"[:200]
    body = format_sales_prep_doc_content(target, parsed)
    return await create_google_doc_titled(title, body, slack_user_id)


async def _publish_prep_result(
    channel_id: str,
    slack_user_id: str,
    thread_ts: str | None,
    target: str,
    parsed: dict[str, Any],
    response_url: str | None,
) -> str:
    """Post a Slack TLDR with link to a formatted Google Doc (no thread replies). Returns doc URL."""
    doc_url, doc_err = await _create_sales_prep_google_doc(target, parsed, slack_user_id)
    if not doc_url:
        raise RuntimeError(doc_err or "Could not create Google Doc")
    logger.info("sales prep Google Doc created for %s: %s", target, doc_url)

    channel_id = await resolve_slack_post_channel(channel_id, slack_user_id)
    fallback_text, blocks = format_sales_prep_slack_payload(target, parsed, doc_url)
    post_kw = {
        "slack_user_id": slack_user_id,
        "skip_sovereign_attribution": True,
        "commercial_footer": _COMMERCIAL_PREP_FOOTER,
    }
    try:
        await post_message(
            channel_id,
            fallback_text,
            thread_ts=thread_ts,
            blocks=blocks,
            **post_kw,
        )
    except RuntimeError as e:
        logger.warning("sales prep channel post failed (%s); using ephemeral", e)
        await _prep_notify(
            channel_id,
            slack_user_id,
            fallback_text,
            response_url,
            commercial_footer=_COMMERCIAL_PREP_FOOTER,
            blocks=blocks,
        )
    return doc_url


async def process_sales_prep(
    target: str,
    channel_id: str,
    slack_user_id: str,
    thread_ts: str | None,
    response_url: str | None,
) -> None:
    """Gather context, write a Google Doc, and post a Slack TLDR with the doc link."""
    target = (target or "").strip()
    if not target:
        await _prep_notify(
            channel_id,
            slack_user_id,
            "Please specify who the call is with, e.g. "
            "`/susan prep me for a sales call with Acme Corp`.",
            response_url,
        )
        return

    gather_timeout = _env_int("SALES_PREP_GATHER_TIMEOUT_SECONDS", 120, 30, 600)
    context_cap = _env_int("SALES_PREP_MAX_CONTEXT_CHARS", 80_000, 10_000, 200_000)

    await _sales_prep_progress(
        response_url,
        channel_id,
        slack_user_id,
        f"Still working on *{target}* — scanning Google Drive and Granola…",
    )

    async def _gather() -> tuple[str, str]:
        docs_task = asyncio.create_task(gather_internal_docs_block(slack_user_id, target))
        granola_task = asyncio.create_task(gather_granola_block(slack_user_id, target))
        return await asyncio.gather(docs_task, granola_task)

    try:
        internal_docs, granola_block = await asyncio.wait_for(
            _gather(), timeout=gather_timeout
        )
    except asyncio.TimeoutError:
        await _prep_notify(
            channel_id,
            slack_user_id,
            (
                f"Sales prep timed out while loading Drive/Granola (>{gather_timeout}s). "
                "Try again, or ask an admin to raise `SALES_PREP_GATHER_TIMEOUT_SECONDS`."
            ),
            response_url,
        )
        return

    internal_docs, granola_block = _cap_sales_prep_context(
        internal_docs, granola_block, context_cap
    )

    await _sales_prep_progress(
        response_url,
        channel_id,
        slack_user_id,
        f"Generating the *{target}* brief with *Claude Opus* (this can take a few minutes)…",
    )
    system = cleandoc(
        f"""
        You are Susan, a sales preparation assistant for Frontier One (F1).

        { _F1_CONTEXT }

        The user is preparing for a sales call. Synthesize:
        1. Internal documentation provided (authoritative for F1 positioning and prior work)
        2. Prior meeting notes (Granola) if any
        3. Your general knowledge about the prospect company/sector — clearly label these
           as *general knowledge* and flag anything that should be verified before the call

        Focus on what helps the caller sell F1:
        - Inference needs, GPU/ML workloads, model deployment patterns
        - Regulatory / data residency / sovereign cloud requirements
        - Current hyperscaler or neo-cloud usage and pain points
        - Decision makers and buying process hints
        - Announced projects or initiatives that may need secure inference
        - Competitive landscape and F1 differentiation angles
        - Suggested discovery questions and talk tracks

        Output ONLY valid JSON (no markdown fence) with this shape:
        {{
          "tldr_slack": "<3-5 short bullets for Slack; *bold* labels ok; keep under 120 words total>",
          "talking_points": [
            "<priority-ordered point to raise on the call>",
            "..."
          ],
          "action_items": [
            "<concrete before/during/after call task>",
            "..."
          ],
          "sections": [
            {{"title": "<section title>", "body": "<detailed plain-text paragraphs and bullets>"}},
            ...
          ]
        }}

        Requirements:
        - ``tldr_slack``: scannable bullets only — what matters most going into the call.
        - ``talking_points``: 5-8 specific, F1-relevant points to say (not generic fluff).
        - ``action_items``: 4-8 checkboxes — prep work, questions to ask, follow-ups after.
        - ``sections``: 4-7 deeper sections (company context, inference/regulatory needs,
          hyperscaler landscape, decision makers, F1 fit, competitive angles, discovery questions).
          Use plain text in section bodies (no Slack mrkdwn).
        """
    )

    user_prompt = (
        f"Sales call target: {target}\n"
        f"Search terms: {', '.join(extract_search_terms(target))}\n\n"
        f"--- INTERNAL DOCS ---\n{internal_docs}\n\n"
        f"--- GRANOLA ---\n{granola_block}"
    )

    max_tokens = _env_int("SALES_PREP_MAX_TOKENS", 8192, 2048, 16_384)
    raw = ""
    try:
        raw = await call_claude(
            system,
            user_prompt,
            max_tokens=max_tokens,
            action="sales_prep",
            model_route="commercial",
        )
        parsed = _parse_prep_response(raw)
    except json.JSONDecodeError as e:
        logger.error("sales prep JSON parse failed: %s raw=%r", e, (raw or "")[:500])
        await _prep_notify(
            channel_id,
            slack_user_id,
            "Susan generated a prep brief but could not parse the structured output. Please try again.",
            response_url,
        )
        return
    except Exception as e:
        logger.exception("sales prep Claude call failed")
        await _prep_notify(
            channel_id,
            slack_user_id,
            f"Sales prep failed: {e}",
            response_url,
        )
        return

    await _sales_prep_progress(
        response_url,
        channel_id,
        slack_user_id,
        f"Writing the *{target}* brief to Google Docs…",
    )

    try:
        doc_url = await _publish_prep_result(
            channel_id,
            slack_user_id,
            thread_ts,
            target,
            parsed,
            response_url,
        )
    except Exception as e:
        logger.exception("sales prep publish failed")
        await _prep_notify(
            channel_id,
            slack_user_id,
            f"Prep brief was generated but could not be published: {e}",
            response_url,
        )
        return

    link = f"<{doc_url}|Open full brief in Google Docs>"
    done_blocks: list[dict] = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"✓ *Sales prep ready* for *{target}*\n\n"
                    f"{link}\n{doc_url}\n\n"
                    f"_Talking points, action items, and full brief are in the doc._"
                ),
            },
        },
    ]
    await _prep_notify(
        channel_id,
        slack_user_id,
        f"Sales prep ready for {target}: {doc_url}",
        response_url,
        blocks=done_blocks,
    )
