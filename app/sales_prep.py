"""Sales call prep: internal docs + Granola + company research for Frontier One (F1)."""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone
from inspect import cleandoc
from typing import Any

import httpx

from app.claude_client import call_claude
from app.config import logger
from app.granola_summarize import collect_granola_notes_for_window
from app.slack_api import (
    markdownish_to_slack_mrkdwn,
    notify_user_ephemeral,
    post_ephemeral,
    post_message,
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
) -> list[dict]:
    """Scan accessible Drive; return Docs/Slides whose names look sales- or prospect-related."""
    candidates: list[dict] = []
    page_token: str | None = None
    listed = 0
    while listed < max_list and budget.take_call():
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
            if listed >= max_list:
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

    max_list = _env_int("SALES_PREP_DRIVE_MAX_LIST", 500, 50, 5000)
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
        async with httpx.AsyncClient(timeout=120) as client:
            by_id: dict[str, dict] = {}

            discovered = await _discover_relevant_drive_files(
                client, headers, search_terms, budget, max_list
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


def _note_matches_target(note: dict[str, Any], terms: list[str]) -> bool:
    blob = " ".join(
        str(note.get(k) or "")
        for k in ("title", "summary", "transcript", "notes_markdown")
    ).lower()
    return any(t.lower() in blob for t in terms if len(t) >= 2)


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

    try:
        token = await get_granola_token(slack_user_id)
        notes = await collect_granola_notes_for_window(token, since_d, until_d)
    except Exception as e:
        logger.warning("sales prep Granola fetch failed: %s", e)
        return header + f"_(Could not load Granola notes: {e})_\n"

    matched = [n for n in notes if _note_matches_target(n, terms)]
    if not matched:
        return (
            header
            + f"_No Granola notes in the last {lookback} days mention "
            f"{target!r} (searched {len(notes)} notes)._ \n"
        )

    max_notes = _env_int("SALES_PREP_GRANOLA_MAX_NOTES", 8, 1, 20)
    max_chars = _env_int("SALES_PREP_GRANOLA_MAX_CHARS", 6000, 500, 30_000)
    lines = [header, f"_Matched {len(matched)} note(s) for {target!r}:_\n"]
    total = 0
    for note in matched[:max_notes]:
        title = (note.get("title") or "Untitled").strip()
        when = (note.get("created_at") or note.get("updated_at") or "")[:10]
        summary = (note.get("summary") or note.get("notes_markdown") or "").strip()
        block = f"#### {title} ({when})\n{summary}"
        if total + len(block) > max_chars:
            lines.append("_…further Granola notes omitted (size cap)._")
            break
        lines.append(block)
        total += len(block)
    return "\n\n".join(lines)


def _parse_prep_response(raw: str) -> dict[str, Any]:
    """Parse Claude JSON output for TLDR + topic threads."""
    text = (raw or "").strip()
    fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if fence:
        text = fence.group(1).strip()
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("expected JSON object")
    tldr = str(data.get("tldr") or "").strip()
    topics = data.get("topics")
    if not tldr:
        raise ValueError("missing tldr")
    if not isinstance(topics, list) or not topics:
        raise ValueError("missing topics")
    cleaned: list[dict[str, str]] = []
    for t in topics:
        if not isinstance(t, dict):
            continue
        title = str(t.get("title") or "").strip()
        body = str(t.get("body") or "").strip()
        if title and body:
            cleaned.append({"title": title, "body": body})
    if not cleaned:
        raise ValueError("no valid topics")
    return {"tldr": tldr, "topics": cleaned}


_COMMERCIAL_PREP_FOOTER = "Prepared with Claude Opus via Susan"


async def _publish_prep_ephemeral_fallback(
    channel_id: str,
    slack_user_id: str,
    target: str,
    tldr: str,
    topics: list[dict[str, str]],
    response_url: str | None,
) -> None:
    """Private fallback when channel post fails — TLDR + one ephemeral per topic."""
    title = f"Sales prep — {target}"
    tldr_body = markdownish_to_slack_mrkdwn(tldr)
    header = (
        f"*{title}*\n\n{tldr_body}\n\n"
        f"_Could not post to the channel (bot may lack access). "
        f"Detailed sections follow as private messages._\n\n_{_COMMERCIAL_PREP_FOOTER}_"
    )
    await notify_user_ephemeral(
        channel_id, slack_user_id, header[:3900], None, response_url
    )
    for topic in topics:
        topic_title = markdownish_to_slack_mrkdwn(topic["title"])
        topic_body = markdownish_to_slack_mrkdwn(topic["body"])
        msg = f"*{topic_title}*\n\n{topic_body}"[:3900]
        try:
            await post_ephemeral(channel_id, slack_user_id, msg)
        except Exception as e:
            logger.warning("sales prep ephemeral topic failed: %s", e)
            await notify_user_ephemeral(
                channel_id, slack_user_id, msg[:3900], None, response_url
            )


async def _publish_prep_thread(
    channel_id: str,
    slack_user_id: str,
    thread_ts: str | None,
    target: str,
    tldr: str,
    topics: list[dict[str, str]],
    response_url: str | None,
) -> None:
    """Post TLDR as parent message, detailed topics as thread replies."""
    channel_id = await resolve_slack_post_channel(channel_id, slack_user_id)
    title = f"Sales prep — {target}"
    tldr_body = markdownish_to_slack_mrkdwn(tldr)
    parent = f"*{title}*\n\n{tldr_body}\n\n_Thread below has detailed sections — posted via Susan._"
    post_kw = {
        "slack_user_id": slack_user_id,
        "skip_sovereign_attribution": True,
        "commercial_footer": _COMMERCIAL_PREP_FOOTER,
    }
    try:
        data = await post_message(
            channel_id, parent[:3900], thread_ts=thread_ts, **post_kw
        )
    except RuntimeError as e:
        logger.warning("sales prep channel post failed (%s); using ephemeral fallback", e)
        await _publish_prep_ephemeral_fallback(
            channel_id, slack_user_id, target, tldr, topics, response_url
        )
        return

    root_ts = thread_ts or str(data.get("ts") or "")
    if not root_ts:
        raise RuntimeError("Slack did not return a message ts for sales prep")

    for topic in topics:
        topic_title = markdownish_to_slack_mrkdwn(topic["title"])
        topic_body = markdownish_to_slack_mrkdwn(topic["body"])
        chunk_limit = 2800
        body = topic_body
        first = True
        while body or first:
            chunk = body[:chunk_limit]
            body = body[chunk_limit:]
            prefix = f"*{topic_title}*\n\n" if first else ""
            first = False
            msg = (prefix + chunk).strip()
            if msg:
                await post_message(
                    channel_id, msg[:3900], thread_ts=root_ts, **post_kw
                )


async def process_sales_prep(
    target: str,
    channel_id: str,
    slack_user_id: str,
    thread_ts: str | None,
    response_url: str | None,
) -> None:
    """Gather context and post a TLDR + threaded deep-dive for a sales call."""
    target = (target or "").strip()
    if not target:
        await notify_user_ephemeral(
            channel_id,
            slack_user_id,
            "Please specify who the call is with, e.g. "
            "`/susan prep me for a sales call with Acme Corp`.",
            None,
            response_url,
        )
        return

    internal_docs = await gather_internal_docs_block(slack_user_id, target)
    granola_block = await gather_granola_block(slack_user_id, target)

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
          "tldr": "<3-6 bullet TLDR in Slack mrkdwn: *bold* not **, links as <url|label>>",
          "topics": [
            {{"title": "<section title>", "body": "<detailed mrkdwn for one thread reply>"}},
            ...
          ]
        }}

        Include 4-8 topic sections. Each topic body should be self-contained and actionable.
        Use Slack mrkdwn in tldr and topic bodies.
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
        await notify_user_ephemeral(
            channel_id,
            slack_user_id,
            "Susan generated a prep brief but could not parse the structured output. Please try again.",
            None,
            response_url,
        )
        return
    except Exception as e:
        logger.exception("sales prep Claude call failed")
        await notify_user_ephemeral(
            channel_id,
            slack_user_id,
            f"Sales prep failed: {e}",
            None,
            response_url,
        )
        return

    try:
        await _publish_prep_thread(
            channel_id,
            slack_user_id,
            thread_ts,
            target,
            parsed["tldr"],
            parsed["topics"],
            response_url,
        )
    except Exception as e:
        logger.exception("sales prep Slack publish failed")
        await notify_user_ephemeral(
            channel_id,
            slack_user_id,
            f"Prep brief was generated but could not be posted: {e}",
            None,
            response_url,
        )
        return

    await notify_user_ephemeral(
        channel_id,
        slack_user_id,
        (
            f"✓ *Sales prep ready* for *{target}* — see the TLDR above and detailed "
            f"sections in the thread. _(Prepared with Claude Opus.)_"
        ),
        None,
        response_url,
    )
