---
rezonant_doc_id: "fccf4afa-9d2b-42ca-983d-5c04d6a07e14"
rezonant_session_id: "88a2b5ce-0374-4006-9d6c-5940a7ff53c2"
updated_at: "2026-06-16T13:02:24+00:00"
---

# Susan – Meeting Notes: Technical Specification

## Summary

Add a `meeting notes` command to Susan (Slack bot) that, when triggered by an @mention, looks up the invoking user's most recent calendar meeting, fetches associated Granola notes and Google Drive documents, and posts a formatted summary with links back into the triggering Slack channel.

## Context and Background

Susan is an existing Slack bot with established integrations to Google Calendar, Google Drive, and Granola. Teams use Granola to capture meeting notes and Google Drive to store supporting documents. Currently, sharing meeting context after a call requires manual copy-paste from multiple tools. This command automates that handoff.

Key assumptions:

- Susan already authenticates with Google Calendar, Google Drive, and Granola on behalf of users — no new OAuth flows are required.
- Drive documents are surfaced from two places: links/attachments in the Google Calendar event, and documents that Granola associates with the meeting record.
- The "last meeting" is the most recently completed calendar event with at least one other attendee and a Granola notes record.



![image](doc://0bebb3a5-0528-47e6-8a44-f9c7430c33e8 "image")



&nbsp;

## dsfRequirements and User Stories

### User Stories

- **US-1 – Trigger:** As a Slack user, when I @mention Susan with a meeting notes request (e.g. `@susan meeting notes`), she identifies my most recent meeting and begins assembling the summary, so I don't have to hunt across tools.
- **US-2 – Meeting lookup:** As a Slack user, I expect Susan to automatically find my last qualifying meeting (past, multi-attendee, with Granola notes) from my Google Calendar, so I don't have to specify which meeting I mean.
- **US-3 – Notes and docs:** As a Slack user, I expect the posted summary to include the Granola meeting notes content and links to all associated Google Drive documents (deduped across calendar event and Granola sources), so everything is in one place.
- **US-4 – Fallback handling:** As a Slack user, if no Granola notes exist for my last meeting, I expect Susan to tell me clearly (rather than silently failing or posting an empty summary), so I know what happened.

### Non-Functional Requirements

- Summary post must appear within 10 seconds of the trigger; Susan should send an acknowledgement message immediately if processing will take longer.
- Drive doc links must be deduplicated before posting.
- The trigger phrase should be intent-matched (not exact string), so minor variations like `@susan share meeting notes` or `@susan post notes` also work.

## Proposed Solution

### High-Level Flow

1. **Receive trigger** — Slack event fires on @susan mention. Intent classifier determines this is a "meeting notes" request.
2. **Identify caller** — Resolve Slack user ID → Google account (using existing auth mapping).
3. **Fetch last meeting** — Query Google Calendar for the most recent past event where: the user is an attendee, there is at least one other attendee, and the event end time is before now.
4. **Match Granola record** — Look up the Granola notes record for that event (match by calendar event ID or title + time window). If no record exists, return the fallback message.
5. **Collect Drive docs** — Extract Drive links from the calendar event description and attachments. Fetch Drive docs surfaced by Granola for the same meeting. Merge and deduplicate by doc ID.
6. **Build summary** — Compose a Slack message with: meeting title, date, and attendees; Granola notes body (truncated if over Slack block limit, with a "full notes" link); and a bulleted list of Drive document links with titles.
7. **Post to channel** — Send the message to the channel where the @mention occurred.

### Key Design Decisions

- **Intent matching over exact command:** Use the existing intent classification layer (if one exists) or a simple keyword match (`meeting notes`, `notes`, `share notes`) rather than a strict slash-command, to keep the UX conversational.
- **Deduplication by Drive doc ID:** Strip doc IDs from URLs from both sources and use a set; post titles from whichever source provided the richer metadata.
- **Truncation at 2,800 characters** for the notes body in Slack (stay safely under block kit limits), appending a "View full notes in Granola" link.

## Rollout Plan

1. **Phase 1:** Implement trigger parsing and calendar lookup. Ship behind a feature flag to internal users only.
2. **Phase 2:** Add Granola fetch and Drive doc aggregation. Validate deduplication logic with real meeting data.
3. **Phase 3:** Enable for all users. Monitor error rates on calendar/Granola/Drive API calls.

## Validation

- Unit tests for: intent detection, "last meeting" selection logic, Drive doc deduplication, and message truncation.
- Integration test: end-to-end trigger → Slack post with a seeded test calendar event, Granola record, and Drive doc.
- Manual QA: test fallback path (no Granola notes), deduplication (same doc in calendar and Granola), and long notes truncation.

## Risks and Open Questions

- **Granola matching reliability:** If Granola doesn't store the Google Calendar event ID, matching by title + time window may produce false positives for back-to-back meetings with similar names. → Confirm how Granola links to calendar events.
- **No Granola notes fallback:** Should Susan post a partial summary (meeting title + Drive docs only) or a hard error? Decision needed before implementation.
- **Drive doc visibility:** Susan can surface links, but can't guarantee the user's Slack audience has Drive access. Out of scope for now but worth noting.
- **Multi-workspace support:** If Susan operates across multiple Slack workspaces, ensure the Google account mapping is workspace-scoped.

## Implementation Plan

This section details the execution steps for agent implementation.

### Step 1 — Intent Parsing

- Add a new intent handler to Susan's message routing layer that matches phrases containing: `meeting notes`, `share notes`, `post notes`, `notes from`.
- If matched, extract the Slack user ID and channel ID from the event payload and pass to the meeting notes handler.
- Immediately post an ephemeral acknowledgement: *"Looking up your last meeting…"*

### Step 2 — Calendar Lookup

- Resolve Slack user ID → Google account email using the existing auth mapping store.
- Call the Google Calendar API (`events.list`) for the user's primary calendar: `timeMax=now`, `orderBy=startTime` descending, `maxResults=10`.
- Filter results: keep only events where `attendees.length > 1` and the user's RSVP status is `accepted` or `tentative`.
- Select the first (most recent) qualifying event. Store its `id`, `summary`, `start`, `end`, `attendees`, `description`, and `attachments`.

### Step 3 — Granola Notes Fetch

- Call the Granola API to find the meeting record: query by calendar event ID first; fall back to title + time window (±15 min) if no ID match.
- If no Granola record found → post error message to channel: *"I found your last meeting ([title], [date]) but couldn't find Granola notes for it."* and exit.
- Extract: notes body text, Granola meeting URL, and any Drive doc references Granola surfaces.

### Step 4 — Drive Doc Aggregation

- Parse calendar event `description` for Google Drive URLs (regex: `docs.google.com|drive.google.com`).
- Parse calendar event `attachments` array for Drive file IDs.
- Merge with Granola-sourced Drive doc references.
- Deduplicate by Drive file ID. For each unique doc, call Google Drive API (`files.get`) to fetch the file title.

### Step 5 — Message Composition and Post

- Build a Slack Block Kit message with sections: **Meeting header** (title, date, attendee list), **Notes** (truncated to 2,800 chars with Granola link), **Documents** (bulleted Drive links with titles).
- If Drive doc list is empty, omit the Documents section.
- Post to the triggering channel using `chat.postMessage`. Delete the ephemeral acknowledgement.
