# Working the roadmap with Susan

Frontier One · internal · 6 August 2026

The plan lives in GitHub, not in a deck. This is how to ask it questions in plain English — what
shipped, what's stuck, and who owes whom — from Slack, without opening a terminal or a browser tab.

| | |
|---|---|
| Where you ask | Slack, `/susan` |
| Setup for you | none, beyond connecting GitHub once |
| Board | Pilot Roadmap (org-level GitHub project) |
| Plan of record | the tracking epic, `cloud-infra#231` |
| Standing rule | Susan files issues and opens PRs. She never merges. |

## What Susan is actually reading

Three things, and it helps to know which is which when Susan cites them back to you.

**The board** — *Pilot Roadmap*, an org-level GitHub project. One row per piece of work, each with a
Status, a Phase (W1 prod env, W2 GPU/model, Seqera pilot, and so on) and a Priority. This is the
live plan. Susan reads the board's fields directly, so she can group by phase and quote Status
verbatim rather than guessing from an issue title.

**The issues** — the detail behind each row, in the `cloud-infra` and `f1-asgardOS` repos.
Discussion, evidence, links to the code that shipped.

**The epic** — one tracking issue with the whole plan as checklists, grouped by phase. The fastest
single page to skim, and where the 6 August reconciliation is recorded. Susan reads it alongside the
board and tells you when the two disagree.

The old Google tracker sheet is legacy. Nobody updates it; Susan doesn't read it, and neither
should you.

## The Status words mean specific things

They were chosen so status can stay honest rather than optimistic. Worth knowing before you quote a
number to anyone outside the company.

| Status | What it means |
|--------|---------------|
| **Todo** | Not started. |
| **In Progress** | Someone is actively working it right now. |
| **Partial** | Some pieces are in place, usually proven on dev; the rest is outstanding. **Not** nearly done. |
| **Done (dev)** | Working in our development environment. The pilot or production re-apply has not happened. |
| **Blocked** | Waiting on a prerequisite or an external party — the blocker is named on the issue. |
| **Done** | Complete and verified. Nothing else outstanding. |

If you're building a customer or investor claim, **Done (dev)** and **Partial** are the two to read
carefully. They exist precisely so we don't overstate.

Susan is built around that: she quotes the Status word verbatim, treats Partial and Done (dev) as
not done, and counts the board arithmetic herself rather than eyeballing it — so the numbers in a
digest are the board's numbers, not a summary's impression of them.

## Connecting, once

In Slack: `/susan connect github`, then authorize the Frontier-One organization when GitHub asks.
That's it. If you don't see our repos afterwards, your GitHub account isn't in the org yet — ask
Stacy or Jesse.

Susan reads the board with your GitHub identity, so you see exactly what you're entitled to see.
Board fields need the `read:project` permission; if Susan says the scope is missing, she'll tell you
what to do and you re-run `/susan connect github`.

Whoever runs the server needs these set once (see `.env.example`):

```
SUSAN_ROADMAP_ORG=Frontier-One
SUSAN_ROADMAP_PROJECT=Pilot Roadmap
SUSAN_ROADMAP_EPIC=cloud-infra#231
SUSAN_ROADMAP_REPOS=Frontier-One/cloud-infra,Frontier-One/f1-asgardOS
GITHUB_OAUTH_SCOPE=repo read:project
```

## The four you'll actually use

These replace the Claude skills of the same name. Nothing to install — type them in Slack.

`/susan board status` — the weekly digest: what shipped, what only moved status, what's blocked and
on whom, in the same shape every week so you can compare Mondays. Add a window:
`board status last 14 days`.

`/susan customer ask Augur` — everything the roadmap says we owe a customer, what's ready, and what
we're waiting on from their side.

`/susan board pack` — the investor or board update: shipped since last time, current risks, and the
honest read on anything still Partial or Done (dev).

`/susan roadmap add <the decision>` — turns a decision from a meeting into a properly formed
roadmap issue. Checks for duplicates first, writes the reasoning, proposes Status, Phase and
Priority, then **shows it to you before filing anything**.

Two more worth knowing:

`/susan board risks` — every P0 and P1 that is Blocked, Partial or Todo, ranked by what breaks first
before a pilot handover, with the dependency named.

`/susan board claims` — split into what you can describe to a customer as live today versus what is
only Partial or Done (dev), with the issue number for each.

Answers come back privately, visible only to you. Add `--no-approval` to post one to the channel
instead. The old skill names work too, if that's what your fingers remember —
`/susan board-status`, `customer-ask Augur`, `board-pack`, `roadmap-add …`.

### Make the Monday digest standing

```
/susan schedule add board status last 7 days every monday at 9:00 in #team-tech
```

Same command, same shape, posted for everyone — which is how the team gets one digest instead of
five different ones.

## Asking anything else

`/susan roadmap <question>` answers from the board and the epic. These are phrased to survive being
asked cold by someone who doesn't know issue numbers.

**Before a board conversation**

```
/susan roadmap what changed in the last seven days, grouped by phase? Separate what actually
shipped from what only moved status, and tell me what's newly blocked and on whom
```

**Reality-check a promise**

```
/susan roadmap a customer needs streaming responses and tool calling, in the UK, with guardrails
on. Is that possible today? If not, which items have to close first and what are their statuses?
```

**Follow the thread on a decision**

```
/susan roadmap find everything about the GCP on-demand GPU quota — a dated timeline of what we
asked for, what was denied, what's still open, and who we're waiting on
```

**Money and capacity**

```
/susan roadmap summarize our GPU fleet, what each node is serving, and what it costs per month.
Flag anything running that nothing is using
```

**Capture something from a meeting**

```
/susan roadmap add we agreed in standup that we need a continuous path for pushing model and
container updates into customer environments
```

Run that one *in the thread where it was agreed* and Susan reads the conversation for context. She
checks whether the roadmap already covers it, and flags a possible duplicate rather than quietly
creating a second row.

That last one matters: filing an issue is how work becomes real. Since 6 August, nothing ships to
GitHub without a board item naming it first.

## One standing rule

Susan can open pull requests and file issues. She never merges. A human gives the final green light
on every merge — the one exception is the midgard demo repo. Everything in this guide except
`roadmap add` is strictly read-only, and `roadmap add` files nothing until you press the button.

## Three habits that keep this trustworthy

**Ask for the issue number.** Susan cites `repo#number` for every status claim by design. It makes
the answer checkable in a click, and it's how you catch a confident-sounding guess.

**Trust the Status word over the summary.** If a summary says a thing works and the board says
Partial, the board wins — and the gap is worth a question in standup. Susan is instructed to
surface that disagreement rather than smooth it over, so treat it as a finding when she does.

**Say when it's for a customer.** "I'm about to tell a customer this" changes how carefully the
answer is qualified. Use that.

---

Board: Pilot Roadmap · Plan of record: epic `cloud-infra#231` · Commands: `/susan help`

Questions about access, or something on the board that looks wrong — Stacy or Jesse.
