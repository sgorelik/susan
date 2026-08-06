"""GitHub GraphQL: read the roadmap board (Projects v2) and place items on it.

REST v3 (``app/github_http.py``) cannot see a project board: ``Status``, ``Phase``
and ``Priority`` are ProjectV2 *fields*, which exist only in GraphQL. Board reads
therefore need **read:project** in addition to ``repo``; the optional write path
(putting a freshly filed issue on the board) needs **project**.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

import httpx

from app.config import logger

GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"

SCOPE_HINT = (
    "Susan needs the *read:project* GitHub scope to read the roadmap board. "
    "Set `GITHUB_OAUTH_SCOPE=repo read:project` on the server, then run "
    "`/susan connect github` again. If this deployment uses a shared `GITHUB_TOKEN`, "
    "re-issue that token with `read:project` (classic PAT) or `project` for board writes."
)


class GithubGraphQLError(RuntimeError):
    """GraphQL transport or query error."""


class GithubProjectScopeError(GithubGraphQLError):
    """Token lacks read:project / project — actionable for the Slack user."""


async def github_graphql(
    query: str, variables: dict, token: str, *, timeout: int = 60
) -> dict:
    """POST a GraphQL document. Raises on transport errors and `errors` payloads."""
    hdrs = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.post(
            GITHUB_GRAPHQL_URL, headers=hdrs, json={"query": query, "variables": variables}
        )
    if r.status_code in (401, 403):
        raise GithubProjectScopeError(
            f"GitHub GraphQL denied the request ({r.status_code}). {SCOPE_HINT}"
        )
    if r.status_code != 200:
        raise GithubGraphQLError(f"GitHub GraphQL failed ({r.status_code}): {r.text[:300]}")
    try:
        payload = r.json()
    except ValueError as e:
        raise GithubGraphQLError(f"GitHub GraphQL returned non-JSON: {e}") from e
    errors = payload.get("errors")
    if errors:
        types = {str((e or {}).get("type") or "") for e in errors}
        msg = "; ".join(str((e or {}).get("message") or "") for e in errors)[:400]
        if "INSUFFICIENT_SCOPES" in types or "FORBIDDEN" in types or "read:project" in msg:
            raise GithubProjectScopeError(f"{msg} — {SCOPE_HINT}")
        raise GithubGraphQLError(f"GitHub GraphQL error: {msg}")
    return payload.get("data") or {}


# --- Board model ------------------------------------------------------------


@dataclass(slots=True)
class BoardItem:
    """One row on the board, with its project fields flattened by field name."""

    title: str
    kind: str  # issue | pull_request | draft
    url: str | None = None
    repo: str | None = None
    number: int | None = None
    state: str | None = None  # OPEN / CLOSED / MERGED
    merged: bool = False
    updated_at: str | None = None
    closed_at: str | None = None
    body: str = ""
    assignees: list[str] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)
    fields: dict[str, str] = field(default_factory=dict)

    def project_field(self, name: str) -> str:
        """Field value by field name, case-insensitive ('' when unset)."""
        want = (name or "").strip().casefold()
        for k, v in self.fields.items():
            if k.casefold() == want:
                return v
        return ""

    @property
    def ref(self) -> str:
        """Citable reference: ``repo#123`` for issues/PRs, a marker for drafts."""
        if self.repo and self.number:
            short = self.repo.split("/")[-1]
            return f"{short}#{self.number}"
        return "(draft item, no issue)"


@dataclass(slots=True)
class ProjectRef:
    node_id: str
    number: int
    title: str
    url: str


@dataclass(slots=True)
class ProjectField:
    node_id: str
    name: str
    options: dict[str, str] = field(default_factory=dict)  # option name -> option id


_PROJECT_BY_NUMBER = """
query($login:String!,$number:Int!){
  %(owner)s(login:$login){
    projectV2(number:$number){ id number title url }
  }
}
"""

_PROJECT_BY_TITLE = """
query($login:String!,$q:String!){
  %(owner)s(login:$login){
    projectsV2(first:25, query:$q){ nodes{ id number title url } }
  }
}
"""

_PROJECT_FIELDS = """
query($project:ID!){
  node(id:$project){
    ... on ProjectV2 {
      fields(first:50){
        nodes{
          __typename
          ... on ProjectV2FieldCommon { id name }
          ... on ProjectV2SingleSelectField { id name options { id name } }
        }
      }
    }
  }
}
"""

_ITEM_FIELDS = """
  id
  updatedAt
  fieldValues(first:30){
    nodes{
      __typename
      ... on ProjectV2ItemFieldTextValue { text field { ... on ProjectV2FieldCommon { name } } }
      ... on ProjectV2ItemFieldNumberValue { number field { ... on ProjectV2FieldCommon { name } } }
      ... on ProjectV2ItemFieldDateValue { date field { ... on ProjectV2FieldCommon { name } } }
      ... on ProjectV2ItemFieldSingleSelectValue { name field { ... on ProjectV2FieldCommon { name } } }
      ... on ProjectV2ItemFieldIterationValue { title field { ... on ProjectV2FieldCommon { name } } }
    }
  }
  content{
    __typename
    ... on Issue {
      number title url state updatedAt closedAt body
      repository { nameWithOwner }
      assignees(first:5){ nodes { login } }
      labels(first:10){ nodes { name } }
    }
    ... on PullRequest {
      number title url state merged mergedAt updatedAt closedAt body
      repository { nameWithOwner }
      assignees(first:5){ nodes { login } }
      labels(first:10){ nodes { name } }
    }
    ... on DraftIssue { title body updatedAt }
  }
"""

_PROJECT_ITEMS = (
    """
query($project:ID!,$cursor:String){
  node(id:$project){
    ... on ProjectV2 {
      items(first:100, after:$cursor){
        pageInfo{ hasNextPage endCursor }
        nodes{ %s }
      }
    }
  }
}
"""
    % _ITEM_FIELDS
)

_ADD_ITEM = """
mutation($project:ID!,$content:ID!){
  addProjectV2ItemById(input:{projectId:$project, contentId:$content}){ item { id } }
}
"""

_SET_SINGLE_SELECT = """
mutation($project:ID!,$item:ID!,$field:ID!,$option:String!){
  updateProjectV2ItemFieldValue(input:{
    projectId:$project, itemId:$item, fieldId:$field,
    value:{ singleSelectOptionId:$option }
  }){ projectV2Item { id } }
}
"""


async def resolve_project(owner: str, spec: str, token: str) -> ProjectRef:
    """Find a ProjectV2 by number ('12') or title ('Pilot Roadmap'), org or user owned."""
    spec = (spec or "").strip()
    if not spec:
        raise GithubGraphQLError(
            "No roadmap board configured. Set `SUSAN_ROADMAP_PROJECT` to the project "
            "number or title (for example `Pilot Roadmap`)."
        )
    last_err: Exception | None = None
    for owner_kind in ("organization", "user"):
        try:
            if spec.isdigit():
                data = await github_graphql(
                    _PROJECT_BY_NUMBER % {"owner": owner_kind},
                    {"login": owner, "number": int(spec)},
                    token,
                )
                node = ((data.get(owner_kind) or {}).get("projectV2")) or None
                nodes = [node] if node else []
            else:
                data = await github_graphql(
                    _PROJECT_BY_TITLE % {"owner": owner_kind},
                    {"login": owner, "q": spec},
                    token,
                )
                nodes = ((data.get(owner_kind) or {}).get("projectsV2") or {}).get("nodes") or []
        except GithubProjectScopeError:
            raise
        except GithubGraphQLError as e:
            last_err = e
            continue
        exact = [n for n in nodes if (n.get("title") or "").casefold() == spec.casefold()]
        chosen = (exact or nodes or [None])[0]
        if chosen:
            return ProjectRef(
                node_id=chosen["id"],
                number=int(chosen.get("number") or 0),
                title=chosen.get("title") or spec,
                url=chosen.get("url") or "",
            )
    if last_err:
        logger.warning("Roadmap project lookup failed for %s/%s: %s", owner, spec, last_err)
    raise GithubGraphQLError(
        f"Could not find project `{spec}` under `{owner}`. Check `SUSAN_ROADMAP_ORG` and "
        "`SUSAN_ROADMAP_PROJECT`, and that your GitHub account can see the board."
    )


def _field_value(node: dict) -> tuple[str, str] | None:
    """('Status', 'Done (dev)') from one fieldValues node."""
    name = ((node.get("field") or {}).get("name") or "").strip()
    if not name:
        return None
    for key in ("name", "text", "title", "date"):
        val = node.get(key)
        if isinstance(val, str) and val.strip():
            return name, val.strip()
    num = node.get("number")
    if isinstance(num, (int, float)):
        return name, f"{num:g}"
    return None


def _board_item_from_node(node: dict) -> BoardItem | None:
    content = node.get("content") or {}
    typename = content.get("__typename") or ""
    if typename == "Issue":
        kind = "issue"
    elif typename == "PullRequest":
        kind = "pull_request"
    elif typename == "DraftIssue":
        kind = "draft"
    else:
        return None  # redacted item, or content the token cannot see

    fields: dict[str, str] = {}
    for fv in (node.get("fieldValues") or {}).get("nodes") or []:
        pair = _field_value(fv or {})
        if pair:
            fields[pair[0]] = pair[1]

    repo = (content.get("repository") or {}).get("nameWithOwner")
    assignees = [
        (n or {}).get("login") or ""
        for n in ((content.get("assignees") or {}).get("nodes") or [])
    ]
    labels = [
        (n or {}).get("name") or "" for n in ((content.get("labels") or {}).get("nodes") or [])
    ]
    return BoardItem(
        title=(content.get("title") or "(untitled)").strip(),
        kind=kind,
        url=content.get("url"),
        repo=repo,
        number=content.get("number"),
        state=content.get("state"),
        merged=bool(content.get("merged")),
        updated_at=content.get("updatedAt") or node.get("updatedAt"),
        closed_at=content.get("closedAt"),
        body=(content.get("body") or "")[:4000],
        assignees=[a for a in assignees if a],
        labels=[la for la in labels if la],
        fields=fields,
    )


async def fetch_project_items(
    project: ProjectRef, token: str, *, max_items: int = 400
) -> list[BoardItem]:
    """Every visible row on the board, paginated 100 at a time."""
    out: list[BoardItem] = []
    cursor: str | None = None
    for _page in range(1, 21):
        data = await github_graphql(
            _PROJECT_ITEMS, {"project": project.node_id, "cursor": cursor}, token
        )
        items = ((data.get("node") or {}).get("items")) or {}
        for node in items.get("nodes") or []:
            item = _board_item_from_node(node or {})
            if item:
                out.append(item)
        if len(out) >= max_items:
            return out[:max_items]
        page_info = items.get("pageInfo") or {}
        if not page_info.get("hasNextPage"):
            break
        cursor = page_info.get("endCursor")
        if not cursor:
            break
    return out


async def fetch_project_fields(project: ProjectRef, token: str) -> dict[str, ProjectField]:
    """Field name (as-is) -> ProjectField, including single-select option ids."""
    data = await github_graphql(_PROJECT_FIELDS, {"project": project.node_id}, token)
    out: dict[str, ProjectField] = {}
    for node in ((data.get("node") or {}).get("fields") or {}).get("nodes") or []:
        name = (node or {}).get("name")
        fid = (node or {}).get("id")
        if not name or not fid:
            continue
        options = {
            (o or {}).get("name") or "": (o or {}).get("id") or ""
            for o in (node.get("options") or [])
        }
        out[name] = ProjectField(
            node_id=fid, name=name, options={k: v for k, v in options.items() if k and v}
        )
    return out


def board_write_enabled() -> bool:
    """Putting new issues on the board is opt-in: it needs the wider `project` scope."""
    return (os.environ.get("SUSAN_ROADMAP_BOARD_WRITE") or "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


async def add_issue_to_project(
    project: ProjectRef, issue_node_id: str, token: str
) -> str | None:
    """Put an existing issue on the board. Returns the new project item id."""
    data = await github_graphql(
        _ADD_ITEM, {"project": project.node_id, "content": issue_node_id}, token
    )
    return ((data.get("addProjectV2ItemById") or {}).get("item") or {}).get("id")


async def set_project_single_select(
    project: ProjectRef,
    item_id: str,
    field: ProjectField,
    option_name: str,
    token: str,
) -> None:
    """Set one single-select field (Status / Phase / Priority) by option *name*."""
    want = (option_name or "").strip().casefold()
    option_id = next((v for k, v in field.options.items() if k.casefold() == want), "")
    if not option_id:
        raise GithubGraphQLError(
            f"`{option_name}` is not an option on the board's `{field.name}` field "
            f"(options: {', '.join(field.options) or 'none'})."
        )
    await github_graphql(
        _SET_SINGLE_SELECT,
        {
            "project": project.node_id,
            "item": item_id,
            "field": field.node_id,
            "option": option_id,
        },
        token,
    )
