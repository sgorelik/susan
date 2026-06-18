# Susan Skills

Susan's **skills** are small, declarative capabilities defined as YAML files in
[`app/skills/definitions`](../app/skills/definitions). Each skill declares the
phrases that trigger it, any values to collect from the user (*slots*), and how
to respond — either with static text or by delegating to a dynamic *handler*.

Utterances are dispatched through `app.skills.dispatch`:

```python
from app.skills import Session, dispatch

session = Session()                      # carries permissions + slot state across turns
result = await dispatch("set a timer for 5 minutes", session)
print(result.text)                       # what Susan says back
print(result.session_end)                # True after "goodbye"
```

`dispatch` returns a `SkillResult` with the reply `text` plus control flags:
`elicit` (Susan is asking for a slot), `needs_permission` (a permission must be
granted), `session_end` (end the conversation), `error`, and `matched`.

## Definition schema

| Field | Description |
|-------|-------------|
| `name` | Unique kebab-case skill id (e.g. `set-timer`). |
| `description` | Human-readable summary. |
| `triggers` | List of phrases. Matching is **case-insensitive** and tolerates trailing punctuation. Embed `{slot}` placeholders to capture values. |
| `slots` | Optional list of `{name, type, required, prompt}`. When a `required` slot is missing, Susan replies with its `prompt` and fills it from the next utterance. |
| `response.text` | Reply template (`str.format` with slot/handler values). |
| `response.dynamic` + `response.handler` | Route the reply through a registered handler instead of static text. |
| `session.end` | When `true`, the session is terminated after the response. |
| `api` | Declares an external API dependency (informational). |
| `permission` | A permission (e.g. `location`) the user must grant before the handler runs. |

## Handlers

Dynamic skills name a handler that runs after slots are filled. Handlers are
registered in [`app/skills/handlers.py`](../app/skills/handlers.py) and receive
the collected `slots`, the `session`, the `skill`, and injectable `services`.

| Handler | Skill | Behaviour |
|---------|-------|-----------|
| `timer.set` | `set-timer` | Parses the `duration` into seconds, schedules a background alert that fires when the timer expires, and confirms. |
| `weather.current` | `weather` | Checks location permission, fetches current conditions from the configured weather API, and formats the reply. |

## Built-in skills

### `set-timer`

- **Triggers:** `set a timer for {duration}`, `timer for {duration}`.
- **Slot:** `duration` (e.g. `5 minutes`, `1 hour 30 minutes`). If omitted, Susan
  asks *"How long should I set the timer for?"* and uses your next reply.
- **Confirmation:** *"Timer set for {duration}. I'll let you know when it's done."*
- **Alert:** when the duration elapses the timer fires a notification
  (*"Time's up! Your {duration} timer is done."*). The notifier is injectable —
  the default logs the alert; a front-end can supply one that posts to Slack.

### `weather`

- **Triggers:** `what's the weather`, `weather today`, `is it raining`
  (case-insensitive).
- **Permission:** requires `location`. If it has not been granted Susan asks for
  it (`needs_permission == "location"`); if it was denied she returns a graceful
  message.
- **Response:** *"Currently in {location}: {conditions}, {temperature}."*
- **Errors:** if the weather API is unreachable or misconfigured Susan replies
  with a graceful *"Sorry, I can't reach the weather service right now."*

Configure the provider via `WEATHER_API_KEY`, `WEATHER_API_URL`, and
`WEATHER_DEFAULT_LOCATION` (see [`.env.example`](../.env.example)). The default
URL targets a [WeatherAPI.com](https://www.weatherapi.com/) `current.json`
response shape; until a key is set the skill returns the graceful error above.

### `goodbye`

- **Triggers:** `goodbye`, `bye susan`, `see you later`, `farewell`
  (case-insensitive).
- **Response:** *"Goodbye! Come back anytime."*
- Stateless, no slots or external APIs; sets `session.end: true` so the session
  terminates after the reply.

## Adding a skill

1. Add `app/skills/definitions/<name>.yaml` following the schema above.
2. For dynamic skills, register the handler in `app/skills/handlers.py`.
3. Add tests in `tests/test_skills.py`.
