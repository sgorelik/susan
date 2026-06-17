# Susan Skills

Susan's **skill engine** turns short user utterances ("hello", "what time is
it", "set a timer for 5 minutes") into responses. Skills are declared as YAML so
new ones can be added without touching the engine, and dynamic behaviour is
delegated to small named handlers.

- Engine & services: [`app/skills/`](../app/skills)
- Skill definitions (one YAML file per skill): [`app/skills/definitions/`](../app/skills/definitions)
- Tests: `tests/test_skills_*.py`

## Quick start

```python
from app.skills import default_engine, Session

engine = default_engine()
session = Session()

reply = await engine.handle("hello", session)
print(reply.text)  # "Hello, World! I'm Susan, and I'm ready to help."
```

`engine.handle(utterance, session)` returns a `SkillResponse` with:

| Field | Meaning |
|-------|---------|
| `text` | What Susan says. |
| `skill` | The matched skill name (`None` if nothing matched). |
| `matched` | `False` when no skill matched (a friendly fallback is returned). |
| `end_session` | `True` after `goodbye` — the caller should end the session. |
| `eliciting` | `True` when Susan is asking for a missing slot value. |
| `permission_request` | A permission Susan is requesting (e.g. `"location"`). |

## Skill definition format

Every skill is a YAML file in `app/skills/definitions/`:

```yaml
name: hello-world          # unique registry name (required)
order: 10                  # ordering used by the `help` listing
help_summary: greet you    # one-line capability shown by `help`
triggers:                  # case-insensitive phrases (required)
  - hello
  - hi susan
response:
  text: "Hello, World! I'm Susan, and I'm ready to help."   # static response
```

A **dynamic** response delegates to a named handler instead of fixed text:

```yaml
response:
  dynamic: true
  handler: time.current_local
```

### Triggers and slots

Trigger matching is **case-insensitive** and tolerant of surrounding words and
trailing punctuation. A trigger may embed a single trailing slot with
`{slot_name}`:

```yaml
triggers:
  - set a timer for {duration}
  - timer for {duration}
slots:
  - name: duration
    type: duration
    required: true
    prompt: "How long should I set the timer for?"
```

If a required slot is missing from the utterance (e.g. the user just says "set a
timer for"), the engine returns the slot `prompt` and remembers it on the
session; the user's next utterance is taken as the slot value.

### Requirements (APIs / permissions)

```yaml
requires:
  - api: weather_service
  - permission: location
```

### Ending the session

```yaml
session:
  end: true
```

## Skill registry

| Skill | Triggers | Response |
|-------|----------|----------|
| `hello-world` | hello; hi susan | static greeting |
| `who-are-you` | who are you; what's your name; introduce yourself | static intro |
| `help` | help; what can you do; commands | dynamic `help.summary` |
| `tell-time` | what time is it; current time; time | dynamic `time.current_local` |
| `tell-date` | what's the date; what day is it; today's date | dynamic `time.current_date` |
| `tell-joke` | tell me a joke; joke; make me laugh | dynamic `content.random_joke` |
| `fun-fact` | tell me a fact; fun fact; surprise me | dynamic `content.random_fact` |
| `set-timer` | set a timer for {duration}; timer for {duration} | dynamic `timer.set` |
| `weather` | what's the weather; weather today; is it raining | dynamic `weather.current` |
| `repeat` | say that again; repeat that; repeat | dynamic `session.replay_last` |
| `goodbye` | goodbye; bye susan; see you later; farewell | static farewell (`session.end`) |

The `help` response is generated from the registry (each skill's
`help_summary`), so it stays in sync automatically as skills are added or
removed.

## Handlers

Handlers are `(HandlerRequest) -> HandlerResult` callables (sync or async),
registered by name in `app/skills/handlers.py`. They receive a `SkillContext`
of shared, injectable services (`clock`, `jokes`, `facts`, `timers`,
`weather`, `notifier`), which makes them easy to test without real time, random
selection, or network calls.

### Time / date

`time.current_local` and `time.current_date` read `context.clock()` and format a
human-readable string ("It's 3:45 PM.", "Today is Tuesday, June 17.").

### Jokes / facts

`content.random_joke` and `content.random_fact` draw from curated pools
(`app/skills/content.py`). A `RotatingPool` cycles round-robin so consecutive
invocations return different content and every item is eventually used.

### Timers

`timer.set` parses the `duration` slot (`parse_duration` understands "5
minutes", "1 hour 30 minutes", "30 seconds", "an hour", …) and schedules an
expiry through `TimerService`. On expiry the service invokes the context's
`notifier` with an alert message. Scheduling is injectable, so tests fire expiry
deterministically instead of waiting on the clock.

### Weather API integration

`weather.current` requires location permission and a configured weather API:

1. If `session.permissions["location"]` is not `"granted"`, Susan requests
   permission (`permission_request="location"`) — except when it is explicitly
   `"denied"`, in which case she returns a graceful message.
2. With permission, it calls `context.weather.current(location)` and replies
   `"Currently in {location}: {conditions}, {temperature}."`.
3. Any provider failure (`WeatherError` or otherwise) yields a graceful "having
   trouble reaching the weather service" message.

The default `WeatherProvider` targets an OpenWeatherMap-style API:

| Env var | Default | Purpose |
|---------|---------|---------|
| `WEATHER_API_KEY` | — (required) | API key; absent ⇒ graceful error |
| `WEATHER_API_URL` | `https://api.openweathermap.org/data/2.5/weather` | Endpoint |
| `WEATHER_DEFAULT_LOCATION` | — | Fallback location |
| `WEATHER_UNITS` | `metric` | `metric` (°C) or `imperial` (°F) |

## Session memory

The `Session` object (`app/skills/models.py`) is threaded through every turn and
holds:

- `last_response` — the most recent thing Susan said. The engine stores it after
  each turn so the **`repeat`** skill (`session.replay_last`) can replay it. The
  `repeat` skill never overwrites it; with no prior response it returns "I
  haven't said anything yet!".
- `pending_skill` / `pending_slot` / `pending_slots` — in-progress slot
  elicitation carried across turns (e.g. the timer `duration`).
- `permissions` / `location` — permission grants and resolved location used by
  the weather skill.
- `ended` — set to `True` after `goodbye`.

Most skills are stateless; the session simply enables `repeat`, multi-turn slot
elicitation, weather permissions, and clean session termination.

## Adding a skill

1. Add a YAML file to `app/skills/definitions/` (`name`, `triggers`,
   `response`, optional `slots`/`requires`/`session`/`order`/`help_summary`).
2. For a dynamic response, add a handler to `app/skills/handlers.py` and
   register it in `default_handlers()`.
3. Add tests under `tests/test_skills_*.py`.

The `help` listing and the registry pick up the new skill automatically.
