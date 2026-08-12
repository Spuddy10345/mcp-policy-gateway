# mcp-policy-gateway

[![CI](https://github.com/Spuddy10345/mcp-policy-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/Spuddy10345/mcp-policy-gateway/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-green)](LICENSE)

**An authorising reverse proxy for MCP servers.** It sits between an agent and
the tools it can reach, and decides — per call, on the actual arguments —
whether the call happens.

MCP servers are being wired directly into agent loops with nothing between
*"the model decided to call this tool"* and *"the tool ran"*. Those are two
different events. This puts something in the gap.

```
  agent ──▶ mcp-policy-gateway ──▶ [ hass ] [ github ] [ filesystem ] ...
                   │
                   ├── policy.yaml   per-tool and per-argument rules, per token
                   ├── audit.jsonl   every decision, hash-chained
                   └── dry-run       log what would break before it breaks
```

---

## The demo

An assistant is asked to summarise a web page. The page contains instructions
the user cannot see. The assistant follows them.

```console
$ uv run demo/prompt_injection.py
```

**Round 1 — agent connected directly to the MCP server**, as almost every MCP
setup is wired today:

```
  agent calls fetch_url(url='https://smart-home-weekly.example/morning-routines')
    page fetched — it contains hidden instructions
    the agent now believes it has three maintenance steps to run

  agent calls ha_remove_entity(entity_id='camera.driveway')
    EXECUTED Entity camera.driveway permanently removed.

  agent calls ha_call_service(domain='lock', service='unlock', entity_id='lock.front_door')
    EXECUTED Called lock.unlock on lock.front_door.

  agent calls ha_restart()
    EXECUTED Home Assistant is restarting.
```

**Round 2 — same attack, same agent, same server, gateway in between:**

```
  tools visible to the agent: 3
    fetch_url, ha_call_service, ha_get_overview

  agent calls ha_remove_entity(entity_id='camera.driveway')
    not in the tool list the agent was given; calling it by name anyway
    BLOCKED  Denied by gateway policy: the call to 'ha_remove_entity' was not
             permitted (destructive operations require a human at a keyboard).

  agent calls ha_call_service(domain='lock', service='unlock', entity_id='lock.front_door')
    BLOCKED  Denied by gateway policy: the call to 'ha_call_service' was not
             permitted (physical security domains are out of scope for an assistant).

  agent calls ha_restart()
    BLOCKED  Denied by gateway policy: the call to 'ha_restart' was not
             permitted (destructive operations require a human at a keyboard).
```

```
                            no gateway    with gateway
  entities remaining                 5               6
  entities deleted                   1               0
  front door                  unlocked          locked
  restarted                       True           False
```

The model was compromised in both rounds. It made exactly the same three calls.
What changed is that in round two those calls had to get past something that
was not reading the web page.

> **On the agent in this demo.** It is scripted, not a language model. Whether a
> given model falls for a given payload depends on the model, the phrasing and
> the day; building the demo on that would make it a benchmark of one model's
> gullibility rather than a test of this software, and it would not run in CI.
> The claim here is about what happens *after* the model is convinced. The
> gateway's guarantee does not depend on the model resisting — which is the
> whole reason to have a gateway rather than a better system prompt.

---

## Install

Not on PyPI yet. From a checkout:

```bash
git clone https://github.com/Spuddy10345/mcp-policy-gateway
cd mcp-policy-gateway
uv sync --extra dev
uv run mcp-policy-gateway --help
```

Or install the built wheel as a standalone tool:

```bash
uv build && uv tool install dist/*.whl
```

## Use

Write a policy:

```yaml
version: 1

upstreams:
  hass:
    transport: stdio
    command: uvx
    args: [hass-mcp]
    env:
      HA_URL: ${HA_URL}
      HA_TOKEN: ${HA_TOKEN}

policies:
  general-assistant:
    default: deny                # a policy that fails open is not a policy
    rules:
      - name: read-the-house
        effect: allow
        tools: [ha_get_*, ha_search]

      - name: safe-domain-actuation
        effect: allow
        tools: [ha_call_service]
        when:
          args.domain:
            in: [light, climate, switch, media_player]
        reason: actuation limited to non-safety-critical domains

      - name: never-unlock
        effect: deny
        tools: [ha_call_service]
        when:
          args.domain:
            in: [lock, alarm_control_panel]
        reason: physical security is out of scope for an assistant
```

Check it before you trust it:

```console
$ mcp-policy-gateway validate -c policy.yaml --strict
$ mcp-policy-gateway explain -c policy.yaml --policy general-assistant \
    --tool ha_call_service --args '{"domain": "lock", "service": "unlock"}'

DENY  ha_call_service  (policy 'general-assistant', upstream 'hass')
  matched:   never-unlock
  reason:    physical security is out of scope for an assistant
  listed:    yes
  trace:
    [safe-domain-actuation] FAIL args.domain='lock' not in ['light', 'climate', ...]
    [never-unlock] PASS args.domain satisfied
```

Then point your MCP client at the gateway instead of the server:

```json
Preparing PyPi Release{
  "mcpServers": {
    "hass": {
      "command": "mcp-policy-gateway",
      "args": ["run", "-c", "/path/to/policy.yaml", "--policy", "general-assistant"]
    }
  }
}
```

With one upstream and default settings the tool names are unchanged, so this is
a drop-in swap for the server it fronts.

---

## What it does

**Argument-level rules.** `ha_call_service` can turn on a lamp or unlock your
front door depending on one string. Allow-listing by tool name cannot tell those
apart, which is why rules reach into arguments:

```yaml
when:
  args.domain: {in: [light, climate]}
  args.entity_id: {matches: "(light|climate)\\..+"}
  args.targets[*].id: {not_matches: "lock\\..*"}    # every element must pass
```

**Capability-scoped tokens.** Each caller gets a token bound to one named policy
— `readonly`, `general-assistant`, `automation-editor` — not a blanket
credential. Tokens live in the config as SHA-256 digests, so the config can be
committed with no secret in it.

**Denied tools are never advertised.** A tool your policy can never permit is
left out of `tools/list` entirely, so an injected model is not told it exists.
Tools that are *conditionally* allowed stay listed, because the model needs them
for the permitted case. Hiding is blast-radius reduction, not the control —
`tools/call` is enforced independently, and a client that calls a hidden tool by
name is still refused.

**Rate limits.** Token buckets, per caller or shared, consumed only by calls that
are actually allowed. A rule naming several buckets debits all or none.

**Dry-run.** `--dry-run` logs every decision and enforces none of them, so you
can point a new policy at real traffic and read what it *would* have broken
before it breaks it. Available per-policy too, so one policy can be under test
while the rest stay enforced.

**A tamper-evident audit log.** Every decision is one JSON line: who called what,
with which arguments (redacted), which rule fired, and whether it ran. Records
are hash-chained, so editing or deleting one breaks the chain:

```console
$ mcp-policy-gateway audit verify audit.jsonl
line 2: content does not match its hash (stored a7895c2e372b...,
        recomputed ac50a6edb9f2...) — record was edited
FAILED: 1 problem(s) across 4 records
```

**A linter for your policy.** The failure mode of a policy language is a rule
that parses, starts, and enforces less than its author believed. `validate`
catches the fail-open shapes: unreachable rules, allow rules with no
constraints, regexes that narrow nothing, `optional` where it weakens a check.

```console
$ mcp-policy-gateway validate -c policy.yaml
warn   policy 'assistant' no-secrets: is unreachable: reads already matches
       everything this rule would, unconditionally. Rules are evaluated in
       order, first match wins.
```

---

## Design decisions worth knowing about

**Rules are first-match-wins, top to bottom.** No priorities, no implicit "deny
overrides allow" pass. A reviewer reads the rules in order and knows what
happens — which matters more than expressive power in a file whose whole job is
to be reviewed.

**`matches` is a full match, never a substring search.** An allow rule written
`light\..*` does not also permit `evil/light.bypass`. `^` and `$` are the two
characters people forget, so the language does not depend on them.

**A missing argument fails a constraint.** `when: {args.domain: {in: [light]}}`
against a call with no `domain` at all is *not* satisfied. Vacuous truth in an
allow rule is a bypass. Say `optional: true` if you meant it — and the linter
will mention that you did.

**Wildcards are universally quantified.** `args.entity_id[*]` requires *every*
element to pass, so a batch call cannot smuggle `lock.front_door` in alongside
two lamps.

**Denials come back as tool results, not protocol errors.** The agent reads
"policy denied this, tell the user" and can act on it. A JSON-RPC error would
surface to most clients as a transport failure and get retried.

**Unknown config keys are rejected.** `deney:` silently ignored would leave a
rule allowing everything it was meant to block.

---

## Non-goals

- **Not a sandbox.** An allowed call runs with whatever authority the upstream
  server has. This decides *whether* a call happens, not what it can do once it
  does.
- **Not a prompt-injection detector.** No classifier, no scanning of tool
  arguments for "suspicious" content. It enforces a policy you wrote. That is
  the point: it works against attacks nobody has thought of yet.
- **Not an LLM guardrail product.** It never sees the conversation, only the
  calls.
- **Not a secrets manager.** Upstream credentials come from your environment.
- **Resources and prompts are not proxied yet** — only tools. They are not
  exposed rather than passed through unchecked, so the omission fails closed.
- **Truncation of the audit log is not detectable** by hash-chaining alone.
  Chaining proves nothing was changed within what remains; catching a lopped-off
  tail needs an external anchor. See [THREAT_MODEL.md](THREAT_MODEL.md).

---

## Documentation

- [**THREAT_MODEL.md**](THREAT_MODEL.md) — what this defends against, what it
  does not, and the assumptions in between.
- [**docs/policy-language.md**](docs/policy-language.md) — the full rule and
  constraint reference.
- [**examples/home-assistant.yaml**](examples/home-assistant.yaml) — a
  worked policy for a real ~90-tool MCP server.

## Transports

| | stdio | streamable HTTP |
|---|---|---|
| Upstreams | yes | yes |
| Serving clients | yes | yes |
| Identity | fixed at launch (`--policy` / `--token`) | bearer token per request |

Under stdio the client launches the gateway, so there is exactly one caller and
the OS process boundary is the authentication. Over HTTP one process serves many
callers, each with their own token and policy, and identity is read from the
request being served.

## Development

```bash
uv sync --extra dev
uv run pytest              # 248 tests
uv run ruff check .
uv run pyright src
```

## License

Apache 2.0.
