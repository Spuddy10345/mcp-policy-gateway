# The policy language

A reference for everything you can write in a gateway config. The language is
deliberately small: a policy engine whose expression language can do arbitrary
computation is one nobody can review, and reviewability is the point.

Check anything here against a real config without deploying it:

```console
$ mcp-policy-gateway explain -c policy.yaml --policy assistant \
    --tool ha_call_service --args '{"domain": "lock"}'
```

---

## File structure

```yaml
version: 1                # required, currently always 1
mode: enforce             # enforce | dry-run

server:      { ... }      # how the gateway presents itself
audit:       { ... }      # where decisions are written
upstreams:   { ... }      # required: the MCP servers being fronted
policies:    { ... }      # required: named capability sets
tokens:      [ ... ]      # bearer credentials, for HTTP transport
rate_limits: { ... }      # named token buckets
```

Unknown keys anywhere are a **hard error**. A typo must never fail open:
`deney:` silently ignored would leave a rule allowing everything it was meant
to block.

---

## Rule evaluation

Rules within a policy are evaluated **in order, first match wins**, falling
through to the policy's `default`. There are no priorities and no implicit
"deny overrides allow" pass — a reviewer reads top to bottom and knows what
happens.

```yaml
policies:
  assistant:
    default: deny                 # applied when no rule matches
    hide_denied_tools: true       # omit never-permitted tools from tools/list
    mode: dry-run                 # optional: override the gateway-wide mode
    rules:
      - name: no-secrets          # optional, but it appears in the audit log
        effect: deny              # allow | deny — required
        tools: [ha_get_secret]    # glob patterns; omit to match every tool
        upstreams: [hass]         # glob patterns; omit to match every upstream
        when: { ... }             # argument constraints; omit for unconditional
        rate_limits: [actuation]  # buckets consumed (allow rules only)
        reason: "not for agents"  # shown to the caller and logged
```

Because it is first-match-wins, **order matters**:

```yaml
# WRONG — the deny never fires
- {effect: allow, tools: [ha_get_*]}
- {effect: deny,  tools: [ha_get_secret]}

# RIGHT
- {effect: deny,  tools: [ha_get_secret]}
- {effect: allow, tools: [ha_get_*]}
```

`validate` catches exactly this case.

### Tool patterns are globs, not regexes

`tools:` and `upstreams:` use `fnmatch` globs — `*`, `?`, `[seq]` — matched
case-sensitively against the **gateway-facing** name (so `hass__ha_restart` when
namespacing is on). Regexes belong in `when`, and the linter says so if a
pattern looks like one.

`tools: []` is an error: it reads as "no tools" but would match everything.
Omit the key instead.

---

## Constraints

`when` maps a **selector** to a **constraint**. Every entry must hold for the
rule to match.

```yaml
when:
  args.domain:
    in: [light, climate]
  args.entity_id:
    matches: "(light|climate)\\..+"
  args.brightness:
    lte: 200
    optional: true
```

A scalar is shorthand for `eq`:

```yaml
when:
  args.domain: light        # same as {eq: light}
```

### Selectors

| Selector | Resolves to |
|---|---|
| `args` | The whole arguments object |
| `args.domain` | One named argument |
| `args.target.entity_id` | A nested value |
| `args.items[0]` | A list element (negative indices allowed) |
| `args.items[*]` | Every element of a list, or every value of a mapping |
| `args.items[*].id` | One field of every element |
| `tool` | The gateway-facing tool name |
| `upstream` | The upstream name |

Malformed selectors are rejected when the config loads, including the ones that
would otherwise resolve to something plausible: `.args`, `args..domain` and
`args.` are all errors rather than being read as `args`.

### Operators

| Operator | Holds when |
|---|---|
| `eq` / `ne` | Value equals / does not equal |
| `in` / `not_in` | Value is / is not in the list |
| `matches` | Value **fully** matches the regex |
| `not_matches` | Value does not fully match the regex |
| `contains` | Substring, list member, or mapping key |
| `gt` `gte` `lt` `lte` | Numeric comparison (booleans are not numbers) |
| `max_length` | `len(value)` is at most this |
| `present` | The selector resolves to something |
| `absent` | The selector resolves to nothing |

Several operators on one selector must **all** hold. A constraint with no
operators is a config error.

### Modifiers

| Modifier | Effect |
|---|---|
| `optional: true` | A selector that resolves to nothing satisfies the constraint |
| `quantifier: all` | With a wildcard, every match must pass (**default**) |
| `quantifier: any` | With a wildcard, at least one match must pass |

---

## Four decisions that are not obvious

These are where the language deliberately differs from what you might assume.
Each closes a bypass.

### `matches` is a full match

```yaml
args.entity_id: {matches: "light\\..*"}
```

matches `light.kitchen` and **not** `evil/light.kitchen`. Anchors still work and
are simply redundant; the linter notes them. The reasoning: `^` and `$` are the
two characters people forget, and forgetting them in an *allow* rule is a
bypass rather than a bug you notice.

### A missing argument fails the constraint

```yaml
args.domain: {in: [light]}
```

against `{"service": "turn_on"}` — with no `domain` at all — does **not** hold.
Vacuous truth in an allow rule means dropping an argument satisfies the rule
that was written to constrain it. Say `optional: true` if you meant it.

To require absence, use `absent`:

```yaml
args.force: {absent: true}
```

### Wildcards require every element to pass

```yaml
args.entity_id[*]: {matches: "light\\..*"}
```

holds for `["light.a", "light.b"]` and not for `["light.a", "lock.front"]`. A
rule constraining a batch operation must not be satisfiable by including one
permitted element alongside forbidden ones. `quantifier: any` opts out, and the
linter warns when you do so in an allow rule.

### Oversized values fail closed

Values longer than 4 KiB are not handed to the regex engine, and the constraint
fails — for `matches` and `not_matches` alike. Tool arguments are
attacker-influenced whenever the model has read untrusted content, and a
policy author's innocent-looking pattern can backtrack catastrophically on a
crafted string.

---

## Upstreams

```yaml
upstreams:
  hass:                              # subprocess over stdio
    transport: stdio
    command: uvx
    args: [hass-mcp]
    env:
      HA_URL: ${HA_URL}              # unset variable = startup error, not ""
      HA_TOKEN: ${HA_TOKEN}
    inherit_env: [PATH]              # nothing is inherited unless named
    cwd: /opt/hass

  github:                            # remote, over streamable HTTP
    transport: http
    url: https://api.example.com/mcp
    headers:
      Authorization: Bearer ${GITHUB_TOKEN}
    timeout: 30
```

Subprocess upstreams inherit **no** environment by default, so an upstream never
sees the gateway's other credentials.

### Namespacing

```yaml
server:
  namespace: auto            # auto | always | never
  namespace_separator: "__"
```

`auto` prefixes tool names with the upstream name only when more than one
upstream is configured, so a single-upstream gateway is a drop-in replacement
for the server it fronts. Rules always match the gateway-facing name.

If two upstreams claim the same gateway-facing name, **both** are dropped and an
error is logged. Picking the one that connected first would make routing a
matter of dict ordering.

---

## Tokens

Only needed for HTTP; under stdio the client picks a policy with `--policy`.

```console
$ mcp-policy-gateway token new laptop --policy general-assistant
```

```yaml
tokens:
  - name: laptop                     # the identity in the audit log
    policy: general-assistant
    sha256: 3b2f...                  # preferred: commit this, not a secret
  - name: ci
    policy: readonly
    env: MPG_TOKEN_CI                # alternative: read plaintext at startup
```

Exactly one of `sha256` or `env` per token. Two tokens with the same value are a
startup error, since one would silently shadow the other and the audit log would
name the wrong caller.

---

## Rate limits

```yaml
rate_limits:
  actuation:
    rate: 20          # tokens added per `per`
    per: 1m           # 500ms | 30s | 5m | 1h, or a bare number of seconds
    burst: 8          # bucket capacity (defaults to `rate`)
    scope: token      # token (per caller, default) | global (shared)
```

Buckets are consumed only by calls that are **allowed** — a refused call does
not spend budget. A rule naming several buckets debits all of them or none, so a
client cannot drain an unrelated budget by hammering one it has already
exhausted. Naming `rate_limits` on a `deny` rule is a config error.

State is in memory: it resets on restart and is not shared across processes.

---

## Audit

```yaml
audit:
  path: ./audit.jsonl        # null to disable
  hash_chain: true
  include_arguments: true
  max_value_length: 512
  redact:                    # selector paths to digest
    - args.template
  redact_key_patterns:       # keys to digest wherever they appear
    - "(?i)(pass(word|wd)|secret|token|api[-_ ]?key|authorization|credential)"
```

The default `redact_key_patterns` already covers the usual credential names;
setting the key replaces the default rather than adding to it.

Set `MPG_REDACTION_KEY` to keep digests comparable across restarts. Left unset,
each run uses a fresh random key — the safer default for a log that may be
shared.

---

## Modes

| Mode | Behaviour |
|---|---|
| `enforce` | Denials are enforced (default) |
| `dry-run` | Every decision is logged; nothing is blocked |

Set it globally (`mode:`), per policy (`policies.<name>.mode`), or per run
(`--dry-run`). Dry-run records appear with `outcome: "dry-run-allowed"` and a
reason beginning `DRY-RUN: would deny`, so:

```console
$ mcp-policy-gateway audit summary audit.jsonl --outcome dry-run-allowed
```

lists exactly what a policy would have broken.

---

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success; `explain` allowed the call |
| 1 | Error (bad config, unreadable file, bad arguments) |
| 2 | `explain` denied the call |
| 3 | `validate` found errors, or `audit verify` found tampering |

Distinct codes so CI can tell "the policy blocked it" from "the tool broke":

```bash
# assert that a policy blocks something, and fail if it stops blocking it
mcp-policy-gateway explain -c policy.yaml --policy assistant \
    --tool ha_restart --args '{}'
test $? -eq 2 || exit 1
```
