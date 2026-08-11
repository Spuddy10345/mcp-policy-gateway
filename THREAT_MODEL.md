# Threat model

What this software defends against, what it does not, and the assumptions
holding the two apart. If you only read one section, read
[Limitations](#limitations) — a security tool that only documents its wins is
selling something.

---

## System and trust boundaries

```
  ┌─ untrusted ─────────────────┐   ┌─ trusted ──────────┐   ┌─ upstream ────┐
  │                             │   │                    │   │               │
  │  web pages, emails,         │   │  policy.yaml       │   │  hass, github │
  │  calendar invites, files,   │   │  token digests     │   │  filesystem   │
  │  tool results, the model    │──▶│  the gateway       │──▶│  ...          │
  │  and everything it decides  │   │  the audit log     │   │               │
  │                             │   │                    │   │               │
  └─────────────────────────────┘   └────────────────────┘   └───────────────┘
                                 ▲                        ▲
                          trust boundary 1         trust boundary 2
```

**Boundary 1 is the one that matters.** The model, and every tool call it emits,
is on the untrusted side. This is the assumption the whole design rests on: a
model that has read attacker-controlled text is an attacker-controlled
component, and no amount of instruction-tuning changes what it *can* emit.

**Boundary 2** is conventional. Upstream servers are trusted to do what they say
and to enforce their own authorisation; the gateway constrains which of their
operations are reachable, not what they do internally.

### Assets

| Asset | Why it matters |
|---|---|
| Upstream tool invocations | The actual capability: deleting entities, unlocking doors, pushing commits |
| Upstream credentials | The `HA_TOKEN` etc. the gateway passes to subprocesses |
| Gateway bearer tokens | Presenting one selects a policy |
| The policy file | Its contents *are* the security posture |
| The audit log | The only record that an attack was attempted |

### Actors

| Actor | Capability assumed |
|---|---|
| **Injected model** | Emits any sequence of tool calls with any arguments. Reads every tool description and result. Primary adversary. |
| **Malicious upstream** | Returns arbitrary content, including tool descriptions crafted to influence the model. |
| **Network attacker (HTTP mode)** | Can reach the listening port; cannot read the config file. |
| **Local attacker** | Has a shell as the gateway's user. Assumed to win, mostly — see [Limitations](#limitations). |

---

## Attacks and how they are handled

### T1. Injected model calls a destructive tool

*A web page, calendar entry or file tells the model to call `ha_remove_entity`.*

**Handled.** The call is evaluated against the caller's policy and refused; the
upstream never sees it. Demonstrated end to end by `demo/prompt_injection.py`
and asserted in `tests/test_gateway.py::test_denied_call_never_reaches_upstream`.

Defence in depth, in order of importance:

1. **Enforcement at `tools/call`** — the control. Argument-independent of how
   the model learned the tool's name.
2. **Omission from `tools/list`** — a tool the policy can never permit is not
   advertised, so an injection has to already know the name to try it.
3. **Server instructions** telling the model to report refusals rather than
   route around them. Advisory only, and counted as worth nothing against a
   model that is already following someone else's instructions.

### T2. Injected model reaches a dangerous *argument* of a permitted tool

*`ha_call_service` is allowed for lights. The injection calls it with
`domain: lock, service: unlock`.*

**Handled, and this is the interesting case.** Tool-name allow-listing cannot
express it — one tool, one name, two wildly different capabilities. Rules
constrain arguments directly, and the decision is re-derived from the arguments
of the call in hand rather than inherited from the listing.

The same reasoning drives three language decisions:

- `matches` is a **full match**, so `light\..*` does not admit `x/light.bypass`.
- A **missing** argument fails its constraint rather than passing vacuously, so
  dropping `domain` from the call does not satisfy a rule that constrains it.
- Wildcards are **universally quantified**, so a batch call cannot hide
  `lock.front_door` among two lamps.

### T3. Injected model escalates by trying every tool

**Partly handled.** Rate limits bound the attempt rate, and every attempt is
logged with the arguments that were tried, so probing is loud. The gateway does
not lock a token out after N denials — an automatic lockout is itself a denial
of service an attacker can trigger deliberately. Detection is via the audit log;
`mcp-policy-gateway audit summary` groups denials by tool and token.

### T4. Malicious or compromised upstream influences the model

*An upstream renames a tool to `ha_get_state_SAFE_ALWAYS_ALLOWED`, or puts
instructions in a tool description.*

**Partly handled.** Policy is keyed on tool names, and a renamed tool matches
different rules — which under `default: deny` means it stops being permitted
rather than starting to be. Tool *descriptions* are passed to the client
unmodified, so an upstream can still attempt to influence the model through
them. Treat upstreams as software you have chosen to run.

### T5. Tool-name collision between upstreams

*Two upstreams both export `search`; a rule allowing `search` was written with
one of them in mind.*

**Handled.** Names are namespaced per upstream by default when more than one is
configured. If namespacing is disabled and names collide, **all** colliding
tools are dropped rather than one shadowing the other — resolving it by
connection order would make routing a matter of luck.

### T6. Stolen gateway token

**Partly handled.** A token grants exactly its policy, so the blast radius is
whatever that policy permits — the reason to issue `readonly` rather than one
credential for everything. There is no expiry or revocation list beyond editing
the config and restarting. Every call the token makes is attributed to it by
name in the audit log.

The config stores SHA-256 digests, not tokens, so a stolen *config* yields no
usable credential.

### T7. Credentials leaking into the audit log

*An argument contains an API key; the log becomes a second copy of every secret
that passed through.*

**Handled.** Values under keys matching credential-shaped patterns
(`password`, `token`, `api_key`, `secret`, `authorization`, …) are replaced with
a keyed digest, at any depth, plus any selector paths the operator names.
Digests are HMAC-SHA-256 under a per-process random key, so equal values are
visibly equal without the log revealing either. Set `MPG_REDACTION_KEY` to keep
digests comparable across restarts. `include_arguments: false` drops payloads
entirely while keeping the decision trail.

### T8. Tampering with the audit log

**Partly handled — read this one carefully.** Records are hash-chained: each
carries the SHA-256 of its predecessor's content, so *editing* or *deleting* a
record breaks every link after it, and `audit verify` names the line.

It does **not** stop an attacker with write access from truncating the log or
rebuilding the whole chain from scratch. Nothing purely local can. What chaining
buys is that quietly removing the single record that incriminates you is no
longer possible — you must rewrite everything after it, and if any copy of the
old tail exists anywhere, the forgery is evident. For stronger guarantees, ship
records off-host as they are written.

### T9. Denial of service against the gateway

**Partly handled.** Rate limits cap upstream load per caller. Regular
expressions in policies are evaluated against attacker-influenced arguments, so
values over 4 KiB are not handed to the regex engine at all and the constraint
fails closed — bounding the catastrophic-backtracking exposure a policy author
can accidentally create. Upstream calls have a deadline (`upstream_timeout`) so
a hung server does not pin a request forever.

The gateway is a single process with no work queue. Nothing stops an authorised
caller from saturating it with allowed calls.

### T10. Config errors that fail open

*The largest realistic risk in practice, and not an attack at all.*

**Handled structurally.** Every mechanism here exists because policy files are
where the real mistakes live:

- Unknown keys are **rejected**, not ignored (`deney:` is an error).
- Policy default is **deny** unless stated otherwise.
- Dangling references — a token naming a missing policy, a rule naming a missing
  rate limit — refuse to start.
- `rate_limits` on a `deny` rule is an error, because it reads as if it does
  something.
- `tools: []` is an error, because it reads as "no tools" but matches everything.
- The linter flags unreachable rules, unconstrained allow rules, regexes that
  narrow nothing, and `optional`/`quantifier: any` where they weaken an allow.
- `explain` answers "what would this policy do with this call" without deploying
  anything, and exits non-zero on a denial so it can be asserted in CI.
- `--dry-run` lets a policy be validated against real traffic before it enforces.

### T11. Unauthenticated access over HTTP

**Handled.** There is no anonymous path and no default identity. Requests
without a valid bearer token are rejected at the ASGI layer with a 401 before
reaching the MCP machinery, and the handler independently re-derives identity
from the request it is serving. Starting an HTTP gateway with no tokens
configured is a startup error rather than a service that treats everyone as
nobody.

Identity is read per request rather than from a context variable set by
middleware, because a request under streamable HTTP is handed to a session task
and context does not reliably follow it — the failure mode being a call
authorised as whoever was served last.

### T12. Upstream credentials leaking to the wrong upstream

**Handled.** Subprocess upstreams inherit **no** environment by default; each
gets only what its `env:` block names, and `inherit_env` must list any variable
explicitly. A `${VAR}` that is unset is a startup error, never an empty string —
expanding a credential to `""` is how a gateway ends up talking to an upstream
unauthenticated.

---

## Limitations

Stated plainly, because these are the questions a reviewer should ask.

1. **An allowed call is unconstrained.** The gateway decides whether a call
   happens. Once it does, it runs with the upstream's full authority. This is
   not a sandbox.

2. **A local attacker wins.** Anyone who can write the policy file, replace the
   binary, or read the process environment has already bypassed this. Protect
   the config as you would any other security-relevant file; the audit log is
   created `0600`.

3. **Truncating the audit log is undetectable locally.** See T8.

4. **No detection, only enforcement.** There is no classifier looking for
   injection. That is deliberate — a policy holds against attacks nobody has
   thought of, and a classifier holds against the ones in its training set — but
   it means the gateway cannot tell you that an attack *occurred*, only that a
   call was refused.

5. **Policy quality is the ceiling.** A policy that allows `ha_call_service` for
   every domain provides no protection against T2 no matter how correct the
   engine is. The linter and `explain` exist to make the policy reviewable;
   they cannot make it right.

6. **The tool catalogue is cached.** An upstream that changes its tools mid-
   session is not noticed until the cache is invalidated. Under `default: deny`
   this fails closed — a new tool is denied, not allowed.

7. **Resources and prompts are not proxied.** They are not exposed at all, which
   fails closed but also means the gateway cannot front a server whose value is
   in its resources.

8. **Rate limiter state is in memory.** It resets on restart and is not shared
   across processes. A gateway that is restarted in a loop has no effective rate
   limit.

---

## Testing the claims

Each of the above is asserted somewhere, not just described:

| Claim | Where |
|---|---|
| Denied calls never reach the upstream | `tests/test_gateway.py::test_denied_call_never_reaches_upstream` |
| Same tool, different arguments, different verdict | `tests/test_gateway.py::test_argument_level_policy_allows_and_denies_the_same_tool` |
| Hidden tools are still enforced | `tests/test_gateway.py::test_hidden_tool_is_still_enforced_when_called_by_name` |
| Missing arguments do not satisfy constraints | `tests/test_matching.py::test_missing_argument_fails_a_constraint_rather_than_passing_vacuously` |
| `matches` cannot be bypassed by substring | `tests/test_matching.py::test_matches_is_a_full_match_not_a_search` |
| Batch calls cannot smuggle elements | `tests/test_matching.py::test_wildcard_defaults_to_requiring_every_element_to_pass` |
| Oversized values do not reach the regex engine | `tests/test_matching.py::test_oversized_value_is_not_handed_to_the_regex_engine` |
| Edited and deleted audit records are detected | `tests/test_audit.py::test_verify_detects_an_edited_record`, `...a_deleted_record` |
| Truncation is *not* detected | `tests/test_audit.py::test_verify_reports_a_truncated_log_as_intact` |
| Credentials are redacted at any depth | `tests/test_audit.py::test_nested_credentials_are_found` |
| Unauthenticated HTTP requests are rejected | `tests/test_http.py::test_a_request_with_no_token_is_rejected` |
| Two tokens get two toolboxes from one process | `tests/test_http.py::test_two_tokens_get_different_toolboxes_from_one_process` |
| Upstreams inherit no environment by default | `tests/test_config.py::test_upstream_env_is_not_inherited_by_default` |
| The whole attack, end to end | `tests/test_demo.py` |

## Reporting a vulnerability

Open a GitHub issue for anything already public. For something that is not,
use GitHub's private vulnerability reporting on this repository.
