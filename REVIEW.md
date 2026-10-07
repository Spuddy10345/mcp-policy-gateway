# Code review — mcp-policy-gateway

Second pass, 2026-09-10. Supersedes the earlier draft of this file, which ranked
cosmetics above two exploitable defects. Every finding below was reproduced against
the running gateway (`tests/conftest.py` harness), not inferred from reading.

**Status: P0 and P1 are fixed, with regression tests. P2 and P3 are open.**
287 tests passing (was 257), `ruff` clean. Forward-looking improvements — architecture,
performance, testing strategy — are in `SUGGESTIONS.md`.

| | finding | status |
|---|---|---|
| P0/1 | secrets in the audit log via `trace` | fixed |
| P0/2 | `MAX_REGEX_INPUT` does not bound regex work | fixed |
| P1/3 | policy typo → unaudited `Internal server error` | fixed |
| P1/4 | dry-run does not record rate-limit decisions | fixed |
| P2–P3 | — | open |

---

## P0 — Critical

### 1. The audit log writes tool arguments in plaintext, bypassing the redactor — FIXED

`Decision.trace` is written straight to `AuditRecord.trace` in `Gateway._record`
without passing through `AuditLog.redact`. The trace lines come from
`matching.evaluate_constraint`, whose failure detail embeds the *actual value*:

```python
return ConstraintResult(False, f"{selector}={_render(value)} {detail}{suffix}")
```

Reproduced — one record, both fields:

```
arguments: {"api_key": "[redacted:60c7e5d6695d57a1]", "password": "[redacted:9c2d..]"}
trace:     ["[allow rule #0] FAIL args.api_key='sk-live-SUPERSECRET-9999' != 'expected-key'"]
```

The redactor did its job on `arguments` and the same secret sits in cleartext two keys
away. It also defeats `include_arguments: false` — documented as the control "for
upstreams that handle regulated data" — which still emits the trace verbatim:

```
arguments: "[arguments not recorded]"
trace:     ["[allow rule #0] FAIL args.api_key='sk-live-SUPERSECRET-9999' != ..."]
```

Triggers on **every denied call** where a constraint on a sensitive field fails —
the common case, since `all` is the default quantifier. `max_value_length` is
bypassed too (trace uses `_render`'s own 80-char cap).

**Fixed.** Constraint details now describe the value instead of printing it —
`args.api_key (a 24-character string) != 'expected-key'`. That keeps everything a
policy author needs to debug a rule (which selector, what kind of value, what was
expected, how many failed) and drops the only part that was sensitive. The value
itself remains in `arguments`, redacted according to policy.

Worth noting how this survived: `test_failure_detail_names_the_offending_value`
asserted `"lock.front" in result.detail`. The leak was not drift — it was a tested
requirement. That test is now inverted.

### 2. `MAX_REGEX_INPUT` does not bound regex work — one argument kills the gateway — FIXED

`matching.py` claims:

> Truncating bounds the work; a `matches` constraint on an over-long value fails closed.

That is false for catastrophic backtracking, which is exponential in input length,
not linear. Measured with `(a+)+b`:

| input length | time |
|---|---|
| 18 | 6 ms |
| 20 | 25 ms |
| 22 | 100 ms |
| 24 | 416 ms |

Roughly ×4 per two characters. `MAX_REGEX_INPUT` is **4096**. A ~30-character
argument hangs forever.

Worse, `PolicyEngine.evaluate` is synchronous and called directly on the anyio event
loop, so the hang takes down **every concurrent caller**, not just the attacker's
request. There is no timeout anywhere on the path. The threat model is exactly the
one the file's own comment describes: operator writes a plausible nested-quantifier
pattern, model reads untrusted content, attacker supplies the argument.

**Fixed.** `matching.unsafe_repetition` rejects the dominant catastrophic shape —
an unbounded quantifier over a group that already repeats unboundedly — when the
config loads, so the pattern never reaches evaluation. `(a+)+b`, `(a*)*`,
`([a-z]+)*z` and `(a+){2,}` are refused with a message naming the fragment;
`(https?)://.*`, `(a|b)+` and `\(a+\)+` still load.

The cap stays at 4096 (lowering it would fail-close legitimate long values) and its
comment now says what it actually does. The check is deliberately not a decision
procedure — it misses overlapping alternations like `(a|ab)*` — so `SUGGESTIONS.md`
B4 covers closing the residual gap with a real evaluation deadline.

---

## P1 — High

### 3. A policy typo becomes an unaudited `Internal server error` — FIXED

The previous pass added a `Rule.when` validator that runs `parse_selector`. It
validates *syntax* but not the *root name*, so the far likelier typo still gets
through. Reproduced:

```
config with selector root 'argz' ACCEPTED at load
  ...then raised at call time: SelectorError: unknown selector root 'argz'
```

End to end through the gateway:

```
raised out of the handler: MCPError: Internal server error
audit records written: 0
```

Two things break. `gateway.py`'s module docstring promises "Denials come back as tool
*results*, not protocol errors" — this is a protocol error. And **nothing is
written to the audit log**, so a policy that rejects every matching call leaves no
trace of having done so.

**Fixed**, all three parts:
- `matching.validate_selector` checks the root against `SELECTOR_ROOTS` as well as
  parsing, and `Rule.when` uses it — `argz.domain` is now refused at load;
- `AuditConfig.redact` gets the same validation, so `validate` no longer passes a
  config that `run` would refuse to boot;
- `PolicyEngine.evaluate` is now a fail-closed wrapper around `_evaluate`. It
  cannot raise: anything unexpected becomes a deny carrying `evaluation_error`,
  which the gateway records with `outcome="error"`.

One subtlety worth calling out: dry-run must **not** forward on an evaluation
error. Dry-run exists to second-guess a verdict, and an engine that fell over did
not reach one — forwarding there turns a broken policy into no policy.

### 4. Dry-run mode does not record rate-limit decisions — FIXED

`--dry-run` exists to "test a new policy against real traffic before trusting it",
and the way you read the result is the audit log. The deny path handles this
correctly (`outcome="dry-run-allowed"`, `reason="DRY-RUN: would deny (...)"`). The
rate-limit path only calls `logger.warning` and falls through to a normal
`_forward`. Reproduced with a 1-per-hour bucket and two calls:

```
outcome='allowed' reason="'send' matched"
outcome='allowed' reason="'send' matched"
```

**Fixed.** `_forward`'s ad-hoc `forced: bool` is replaced by a `_DryRunNote`
carrying the outcome and reason a dry-run record should show, which both the denial
path and the rate-limit path now supply. A would-be throttle records
`outcome="dry-run-rate-limited"`, `reason="DRY-RUN: would rate limit (...)"`.

---

## P2 — Medium

### 5. Refusal text leaks constraint selectors to the caller

`_refusal_text`'s docstring:

> It names the tool and gives the operator's reason, but not the rule's internals: a
> caller that can enumerate the policy by probing it has been handed a map of what to
> try next.

`Decision.reason` falls back to the joined constraint details when a rule has no
`reason:` set, so what actually reaches the agent is:

```
Denied by gateway policy: the call to 'send' was not permitted
(args.recipient satisfied). ...
```

An injected model now knows the gateway inspects `args.recipient` and can probe for
the boundary — in a tool whose stated purpose is defending against that model. The
shipped example policies set `reason:` on their deny rules so they dodge it, but the
language does not guarantee it. Fix: use a fixed string when `rule.reason` is `None`,
and have `lint` require `reason:` on deny rules.

### 6. One torn line makes the entire audit log unverifiable

`_tail_chain_state` skips an unparsable final line, commenting "Verification will
flag it; appending after it is still the right move." Verification does not flag it —
`read_records` raises and `verify_chain` returns `checked=0` for the whole file:

```
clean log:                    OK: 3 records, chain intact
after one torn final line:    FAILED: 1 problem(s) across 0 records
```

So an ordinary hard kill permanently destroys verifiability of all prior history,
and the gateway keeps appending to the now-unverifiable file. It is also a very cheap
denial-of-audit for anyone who can append one byte. Fix: make `verify_chain` report
the bad line and continue checking the records around it.

### 7. Catalogue caching has no invalidation path in production

`UpstreamConnection.invalidate()` and `catalogue(refresh=True)` are called only from
tests. Nothing subscribes to upstream `notifications/tools/list_changed`, so tool,
resource and prompt listings are frozen for the life of the process. A tool added
upstream is invisible until restart (fail-safe), and a tool *removed* upstream stays
advertised and routes to a 404 (not).

### 8. `namespace: auto` silently rewrites every tool name on the second upstream

With one upstream, `auto` means no prefix and rules are written as `ha_restart`. Add a
second upstream and every gateway-facing name becomes `hass__ha_restart`, so every
`tools:` pattern stops matching and the policy default takes over. That is
fail-closed, but it is a total outage from a one-line config change, and `lint` has
everything it needs to warn about it (it knows the upstream count, the separator, and
whether patterns contain it).

### 9. Audit records have no size bound

`Redactor._truncate` caps individual leaf strings at `max_value_length`, but nothing
caps structure. A tool call carrying a 100k-element array writes all of it. The
`_handle_call_tool` comment makes a point of not letting an *unauthenticated* caller
grow the log; an authenticated one can grow it without limit.

---

## P3 — Low

- **Duplicate `Authorization` header**: `BearerAuthMiddleware` builds a dict (last
  wins), the handler uses starlette `Headers.get` (first wins). Not obviously
  exploitable — both would have to be valid tokens the caller already holds — but the
  screening layer and the authorising layer should not be able to disagree about
  which credential they are looking at.
- **`AuditRecord.to_dict` drops falsy values** via `value not in (None, [], "")`, so a
  sub-millisecond call loses `duration_ms: 0.0`. Use `is None` / explicit checks.
- **`RateLimiter.snapshot()` reads buckets outside `self._lock`** while `acquire`
  mutates under it. Diagnostics-only today.
- **`lint._is_unbounded`**: `re.fullmatch(r"\.\*", stripped)` is fully subsumed by the
  `in (".*", ...)` check above it. And `pattern.strip("^$")` strips any mix from both
  ends — use `removeprefix("^")` / `removesuffix("$")`.
- **`matches_any` uses `fnmatchcase`**, so `[`/`]` in a tool pattern silently become a
  character class. Rare in tool names; worth a lint note.
- **`gateway._handle_read_resource` reaches into `pool._resource_routes`** where the
  tool and prompt paths use `resolve()` / `resolve_prompt()`. Style, but the
  asymmetry is why the resource path is the least-tested of the three.
- **Unauthenticated `read_resource`** returns `ReadResourceResult(contents=[],
  _meta={"is_error": True})` with a comment admitting uncertainty about the field. A
  caller cannot distinguish denied from empty.
- **`server.build_http_app` hard-codes `allowed_hosts`** to localhost plus the bind
  address; a deployment behind a reverse proxy needs a config key, not a code change.
- **Doubled `# noqa: ASYNC109  # noqa: ASYNC109`** in `upstream.py`.

---

## Assessment of the previous pass

| Fix | Verdict |
|---|---|
| `present: false` / `absent: false` | Directionally right, oversold, and hiding a regression |
| `when:` selector validation | Right instinct, **incomplete** — the original bug survives |
| Dead visibility helpers removed | Correct, zero-risk, low-value |

**`present`/`absent`.** Calling this a fail-open overstates it: `present: false` is
not in the docs, not in any shipped config, and nobody was relying on it. Rejecting
`absent: false` is a breaking schema change for zero security benefit (blast radius
is nil — nothing ships with it — but it should be a changelog line). More
importantly, the fix **silently changed `present: true` semantics** and this was not
flagged, tested, or documented:

```
present:true with args.domain=null -> False   (was True before the fix)
```

Routing `present` through `_op_present` means an explicit JSON `null` now fails the
constraint. That is arguably more correct and it is fail-closed, so it is safe — but
it is a behaviour change to a matching primitive shipped as a cosmetic cleanup.

**Selector validation.** The right thing to do, and the doc/impl gap it identified is
real. But it validates only that the string parses, and the overwhelmingly likely
typo is a wrong *root* (`argz.domain`, `arg.domain`, `params.x`), which still sails
through load and detonates at call time — see P1/3, where I reproduced exactly the
bug the fix was supposed to close. It also missed the sibling case in
`AuditConfig.redact`, and did not add the handler guard that would make the failure
mode auditable rather than a 500.

**Suggestions list.** Reasonable as far as it went, but it was a list of tidiness
items — private-attribute access, a dead regex branch, a doubled `noqa` — presented
at the same weight as everything else, and it missed all four P0/P1 defects. The
`allowed_hosts` and audit-record-size notes were the two with real substance. The
recurring pattern in the misses: it read comments and docstrings as statements of
fact rather than as claims to test. Three of the four top findings here are places
where the code says it does something and does not.
