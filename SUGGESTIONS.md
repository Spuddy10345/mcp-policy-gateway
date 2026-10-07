# Improvement backlog — mcp-policy-gateway

Forward-looking work, separate from `REVIEW.md` (which records defects). Nothing
here is a bug you have to fix today; it is the set of changes that would most
improve the project as a security tool people are asked to trust.

Ordered within each section by value. Where a claim is measurable I measured it.

---

## A. Architecture

### A1. Collapse the three request handlers into one authorisation pipeline

`_handle_call_tool`, `_handle_read_resource` and `_handle_get_prompt` are each
~70 lines running the identical sequence: resolve identity → resolve policy →
compute mode → resolve target → evaluate → deny-and-record / forward-and-record.
They were clearly written by copying, and they have since drifted:

| | tools | resources | prompts |
|---|---|---|---|
| routing | `pool.resolve()` | reaches into `pool._resource_routes` | `pool.resolve_prompt()` |
| dry-run denial | forwards, records `dry-run-allowed` | logs only, **no record** | logs only, **no record** |
| would-be rate limit | recorded | n/a | n/a |
| refusal to caller | `_refusal_text` | empty result | `description=` |
| unauthenticated | `_error_result` | `_meta={"is_error": True}` + a comment admitting uncertainty | `description="Unauthenticated"` |

Every anomaly I found in this codebase lives in the resource column. That is not
a coincidence — it is what duplicated control flow does over time. A single
`_authorise(context, target, event) -> Authorised | Refused` used by all three
would make the divergences impossible rather than merely fixed.

This is the highest-value structural change in the repo.

### A2. Break the `config` ↔ `matching` import cycle

`matching.py` imports `Constraint` from `config.py` at module scope; `config.py`
now needs `validate_selector` and `unsafe_repetition` from `matching.py` and gets
them through three function-level imports. That works, and it is a smell that
will be copied.

Extract the selector and pattern primitives — `parse_selector`, `validate_selector`,
`resolve`, `unsafe_repetition`, `SELECTOR_ROOTS`, `MAX_REGEX_INPUT` — into
`selectors.py`, which imports neither. `config` and `matching` both depend on it,
the cycle disappears, and the imports move back to the top of the file.

### A3. The gateway authorises requests and trusts responses

This is the largest conceptual gap. Every enforcement point is on the way *in*.
On the way *out*, `pool.call()`'s result is returned to the model verbatim: no
size limit, no content inspection, no policy hook. For a tool whose premise is
"the model may be driven by injected instructions", the channel by which
injected instructions actually arrive — tool output containing attacker text —
has no policy over it at all.

I am not proposing a classifier (Limitation #4 rejects that, correctly). But the
architecture should at least have a seam:

- a per-rule `max_result_bytes`, so one tool call cannot return a megabyte of
  attacker-authored text into the context window;
- a `deny_result_matching` constraint reusing the existing regex machinery, for
  operators who want to strip or refuse known-bad markers;
- failing both, an explicit statement in `THREAT_MODEL.md` that responses are
  trusted, so a reviewer knows it is a decision rather than an oversight.

### A4. Pin tool definitions so a "rug pull" needs re-approval

T4 acknowledges that descriptions pass through unmodified. The sharper version
is that an upstream can change a tool's description *after* the operator wrote a
policy against it — approve `ha_get_state` as a benign reader on Monday, get a
description full of instructions on Friday, same name, same rules.

A `tools:` entry could optionally carry a digest of the tool's name + description
+ input schema. Mismatch → the tool is hidden and the change is audited. That
turns a silent substitution into a visible one, which is this project's whole
philosophy applied to a surface it currently leaves open.

### A5. Decide what the error taxonomy is

`errors.py` defines `PolicyDenied` and `RateLimited`. Neither is raised anywhere
(hence `errors.py` at 62% coverage). Meanwhile the engine signals denial by
returning a `Decision`, the pool signals failure by raising `UpstreamError`, and
`matching` raises `SelectorError`, which inherits `ValueError` and **not**
`GatewayError` — so `cli.main`'s `except GatewayError` does not catch it.

Either raise the two unused classes and make the contract uniform, or delete them
and make `SelectorError` a `ConfigError`. Right now a reader has to check each
module to learn how it reports failure.

---

## B. Security hardening

### B1. `THREAT_MODEL.md` is wrong about the gateway's own attack surface

Limitation #7 states:

> **Resources and prompts are not proxied.** They are not exposed at all, which
> fails closed [...]

They are proxied. There are four handlers wired in `build_server()` and four
passing tests exercising them. A reviewer who reads the threat model will not
audit that surface — and it is the least-covered, most-divergent code in the
repo (see A1 and D1).

For a security tool, a threat model that understates the surface is worse than
no threat model. Fix the section, and re-run the T-series claims against the
current code; #6 and #8 should also be re-checked.

### B2. Bind every audit record to the policy that produced it

The log records the rule *name* that fired. It does not record which version of
the config that name referred to. Rename a rule, loosen a constraint, restart —
the old records still say `allow lights` and there is no way to show what
`allow lights` meant at the time.

Add a config fingerprint (SHA-256 over the validated, normalised config) to
`AuditRecord`, and print it at startup. It costs one field and turns "the log
says this was allowed" into "the log says this was allowed *by this policy*",
which is what an incident review actually needs.

### B3. Give the audit log a durability and rotation story

Two gaps, both operational:

- **No `fsync`.** `write()` calls `flush()`, which reaches the OS and not the
  disk. A power loss drops records that the gateway reported as written. Offer
  `audit.fsync: true` for deployments that need it.
- **No rotation.** The file grows without bound, and naive rotation breaks the
  hash chain. Chain-aware rotation — close a segment with an anchor record
  carrying the final hash, start the next segment from it, and teach
  `audit verify` to follow the anchors — is the right shape.

### B4. Defence in depth for regex evaluation

`unsafe_repetition` (added this pass) rejects the dominant catastrophic shape at
config load, but it is deliberately not a decision procedure — it does not catch
overlapping alternations like `(a|ab)*`. Two options that would close the
residual risk:

- the `regex` package supports `regex.fullmatch(..., timeout=...)`, which bounds
  the work directly. One dependency, complete mitigation.
- or evaluate constraints in a worker thread with a deadline. This does not
  cancel the runaway thread, but it converts "the whole event loop is wedged for
  every caller" into "one request denied, one thread leaked".

### B5. Bound what a single call can write to the log

`Redactor._truncate` caps individual leaf strings at `max_value_length`; nothing
caps the *structure*. A tool call carrying a 100k-element array writes all of it.
`_handle_call_tool` takes care that an unauthenticated caller cannot grow the
log; an authenticated one can grow it without limit. Cap total serialised record
size and note the truncation in the record.

---

## C. Performance

### C1. The audit write is blocking I/O on the event loop

`AuditLog.write` is `async`, but its body is not:

```python
async with self._lock:
    ...
    self._stream.write(json.dumps(payload, default=str) + "\n")
    self._stream.flush()
```

Both calls are synchronous file I/O, executed on the event loop thread, inside a
lock every request must pass through. Under concurrency the gateway serialises
all traffic behind one disk write. This is the single worst scaling property in
the codebase and it is on the hot path of every call.

Fix: a background writer task fed by a memory channel, or `anyio.to_thread.run_sync`
for the write. The lock can then protect only the sequence/hash update, which is
pure computation.

### C2. Precompile regexes into the `Constraint`

`_op_matches` calls `re.fullmatch(operand, text)` with a pattern string on every
evaluation, relying on `re`'s internal 512-entry cache. A deployment with many
patterns evicts, and cache lookup is on the hot path regardless. Compile once in
the field validator (which already compiles them to check validity, then throws
the result away) and store the compiled object.

### C3. Cache the route table instead of rebuilding it per request

`_handle_list_tools` calls `pool.catalogue()` on every `tools/list`, which
re-walks every connection's cached tool list, re-derives every gateway name,
re-detects collisions and rebuilds `_routes`. The underlying data cannot change
between calls (nothing invalidates it — see C4). Build it once, rebuild on
explicit invalidation.

### C4. Wire cache invalidation to something

`UpstreamConnection.invalidate()` and `catalogue(refresh=True)` are called only
from tests. Nothing subscribes to upstream `notifications/tools/list_changed`.
Limitation #6 acknowledges the stale-catalogue behaviour in the fail-closed
direction; the other direction is that a tool *removed* upstream stays advertised
and routes to an error. Subscribing to the notification, or a periodic refresh,
would close both.

### C5. Memoise visibility filtering

`is_visible` runs the rule list per tool per `tools/list` request — O(rules ×
tools) with no caching, for a result that only changes when the policy or the
catalogue changes. Key a cache on (policy name, catalogue version).

---

## D. Testing

### D1. The enforcement core has the worst coverage

Measured, `--cov-branch`:

| module | coverage |
|---|---|
| `identity.py` | 99% |
| `ratelimit.py` | 98% |
| `engine.py` | 97% |
| `config.py` | 95% |
| `matching.py` | 90% |
| `upstream.py` | 85% |
| **`gateway.py`** | **73%** |
| `server.py` | 66% |

`gateway.py` is where authorisation actually happens, and it is last. The missing
lines are almost entirely `_handle_list_resources` / `_handle_read_resource` /
`_handle_list_prompts` / `_handle_get_prompt` — two whole protocol surfaces
covered by four happy/sad-path tests, with no tests at all for their dry-run
behaviour, their error paths, their unauthenticated paths, or their audit
records. See B1: the threat model says this surface does not exist.

### D2. Boot the transports at least once

`server.py` at 66% means nothing exercises `build_gateway`, `run_stdio` or
`run_http` end to end. `test_http.py` builds the ASGI app directly. A smoke test
that actually starts and shuts down each transport would catch wiring breaks that
every current test is structured to miss.

### D3. Property-based tests where they pay

Three components have the shape hypothesis is built for:

- `parse_selector` / `validate_selector` — round-trip and never-crash properties
  over generated selector strings;
- `matches_any` — glob semantics, especially around the `[seq]` character-class
  behaviour `fnmatchcase` inherits;
- the audit chain — for any sequence of records, `verify_chain` accepts the log,
  and for any single-byte mutation, rejects it. That is a much stronger statement
  than the current fixed-fixture tampering tests.

A fuzz target over `load_config` would also be cheap: the property is simply
"never raises anything that is not a `ConfigError`".

### D4. Nothing tests concurrency

`AuditLog.write` and `RateLimiter.acquire` both take locks, and both have
comments explaining why the locking matters. No test ever has two tasks contend
for either. A test that fires N concurrent calls and asserts the audit sequence
numbers are `1..N` with an intact chain would give those comments teeth — and
would have caught the C1 blocking-I/O issue as a latency regression.

### D5. Consider mutation testing

The suite leans on asserting `outcome == "denied"`. That is exactly the assertion
shape where a mutant flipping a default (`hide_denied_tools`, `default: deny`,
a comparison operator) survives, because the test passes for the wrong reason.
`mutmut` or `cosmic-ray` over `engine.py` and `matching.py` would be a strong
signal for a project whose value proposition is that its decisions are correct.

### D6. Explain or delete `tests/windows.py.fail`

An unexplained non-Python artifact in the test directory. If it documents a known
Windows failure it belongs in an issue or a skipped test with a reason.

---

## E. Maintainability

### E1. Documentation drift is the recurring failure mode here

Across two review passes, five separate places said something the code did not do:

- `docs/policy-language.md`: "malformed selectors are rejected when the config
  loads" — they were not (fixed).
- `matching.py`: "Truncating bounds the work" — it does not (fixed).
- `_refusal_text`: "not the rule's internals" — it leaks them (open, P2/5).
- `_tail_chain_state`: "verification will flag it" — it aborts on the whole file
  (open, P2/6).
- `THREAT_MODEL.md` #7: "resources and prompts are not proxied" — they are (open, B1).

Every one of these is a comment asserting a security property that no test holds
it to. The fix is not more careful writing; it is that a comment claiming a
security property should cite the test that enforces it. `THREAT_MODEL.md`
already has a "Testing the claims" section doing exactly this — extend that
convention to the code.

### E2. Add a CHANGELOG

This pass alone changed constraint-detail formatting, added an `Outcome` value,
tightened `Constraint` validation, and altered `present: true` semantics for
explicit nulls. At `0.1.0` with a published wheel in `dist/`, that needs
recording.

### E3. Update `docs/policy-language.md`

Not yet reflected: the regex restriction and its rationale, the selector-root
validation, the rejection of `present: false` / `absent: false`, and the fact
that constraint failures now describe values rather than printing them (which
policy authors will notice in `explain` output).

### E4. Small dead code

`cli._fail` is unreachable (`# pragma: no cover - convenience for future
subcommands`). `__main__.py` is at 0% coverage. Both are fine to keep; both
should be deliberate rather than incidental.
