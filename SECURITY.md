# Security policy

This is a security tool. If it has a vulnerability, that matters more here
than it would in most projects — please report it privately rather than as a
public issue.

## Supported versions

Pre-1.0, only the latest published release on PyPI is supported. There is no
backport policy yet; fixes land on `main` and ship in the next release.

| Version | Supported |
|---|---|
| latest `0.x` | yes |
| anything older | no |

## Reporting a vulnerability

**Private reporting is not currently configured for this repository.**
Maintainers must enable GitHub Private Vulnerability Reporting or provide a
monitored private contact channel before this policy can accept reports. Do
not disclose vulnerability details in a public issue. Once enabled, reports
submitted through GitHub are visible to repository maintainers, the reporter,
and any collaborators invited to the advisory. Maintainers can publish an
advisory without the reporter's agreement, so coordinate disclosure with the
maintainers before sharing details publicly.

Please include, where you can:

- The version (or commit SHA) affected.
- A minimal `policy.yaml` and call that reproduces the issue.
- What you expected the gateway to do, and what it did instead.
- Whether this is a bypass of an *enforced* control, or a gap in something
  documented as a [known limitation](THREAT_MODEL.md#limitations) — the
  latter is still worth reporting, but is triaged differently from a control
  silently failing.

## What counts as a security issue here

Read [THREAT_MODEL.md](THREAT_MODEL.md) first — it draws the line between
"defended against" and "explicitly out of scope" in detail. Roughly:

**Please report:**
- A policy that should deny a call but allows it (or the reverse, if it fails
  in a way that breaks a legitimate caller in a security-relevant way).
- A way to make a denied tool reachable anyway — by name, by argument
  shape, by an upstream-name collision, etc.
- A way to make the audit log accept a tampered record as valid, or to make
  credential redaction miss a value it should have caught.
- Anything in the HTTP transport that lets a request be served under the
  wrong identity, or with no identity at all.
- Supply-chain concerns in the release pipeline itself (the publish workflow,
  its permissions, its dependencies).

**Please don't bother reporting** (open a normal issue instead — these are
documented non-goals, not bugs):
- "An allowed call did something bad" — see [Non-goals](README.md#non-goals),
  this is not a sandbox.
- "The audit log doesn't detect truncation" — documented in T8 and the
  Limitations section, on purpose.
- Missing resource/prompt proxying — documented as not implemented yet.

## Response

This is currently a one-person project, so there is no SLA to promise. Expect
an acknowledgement within a few days. Fixes for confirmed issues will be
prioritised over everything else on the board, and you'll get credit in the
advisory and release notes unless you'd rather stay anonymous.
