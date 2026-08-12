## What this changes and why

<!-- One or two sentences. If this fixes an issue, link it: Fixes #123 -->

## Checklist

- [ ] `uv run pytest` passes locally, including new tests for the change
- [ ] `uv run ruff check .` and `uv run pyright src` are clean
- [ ] If this touches `engine.py`, `matching.py`, or `gateway.py`: a test
      asserts the *security-relevant* behaviour, not just that it runs
      (see `tests/test_gateway.py` / `tests/test_matching.py` for the pattern)
- [ ] If this changes what a policy can express: `docs/policy-language.md` is
      updated to match
- [ ] If this changes what the gateway defends against (or doesn't):
      `THREAT_MODEL.md` is updated — a security claim that drifts from the
      code is worse than no claim at all
- [ ] If this adds a config key: unknown-key rejection still covers it, and
      a sensible failure mode was chosen deliberately (see T10 in the threat
      model for what "deliberately" means here)

## Anything a reviewer should know before reading the diff

<!-- Non-obvious trade-offs, things you considered and rejected, TODOs you left on purpose. -->
