"""Command-line interface.

Beyond `run`, the subcommands exist so a policy can be examined without being
deployed: `explain` answers "what would happen if…" against a real config, and
`validate` catches the fail-open mistakes before they are in front of anything.
"""

from __future__ import annotations

import argparse
import json
import logging
import secrets
import sys
from collections import Counter
from pathlib import Path
from typing import Any, NoReturn

import anyio

from . import __version__
from .audit import read_records, verify_chain
from .config import GatewayConfig, load_config
from .engine import PolicyEngine
from .errors import GatewayError
from .identity import resolve_launch_identity, token_digest
from .lint import lint
from .matching import MatchContext

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_DENIED = 2
EXIT_FINDINGS = 3


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    _configure_logging(args)

    try:
        return args.handler(args)
    except GatewayError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:  # pragma: no cover - interactive
        return 130


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-policy-gateway",
        description="An authorising reverse proxy for MCP servers.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase log verbosity")
    subparsers = parser.add_subparsers(dest="command", required=True)

    _add_run(subparsers)
    _add_validate(subparsers)
    _add_explain(subparsers)
    _add_audit(subparsers)
    _add_token(subparsers)

    return parser


def _config_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        required=True,
        metavar="PATH",
        help="path to the gateway config (YAML)",
    )


# ------------------------------------------------------------------------ run


def _add_run(subparsers: Any) -> None:
    parser = subparsers.add_parser("run", help="run the gateway")
    _config_argument(parser)
    parser.add_argument(
        "--transport",
        choices=("stdio", "http"),
        default="stdio",
        help="stdio (default) for a client that launches the gateway; http to serve many callers",
    )
    parser.add_argument("--token", metavar="NAME", help="stdio only: run as this configured token")
    parser.add_argument("--policy", metavar="NAME", help="stdio only: run under this policy directly")
    parser.add_argument("--host", default="127.0.0.1", help="http only (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="http only (default: 8080)")
    parser.add_argument("--path", default="/mcp", help="http only (default: /mcp)")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="log what policy would block, but forward everything. Use it to test a new policy "
        "against real traffic before trusting it.",
    )
    parser.add_argument(
        "--audit",
        type=Path,
        metavar="PATH",
        help="override the configured audit log path ('-' for stderr)",
    )
    parser.set_defaults(handler=_run)


def _run(args: argparse.Namespace) -> int:
    config = _load(args)

    if args.transport == "stdio":
        identity = resolve_launch_identity(config, token_name=args.token, policy_name=args.policy)
        _log_startup(config, f"stdio as {identity.name!r} (policy {identity.policy!r})")
        from .server import run_stdio

        anyio.run(run_stdio, config, identity)
        return EXIT_OK

    if args.token or args.policy:
        print(
            "error: --token/--policy apply to stdio only; over HTTP each request "
            "carries its own bearer token",
            file=sys.stderr,
        )
        return EXIT_ERROR

    _log_startup(config, f"http on {args.host}:{args.port}{args.path}")
    from .server import run_http

    async def serve() -> None:
        await run_http(config, host=args.host, port=args.port, path=args.path)

    anyio.run(serve)
    return EXIT_OK


def _log_startup(config: GatewayConfig, target: str) -> None:
    if config.mode == "dry-run":
        print(
            "WARNING: running in dry-run mode. Policy decisions are logged but NOT enforced.",
            file=sys.stderr,
        )
    logging.getLogger(__name__).info("starting gateway: %s", target)


# ------------------------------------------------------------------- validate


def _add_validate(subparsers: Any) -> None:
    parser = subparsers.add_parser("validate", help="parse and statically check a config")
    _config_argument(parser)
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit non-zero on warnings as well as errors (use this in CI)",
    )
    parser.set_defaults(handler=_validate)


def _validate(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    findings = lint(config)

    print(
        f"{args.config}: {len(config.upstreams)} upstream(s), "
        f"{len(config.policies)} policy(ies), {len(config.tokens)} token(s), mode={config.mode}"
    )

    for finding in findings:
        print(finding.format())

    counts = Counter(finding.severity for finding in findings)
    if counts["error"]:
        print(f"\n{counts['error']} error(s), {counts['warning']} warning(s)", file=sys.stderr)
        return EXIT_FINDINGS
    if args.strict and counts["warning"]:
        print(f"\n{counts['warning']} warning(s) (--strict)", file=sys.stderr)
        return EXIT_FINDINGS

    print("\nconfig is valid")
    return EXIT_OK


# --------------------------------------------------------------------- explain


def _add_explain(subparsers: Any) -> None:
    parser = subparsers.add_parser(
        "explain",
        help="show how a policy decides a specific call, without running anything",
    )
    _config_argument(parser)
    parser.add_argument("--policy", required=True, metavar="NAME")
    parser.add_argument("--tool", required=True, metavar="NAME", help="gateway-facing tool name")
    parser.add_argument(
        "--args",
        default="{}",
        metavar="JSON",
        help="tool arguments as a JSON object (default: {})",
    )
    parser.add_argument("--upstream", default="", help="upstream name, if rules match on it")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.set_defaults(handler=_explain)


def _explain(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    policy = config.policy_for(args.policy)

    try:
        arguments = json.loads(args.args)
    except json.JSONDecodeError as exc:
        print(f"error: --args is not valid JSON: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if not isinstance(arguments, dict):
        print("error: --args must be a JSON object", file=sys.stderr)
        return EXIT_ERROR

    upstream = args.upstream or _guess_upstream(config, args.tool)
    engine = PolicyEngine()
    context = MatchContext(tool=args.tool, upstream=upstream, arguments=arguments)
    decision = engine.evaluate(policy, context)
    visible = engine.is_visible(policy, args.tool, upstream)
    mode = config.effective_mode(policy)

    if args.json:
        print(
            json.dumps(
                {
                    "policy": args.policy,
                    "tool": args.tool,
                    "upstream": upstream,
                    "effect": decision.effect,
                    "enforced": mode == "enforce",
                    "rule": decision.rule_name,
                    "reason": decision.reason,
                    "rate_limits": list(decision.rate_limits),
                    "listed": visible,
                    "trace": list(decision.trace),
                },
                indent=2,
            )
        )
        return EXIT_OK if decision.allowed else EXIT_DENIED

    verdict = "ALLOW" if decision.allowed else "DENY"
    print(f"{verdict}  {args.tool}  (policy {args.policy!r}, upstream {upstream or '?'!r})")
    print(f"  matched:   {decision.rule_name or 'no rule — policy default'}")
    print(f"  reason:    {decision.reason}")
    if decision.rate_limits:
        print(f"  consumes:  {', '.join(decision.rate_limits)}")
    print(f"  listed:    {'yes' if visible else 'no — hidden from tools/list'}")
    if mode == "dry-run":
        print("  mode:      dry-run — this decision would be logged but NOT enforced")
    if decision.trace:
        print("  trace:")
        for line in decision.trace:
            print(f"    {line}")

    return EXIT_OK if decision.allowed else EXIT_DENIED


def _guess_upstream(config: GatewayConfig, tool: str) -> str:
    """Infer the upstream from a namespaced tool name, for convenience."""
    separator = config.server.namespace_separator
    if separator and separator in tool:
        candidate = tool.split(separator, 1)[0]
        if candidate in config.upstreams:
            return candidate
    return next(iter(config.upstreams), "")


# ----------------------------------------------------------------------- audit


def _add_audit(subparsers: Any) -> None:
    parser = subparsers.add_parser("audit", help="inspect an audit log")
    audit_subparsers = parser.add_subparsers(dest="audit_command", required=True)

    verify = audit_subparsers.add_parser("verify", help="check the hash chain for tampering")
    verify.add_argument("path", type=Path)
    verify.set_defaults(handler=_audit_verify)

    summary = audit_subparsers.add_parser("summary", help="counts by outcome, tool and token")
    summary.add_argument("path", type=Path)
    summary.add_argument("--outcome", help="only show records with this outcome")
    summary.set_defaults(handler=_audit_summary)


def _audit_verify(args: argparse.Namespace) -> int:
    result = verify_chain(args.path)
    for problem in result.problems:
        print(problem, file=sys.stderr)
    print(result.summary())
    return EXIT_OK if result.ok else EXIT_FINDINGS


def _audit_summary(args: argparse.Namespace) -> int:
    outcomes: Counter[str] = Counter()
    tools: Counter[str] = Counter()
    tokens: Counter[str] = Counter()
    denials: list[dict[str, Any]] = []

    for _, record in read_records(args.path):
        outcome = str(record.get("outcome", "?"))
        if args.outcome and outcome != args.outcome:
            continue
        outcomes[outcome] += 1
        tools[str(record.get("tool", "?"))] += 1
        tokens[str(record.get("token", "?"))] += 1
        if outcome in ("denied", "rate_limited"):
            denials.append(record)

    total = sum(outcomes.values())
    print(f"{args.path}: {total} record(s)\n")

    _print_counter("by outcome", outcomes)
    _print_counter("by tool", tools, limit=10)
    _print_counter("by token", tokens, limit=10)

    if denials:
        print(f"\nmost recent denials ({min(len(denials), 5)} of {len(denials)}):")
        for record in denials[-5:]:
            print(
                f"  {record.get('timestamp')}  {record.get('token')}  "
                f"{record.get('tool')}  {record.get('reason')}"
            )

    return EXIT_OK


def _print_counter(title: str, counter: Counter[str], *, limit: int | None = None) -> None:
    if not counter:
        return
    print(f"{title}:")
    for name, count in counter.most_common(limit):
        print(f"  {count:>6}  {name}")
    print()


# ----------------------------------------------------------------------- token


def _add_token(subparsers: Any) -> None:
    parser = subparsers.add_parser("token", help="generate and digest bearer tokens")
    token_subparsers = parser.add_subparsers(dest="token_command", required=True)

    new = token_subparsers.add_parser(
        "new",
        help="mint a token and print the config stanza to paste (the secret is shown once)",
    )
    new.add_argument("name")
    new.add_argument("--policy", required=True)
    new.set_defaults(handler=_token_new)

    digest = token_subparsers.add_parser("hash", help="print the SHA-256 of a token read from stdin")
    digest.set_defaults(handler=_token_hash)


def _token_new(args: argparse.Namespace) -> int:
    secret = secrets.token_urlsafe(32)
    print("# Add to your config's `tokens:` list.\n")
    print("  - name: " + args.name)
    print("    policy: " + args.policy)
    print("    sha256: " + token_digest(secret))
    print(f"\n# Bearer token (shown once, not recoverable from the digest above):\n{secret}")
    return EXIT_OK


def _token_hash(args: argparse.Namespace) -> int:
    del args
    secret = sys.stdin.read().strip()
    if not secret:
        print("error: no token on stdin", file=sys.stderr)
        return EXIT_ERROR
    print(token_digest(secret))
    return EXIT_OK


# ---------------------------------------------------------------------- shared


def _load(args: argparse.Namespace) -> GatewayConfig:
    config = load_config(args.config)
    updates: dict[str, Any] = {}

    if getattr(args, "dry_run", False):
        updates["mode"] = "dry-run"
    if getattr(args, "audit", None) is not None:
        audit_path = None if str(args.audit) == "-" else Path(args.audit)
        updates["audit"] = config.audit.model_copy(update={"path": audit_path})

    return config.model_copy(update=updates) if updates else config


def _configure_logging(args: argparse.Namespace) -> None:
    level = {0: logging.WARNING, 1: logging.INFO}.get(args.verbose, logging.DEBUG)
    # stderr, always: under stdio transport stdout carries the MCP protocol.
    logging.basicConfig(
        level=level,
        stream=sys.stderr,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )


def _fail(message: str) -> NoReturn:  # pragma: no cover - convenience for future subcommands
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(EXIT_ERROR)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
