"""The gateway: an MCP server that authorises, then forwards.

Two request handlers carry the whole enforcement story.

`tools/list` answers with only the tools the caller's policy could ever permit,
so a model driven by injected instructions is never even told that
`ha_remove_entity` exists.

`tools/call` is the control. It re-derives the decision from the actual
arguments, because a tool that is fine to call with `light.kitchen` is not fine
to call with `lock.front_door`, and no filtering of the tool list can express
that. Denials come back as tool *results*, not protocol errors: the agent gets
a legible "policy denied this" it can reason about and report, instead of a
transport failure it will most likely retry.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any, TypeAlias

import mcp.types as types
from mcp.server.lowlevel import Server

from .audit import AuditLog, AuditRecord, Outcome, now_iso
from .config import GatewayConfig, Policy
from .engine import Decision, PolicyEngine
from .errors import AuthenticationError, ConfigError, GatewayError, UpstreamError
from .identity import Identity, TokenRegistry, current_identity, identity_from_headers
from .matching import MatchContext
from .ratelimit import RateLimiter
from .upstream import NamespacedTool, UpstreamPool

if TYPE_CHECKING:
    from mcp.server.context import ServerRequestContext

logger = logging.getLogger(__name__)

#: The SDK's default lifespan yields an empty dict, so that is the type the
#: server and its request contexts are parameterised by. Aliased because it
#: appears in every handler signature.
LifespanState: TypeAlias = "dict[str, Any]"
RequestContext: TypeAlias = "ServerRequestContext[LifespanState]"


class Gateway:
    """Wires config, policy engine, rate limiter, audit log and upstreams together."""

    def __init__(
        self,
        config: GatewayConfig,
        pool: UpstreamPool,
        audit: AuditLog,
        *,
        engine: PolicyEngine | None = None,
        limiter: RateLimiter | None = None,
        registry: TokenRegistry | None = None,
    ) -> None:
        self.config = config
        self.pool = pool
        self.audit = audit
        self.engine = engine or PolicyEngine()
        self.limiter = limiter or RateLimiter(config.rate_limits)
        self.registry = registry

    def identity_for(self, context: RequestContext) -> Identity:
        """Establish who is making this request.

        Under HTTP the SDK hands the handler the underlying request, so the
        credential is read from the call in hand. Under stdio there is no
        per-request credential — the client launched this process — so the
        identity fixed at startup applies.
        """
        request = context.request
        if request is not None:
            return identity_from_headers(request.headers, self.registry)
        return current_identity()

    # ------------------------------------------------------------------ setup

    def build_server(self) -> Server[LifespanState]:
        """Construct the MCP server exposing this gateway."""
        return Server(
            name=self.config.server.name,
            version=self.config.server.version,
            instructions=self.config.server.instructions or self._default_instructions(),
            on_list_tools=self._handle_list_tools,
            on_call_tool=self._handle_call_tool,
            on_list_resources=self._handle_list_resources,
            on_read_resource=self._handle_read_resource,
            on_list_prompts=self._handle_list_prompts,
            on_get_prompt=self._handle_get_prompt,
        )

    def _default_instructions(self) -> str:
        return (
            "Tools reached through this gateway are subject to an authorisation policy. "
            "A call may be refused; the refusal is returned as a tool result explaining why. "
            "Do not attempt to work around a refusal, and report it to the user instead."
        )

    # --------------------------------------------------------------- handlers

    async def _handle_list_tools(
        self, context: RequestContext, params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        del params  # upstream catalogues are small enough to return unpaginated
        try:
            identity = self.identity_for(context)
            policy = self.config.policy_for(identity.policy)
        except (AuthenticationError, ConfigError) as exc:
            # Advertise nothing rather than failing the request: a client that
            # cannot be placed under a policy gets an empty toolbox, which is
            # exactly the set of tools it is allowed to use.
            logger.warning("listing tools for an unresolvable caller: %s", exc)
            return types.ListToolsResult(tools=[])

        catalogue = await self.pool.catalogue()
        if policy.hide_denied_tools:
            visible = [
                entry
                for entry in catalogue
                if self.engine.is_visible(policy, entry.gateway_name, entry.upstream)
            ]
        else:
            visible = list(catalogue)

        hidden = len(catalogue) - len(visible)
        if hidden:
            logger.debug("policy %r hid %d of %d tools", identity.policy, hidden, len(catalogue))

        return types.ListToolsResult(tools=[entry.as_advertised() for entry in visible])

    async def _handle_call_tool(
        self, context: RequestContext, params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        started = time.perf_counter()
        request_id = str(context.request_id) if context.request_id is not None else None
        arguments: dict[str, Any] = dict(params.arguments or {})

        try:
            identity = self.identity_for(context)
        except AuthenticationError as exc:
            # No audit record: with no identity there is nothing to attribute
            # it to, and an unauthenticated caller must not be able to grow the
            # log at will.
            logger.warning("rejected call to %r: %s", params.name, exc)
            return _error_result(f"Unauthenticated: {exc}")

        try:
            policy = self.config.policy_for(identity.policy)
        except ConfigError as exc:
            # The identity is authentic but names a policy that is not in the
            # config — a token that outlived a rename, say. There is no policy
            # to consult, so there is no basis on which to allow anything.
            logger.error("token %r references %s", identity.name, exc)
            await self._record(
                identity,
                outcome="error",
                reason=str(exc),
                target=params.name,
                upstream=None,
                arguments=None,
                mode=self.config.mode,
                request_id=request_id,
                started=started,
            )
            return _error_result(f"Gateway misconfigured: {exc}. No call was made.")

        mode = self.config.effective_mode(policy)

        try:
            target = await self.pool.resolve(params.name)
        except UpstreamError as exc:
            await self._record(
                identity,
                outcome="error",
                reason=str(exc),
                target=params.name,
                upstream=None,
                arguments=None,
                mode=mode,
                request_id=request_id,
                started=started,
            )
            return _error_result(str(exc))

        decision = self.engine.evaluate(
            policy,
            MatchContext(tool=target.gateway_name, upstream=target.upstream, arguments=arguments),
        )

        if not decision.allowed:
            return await self._refuse(
                identity, target, arguments, decision, mode, request_id, started, policy
            )

        verdict = await self.limiter.acquire(decision.rate_limits, identity.name)
        if not verdict:
            reason = f"rate limit {verdict.bucket!r} exhausted; retry in {verdict.retry_after:.1f}s"
            if mode == "enforce":
                await self._record(
                    identity,
                    outcome="rate_limited",
                    reason=reason,
                    target=target.gateway_name,
                    upstream=target.upstream,
                    arguments=arguments,
                    mode=mode,
                    rule=decision.rule_name,
                    request_id=request_id,
                    started=started,
                )
                return _error_result(f"Rate limited by policy: {reason}")
            logger.warning("dry-run: would have rate limited %r (%s)", target.gateway_name, reason)

        return await self._forward(identity, target, arguments, decision, mode, request_id, started)

    # ---------------------------------------------------------------- helpers

    async def _refuse(
        self,
        identity: Identity,
        target: NamespacedTool,
        arguments: dict[str, Any],
        decision: Decision,
        mode: str,
        request_id: str | None,
        started: float,
        policy: Policy,
    ) -> types.CallToolResult:
        """Handle a denial, honouring dry-run."""
        del policy  # reserved for per-policy refusal text

        if mode == "dry-run":
            logger.warning(
                "dry-run: would have denied %s -> %s (%s)",
                identity.name,
                target.gateway_name,
                decision.describe(),
            )
            result = await self._forward(
                identity, target, arguments, decision, mode, request_id, started, forced=True
            )
            return result

        await self._record(
            identity,
            outcome="denied",
            reason=decision.reason,
            target=target.gateway_name,
            upstream=target.upstream,
            arguments=arguments,
            mode=mode,
            rule=decision.rule_name,
            trace=list(decision.trace),
            request_id=request_id,
            started=started,
        )
        return _error_result(_refusal_text(target.gateway_name, decision))

    async def _forward(
        self,
        identity: Identity,
        target: NamespacedTool,
        arguments: dict[str, Any],
        decision: Decision,
        mode: str,
        request_id: str | None,
        started: float,
        *,
        forced: bool = False,
    ) -> types.CallToolResult:
        """Send an authorised call upstream and record what came back."""
        outcome: Outcome = "dry-run-allowed" if forced else "allowed"
        error: str | None = None

        try:
            result = await self.pool.call(target, arguments)
        except GatewayError as exc:
            outcome, error = "error", str(exc)
            result = _error_result(f"Upstream error: {exc}")
        except Exception as exc:
            logger.exception("upstream %r raised calling %r", target.upstream, target.upstream_name)
            outcome, error = "error", f"{type(exc).__name__}: {exc}"
            result = _error_result("Upstream error: the tool call failed. See the gateway log.")
        else:
            if result.is_error:
                # The upstream ran and refused: the call was still authorised,
                # so it is not a policy failure, but the log should show it.
                error = "upstream reported is_error"

        await self._record(
            identity,
            outcome=outcome,
            reason=decision.reason if not forced else f"DRY-RUN: would deny ({decision.reason})",
            target=target.gateway_name,
            upstream=target.upstream,
            arguments=arguments,
            mode=mode,
            rule=decision.rule_name,
            request_id=request_id,
            started=started,
            error=error,
        )
        return result

    async def _record(
        self,
        identity: Identity,
        *,
        outcome: Outcome,
        reason: str,
        target: str | None,
        upstream: str | None,
        arguments: dict[str, Any] | None,
        mode: str,
        started: float,
        rule: str | None = None,
        trace: list[str] | None = None,
        request_id: str | None = None,
        error: str | None = None,
        event: str = "tools/call",
    ) -> None:
        record = AuditRecord(
            timestamp=now_iso(),
            event=event,
            token=identity.name,
            policy=identity.policy,
            upstream=upstream,
            target=target,
            outcome=outcome,
            reason=reason,
            mode=mode,
            rule=rule,
            arguments=self.audit.redact(arguments, target=target or "", upstream=upstream or ""),
            duration_ms=round((time.perf_counter() - started) * 1000, 3),
            request_id=request_id,
            error=error,
            trace=trace or [],
        )
        await self.audit.write(record)


    async def _handle_list_resources(
        self, context: RequestContext, params: types.PaginatedRequestParams | None
    ) -> types.ListResourcesResult:
        del params
        try:
            identity = self.identity_for(context)
            policy = self.config.policy_for(identity.policy)
        except (AuthenticationError, ConfigError) as exc:
            logger.warning("listing resources for an unresolvable caller: %s", exc)
            return types.ListResourcesResult(resources=[])

        catalogue = await self.pool.catalogue_resources()
        if policy.hide_denied_resources:
            visible = [
                res
                for name, res in catalogue
                if self.engine.is_resource_visible(policy, str(res.uri), name)
            ]
        else:
            visible = [res for name, res in catalogue]

        return types.ListResourcesResult(resources=visible)

    async def _handle_read_resource(
        self, context: RequestContext, params: types.ReadResourceRequestParams
    ) -> types.ReadResourceResult:
        started = time.perf_counter()
        request_id = str(context.request_id) if context.request_id is not None else None

        try:
            identity = self.identity_for(context)
        except AuthenticationError as exc:
            logger.warning("rejected read_resource %r: %s", params.uri, exc)
            return types.ReadResourceResult(contents=[], _meta={"is_error": True})  # mcp 1.x read doesn't have is_error usually but let's just raise or return empty

        try:
            policy = self.config.policy_for(identity.policy)
        except ConfigError as exc:
            logger.error("token %r references %s", identity.name, exc)
            await self._record(
                identity,
                outcome="error",
                reason=str(exc),
                target=str(params.uri),
                upstream=None,
                arguments=None,
                mode=self.config.mode,
                request_id=request_id,
                started=started,
                event="resources/read",
            )
            return types.ReadResourceResult(contents=[])

        mode = self.config.effective_mode(policy)

        if str(params.uri) not in self.pool._resource_routes:
            await self.pool.catalogue_resources()
        
        upstream = self.pool._resource_routes.get(str(params.uri))
        if not upstream:
            error_msg = f"unknown resource {params.uri!r}"
            await self._record(
                identity,
                outcome="error",
                reason=error_msg,
                target=str(params.uri),
                upstream=None,
                arguments=None,
                mode=mode,
                request_id=request_id,
                started=started,
                event="resources/read",
            )
            return types.ReadResourceResult(contents=[])

        decision = self.engine.evaluate(
            policy,
            MatchContext(resource=str(params.uri), upstream=upstream, arguments={}),
        )

        if not decision.allowed:
            if mode == "dry-run":
                logger.warning(
                    "dry-run: would have denied %s -> %s (%s)",
                    identity.name,
                    params.uri,
                    decision.describe(),
                )
            else:
                await self._record(
                    identity,
                    outcome="denied",
                    reason=decision.reason,
                    target=str(params.uri),
                    upstream=upstream,
                    arguments=None,
                    mode=mode,
                    rule=decision.rule_name,
                    trace=list(decision.trace),
                    request_id=request_id,
                    started=started,
                    event="resources/read",
                )
                return types.ReadResourceResult(contents=[])

        outcome: Outcome = "allowed"
        error: str | None = None
        try:
            result = await self.pool.read_resource(str(params.uri))
        except Exception as exc:
            logger.exception("upstream %r raised reading %r", upstream, params.uri)
            outcome, error = "error", f"{type(exc).__name__}: {exc}"
            result = types.ReadResourceResult(contents=[])

        await self._record(
            identity,
            outcome="dry-run-allowed" if mode == "dry-run" and not decision.allowed else outcome,
            reason=decision.reason if mode != "dry-run" or decision.allowed else f"DRY-RUN: would deny ({decision.reason})",
            target=str(params.uri),
            upstream=upstream,
            arguments=None,
            mode=mode,
            rule=decision.rule_name,
            request_id=request_id,
            started=started,
            error=error,
            event="resources/read",
        )
        return result

    async def _handle_list_prompts(
        self, context: RequestContext, params: types.PaginatedRequestParams | None
    ) -> types.ListPromptsResult:
        del params
        try:
            identity = self.identity_for(context)
            policy = self.config.policy_for(identity.policy)
        except (AuthenticationError, ConfigError) as exc:
            logger.warning("listing prompts for an unresolvable caller: %s", exc)
            return types.ListPromptsResult(prompts=[])

        catalogue = await self.pool.catalogue_prompts()
        if policy.hide_denied_prompts:
            visible = [
                entry
                for entry in catalogue
                if self.engine.is_prompt_visible(policy, entry.gateway_name, entry.upstream)
            ]
        else:
            visible = list(catalogue)

        return types.ListPromptsResult(prompts=[entry.as_advertised() for entry in visible])

    async def _handle_get_prompt(
        self, context: RequestContext, params: types.GetPromptRequestParams
    ) -> types.GetPromptResult:
        started = time.perf_counter()
        request_id = str(context.request_id) if context.request_id is not None else None
        arguments = params.arguments or {}

        try:
            identity = self.identity_for(context)
        except AuthenticationError as exc:
            logger.warning("rejected get_prompt %r: %s", params.name, exc)
            return types.GetPromptResult(description="Unauthenticated", messages=[])

        try:
            policy = self.config.policy_for(identity.policy)
        except ConfigError as exc:
            logger.error("token %r references %s", identity.name, exc)
            await self._record(
                identity,
                outcome="error",
                reason=str(exc),
                target=params.name,
                upstream=None,
                arguments=None,
                mode=self.config.mode,
                request_id=request_id,
                started=started,
                event="prompts/get",
            )
            return types.GetPromptResult(description="Gateway misconfigured", messages=[])

        mode = self.config.effective_mode(policy)

        try:
            target = await self.pool.resolve_prompt(params.name)
        except UpstreamError as exc:
            await self._record(
                identity,
                outcome="error",
                reason=str(exc),
                target=params.name,
                upstream=None,
                arguments=None,
                mode=mode,
                request_id=request_id,
                started=started,
                event="prompts/get",
            )
            return types.GetPromptResult(description=str(exc), messages=[])

        decision = self.engine.evaluate(
            policy,
            MatchContext(prompt=target.gateway_name, upstream=target.upstream, arguments=arguments),
        )

        if not decision.allowed:
            if mode == "dry-run":
                logger.warning(
                    "dry-run: would have denied %s -> %s (%s)",
                    identity.name,
                    target.gateway_name,
                    decision.describe(),
                )
            else:
                await self._record(
                    identity,
                    outcome="denied",
                    reason=decision.reason,
                    target=target.gateway_name,
                    upstream=target.upstream,
                    arguments=arguments,
                    mode=mode,
                    rule=decision.rule_name,
                    trace=list(decision.trace),
                    request_id=request_id,
                    started=started,
                    event="prompts/get",
                )
                return types.GetPromptResult(description=_refusal_text(target.gateway_name, decision), messages=[])

        outcome: Outcome = "allowed"
        error: str | None = None
        try:
            result = await self.pool.get_prompt(target, arguments)
        except Exception as exc:
            logger.exception("upstream %r raised getting prompt %r", target.upstream, target.upstream_name)
            outcome, error = "error", f"{type(exc).__name__}: {exc}"
            result = types.GetPromptResult(description="Upstream error", messages=[])

        await self._record(
            identity,
            outcome="dry-run-allowed" if mode == "dry-run" and not decision.allowed else outcome,
            reason=decision.reason if mode != "dry-run" or decision.allowed else f"DRY-RUN: would deny ({decision.reason})",
            target=target.gateway_name,
            upstream=target.upstream,
            arguments=arguments,
            mode=mode,
            rule=decision.rule_name,
            request_id=request_id,
            started=started,
            error=error,
            event="prompts/get",
        )
        return result


def _refusal_text(tool: str, decision: Decision) -> str:
    """The message an agent receives when policy blocks a call.

    It names the tool and gives the operator's reason, but not the rule's
    internals: a caller that can enumerate the policy by probing it has been
    handed a map of what to try next.
    """
    reason = decision.reason if decision.matched_rule else "no rule permits this call"
    return (
        f"Denied by gateway policy: the call to {tool!r} was not permitted ({reason}). "
        "This decision has been logged. Report it to the user rather than retrying "
        "or attempting a different route to the same effect."
    )


def _error_result(message: str) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=message)],
        is_error=True,
    )
