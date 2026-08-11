"""Transport runners.

The gateway is the same object either way; only how a caller reaches it and how
their identity is established differ. See `identity` for why those two things
are coupled.
"""

from __future__ import annotations

import logging
from contextlib import AsyncExitStack
from typing import TYPE_CHECKING, Any

from mcp.server.stdio import stdio_server

from .audit import AuditLog
from .config import GatewayConfig
from .errors import AuthenticationError, ConfigError
from .gateway import Gateway
from .identity import (
    Identity,
    TokenRegistry,
    bearer_token,
    reset_ambient_identity,
    set_ambient_identity,
)
from .ratelimit import RateLimiter
from .upstream import UpstreamPool

if TYPE_CHECKING:
    from starlette.applications import Starlette

logger = logging.getLogger(__name__)


async def build_gateway(config: GatewayConfig, stack: AsyncExitStack) -> Gateway:
    """Bring up upstreams and the audit log on `stack`, and return the gateway."""
    pool = await stack.enter_async_context(UpstreamPool(config))
    audit = await stack.enter_async_context(AuditLog(config.audit))
    gateway = Gateway(config, pool, audit, limiter=RateLimiter(config.rate_limits))

    catalogue = await pool.catalogue()
    logger.info(
        "gateway ready: %d upstream(s), %d tool(s), mode=%s",
        len(pool.connections),
        len(catalogue),
        config.mode,
    )
    return gateway


async def run_stdio(config: GatewayConfig, identity: Identity) -> None:
    """Serve one client over stdio, as a fixed identity."""
    async with AsyncExitStack() as stack:
        gateway = await build_gateway(config, stack)
        server = gateway.build_server()

        # Set before the server's task group starts, so every handler task
        # inherits it: child tasks copy the context at creation time.
        context_token = set_ambient_identity(identity)
        try:
            async with stdio_server() as (read_stream, write_stream):
                await server.run(read_stream, write_stream, server.create_initialization_options())
        finally:
            reset_ambient_identity(context_token)


class BearerAuthMiddleware:
    """Rejects unauthenticated requests before they reach the MCP machinery.

    This is the outer of two checks. It exists so that an anonymous or invalid
    caller never gets as far as opening a session, and gets a correct 401 with
    a `WWW-Authenticate` header rather than a JSON-RPC error. The authoritative
    check is in the handler (`Gateway.identity_for`), which re-reads the
    credential from the request it is actually serving — this middleware
    decides *whether* a request proceeds, not *as whom*.
    """

    def __init__(self, app: Any, registry: TokenRegistry) -> None:
        self._app = app
        self._registry = registry

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1") for key, value in scope.get("headers", [])
        }

        try:
            self._registry.verify(bearer_token(headers))
        except AuthenticationError as exc:
            logger.warning("rejected unauthenticated request to %s: %s", scope.get("path"), exc)
            await _send_unauthorised(send)
            return

        await self._app(scope, receive, send)


async def _send_unauthorised(send: Any) -> None:
    body = b'{"error":"unauthorized","error_description":"a valid bearer token is required"}'
    await send(
        {
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"application/json"),
                (b"www-authenticate", b'Bearer realm="mcp-policy-gateway"'),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


def build_http_app(config: GatewayConfig, gateway: Gateway, *, host: str, path: str) -> Starlette:
    """An ASGI app serving the gateway, with bearer-token authentication.

    Every request must carry a token that maps to a configured policy; there is
    no anonymous path, and no default identity to fall back to.
    """
    registry = TokenRegistry(config.tokens)
    if not registry:
        raise ConfigError(
            "HTTP transport requires at least one configured token: "
            "an HTTP gateway serves many callers and cannot infer who they are"
        )

    # The handler resolves identity from each request, so the gateway needs the
    # same registry the middleware screens with.
    gateway.registry = registry

    app = gateway.build_server().streamable_http_app(
        streamable_http_path=path,
        host=host,
        stateless_http=False,
    )
    app.add_middleware(BearerAuthMiddleware, registry=registry)
    return app


async def run_http(
    config: GatewayConfig,
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
    path: str = "/mcp",
) -> None:
    """Serve the gateway over streamable HTTP until interrupted."""
    import uvicorn

    async with AsyncExitStack() as stack:
        gateway = await build_gateway(config, stack)
        app = build_http_app(config, gateway, host=host, path=path)

        logger.info("listening on http://%s:%d%s", host, port, path)
        server = uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="info", access_log=False))
        await server.serve()
