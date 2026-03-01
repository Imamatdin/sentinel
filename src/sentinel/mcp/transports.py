"""
MCP Transport Layer — stdio and HTTP+SSE transports.

stdio: For local MCP clients (Claude Desktop, Cursor)
  Read JSON-RPC from stdin, write to stdout, one message per line.

HTTP+SSE: For remote MCP clients
  POST /mcp for JSON-RPC requests
  GET /mcp/sse for server-sent events (notifications, progress)
"""

import asyncio
import json
import sys

from sentinel.mcp.server import MCPServer
from sentinel.core import get_logger

logger = get_logger(__name__)


class StdioTransport:
    """MCP transport over stdin/stdout for local clients."""

    def __init__(self, server: MCPServer):
        self.server = server

    async def run(self):
        """Main loop: read from stdin, process, write to stdout."""
        logger.info("mcp_stdio_started")
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        loop = asyncio.get_event_loop()
        await loop.connect_read_pipe(lambda: protocol, sys.stdin)

        while True:
            try:
                line = await reader.readline()
                if not line:
                    break

                line_str = line.decode().strip()
                if not line_str:
                    continue

                response = await self.server.handle_message(line_str)
                sys.stdout.write(response + "\n")
                sys.stdout.flush()
            except Exception as e:
                logger.error("mcp_stdio_error", error=str(e))
                break

        logger.info("mcp_stdio_stopped")


def create_http_routes(server: MCPServer):
    """
    Create FastAPI routes for HTTP+SSE MCP transport.

    Returns a FastAPI APIRouter to be included in the main app.
    """
    from fastapi import APIRouter, Request, Response
    from fastapi.responses import StreamingResponse

    router = APIRouter(prefix="/mcp", tags=["mcp"])

    @router.post("")
    async def mcp_rpc(request: Request):
        body = await request.body()
        auth = request.headers.get("Authorization", "").replace("Bearer ", "")
        response = await server.handle_message(
            body.decode(), auth_token=auth or None
        )
        return Response(content=response, media_type="application/json")

    @router.get("/sse")
    async def mcp_sse(request: Request):
        async def event_stream():
            yield (
                f"data: {json.dumps({'type': 'connected', 'server': 'sentinel'})}\n\n"
            )
            while True:
                await asyncio.sleep(30)
                yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"

        return StreamingResponse(
            event_stream(), media_type="text/event-stream"
        )

    @router.get("/health")
    async def mcp_health():
        return {
            "status": "ok",
            "tools": len(server.tools),
            "resources": len(server.resources),
            "sessions": len(server.sessions),
        }

    return router
