import logging
import sys

import uvicorn

from .agent_app import mcp
from .app_config import MCP_HOST, MCP_PATH, MCP_PORT


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("device-block-agent")

async def serve() -> None:
    app = mcp.http_app(path=MCP_PATH, transport="streamable-http")
    config = uvicorn.Config(
        app=app,
        host=MCP_HOST,
        port=MCP_PORT,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)

    logger.info("starting streamable HTTP MCP server on %s:%s%s", MCP_HOST, MCP_PORT, MCP_PATH)
    print(MCP_PORT, flush=True)

    await server.serve()