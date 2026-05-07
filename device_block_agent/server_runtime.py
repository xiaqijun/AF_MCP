import logging
import socket
import sys

import uvicorn

from .agent_app import mcp
from .app_config import MCP_HOST, MCP_PATH


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("device-block-agent")


def bind_random_port(host: str) -> tuple[socket.socket, int]:
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, 0))
    server_socket.listen(socket.SOMAXCONN)
    server_socket.set_inheritable(True)
    port = int(server_socket.getsockname()[1])
    return server_socket, port


async def serve() -> None:
    app = mcp.http_app(path=MCP_PATH, transport="streamable-http")
    config = uvicorn.Config(
        app=app,
        host=MCP_HOST,
        port=0,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)
    server_socket, port = bind_random_port(MCP_HOST)

    logger.info("starting streamable HTTP MCP server on %s:%s%s", MCP_HOST, port, MCP_PATH)
    print(port, flush=True)

    try:
        await server.serve(sockets=[server_socket])
    finally:
        server_socket.close()