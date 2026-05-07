import asyncio
import logging

from device_block_agent.server_runtime import serve


logger = logging.getLogger("device-block-agent")


def main() -> None:
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        logger.info("server stopped by keyboard interrupt")


if __name__ == "__main__":
    main()