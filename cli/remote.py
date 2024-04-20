# Copyright (c) 2024 Dry Ark LLC
import asyncio
import logging
import sys

from ..remote.tunnel_service import (
    start_tunnel,
    get_core_device_tunnel_service_from_ipv6,
    list_remotes,
    remote_pair,
)
from typing import (
    Optional,
    TextIO,
)

MAX_IDLE_TIMEOUT = 30.0

logger = logging.getLogger(__name__)

async def stop_task():
    loop = asyncio.get_running_loop()
    user_input = await loop.run_in_executor(None, input, "Type 'stop' to exit: ")
    return user_input.strip().lower() == 'stop'

async def tunnel_task(
    service,
    secrets: Optional[TextIO] = None,
    max_idle_timeout: float = MAX_IDLE_TIMEOUT,
    protocol: str = 'quic'
) -> None:
    async with start_tunnel(
        service,
        secrets=secrets,
        max_idle_timeout=max_idle_timeout,
        protocol=protocol
    ) as tunnel_result:
        #logger.info(f'tunnel created: {tunnel_result}')
        
        print(f'{{ "{tunnel_result.address}", "port": {tunnel_result.port} }}')
        
        sys.stdout.flush()
        
        task = asyncio.create_task( await tunnel_result.client.wait_closed_task() )  # Start the task
        
        if await stop_task():
            task.cancel()
        
        try:
            await task
        except asyncio.CancelledError:
            print("Exiting")
        
        logger.info('tunnel was closed')


async def start_tunnel_task_from_ipv6(
    ipv6: str,
) -> None:
    tunnel_service = await get_core_device_tunnel_service_from_ipv6( ipv6 = ipv6 )
    await tunnel_task(
        tunnel_service,
        protocol='quic'
    )

def remote_tunnel(
    ipv6: str,
) -> None:
    asyncio.run(
        start_tunnel_task_from_ipv6(
            ipv6=ipv6,
        ),
        debug=True,
    )

def cli_pair(
    ipv6: str,
) -> None:
    asyncio.run(
        remote_pair( ipv6 = ipv6 )
    )

def cli_list() -> None:
    asyncio.run(
        list_remotes()
    )

