# Copyright (c) 2024 Dry Ark LLC
import asyncio
import logging
import os
import signal
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

async def read_input():
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)

    # Read one line of input
    line = await reader.readline()
    print(f"Received: {line.decode().strip()}")
    return line.decode().strip()
    
async def read_inputo():
    loop = asyncio.get_running_loop()
    try:
        # Read from stdin using os.read() in a separate thread
        future = loop.run_in_executor(None, os.read, sys.stdin.fileno(), 1024)
        result = await future
        return result.decode().strip()
    except KeyboardInterrupt:
        print("Ctrl-C detected. Exiting...")
        return 'stop'

async def stop_task():
    loop = asyncio.get_running_loop()
    inp = 'x'
    while inp != 'stop':
        #user_input = await loop.run_in_executor(None, input, "Type 'stop' to exit: ")
        user_input = await read_input()
        print(f'input {user_input}')
        #user_input = await reader.readline()
        inp = user_input.strip().lower()
        print(f'input is {inp}')
    return 1

async def start_tunnel_collector(a,b,c,d):
    async with start_tunnel(
        a,
        secrets=b,
        max_idle_timeout=c,
        protocol=d
    ) as result:
        return result

def stop_loop(loop, task):
    """Stop the event loop and cancel the tasks"""
    print("Stopping loop and cancelling tasks")
    task.cancel()  # Cancel the specific background task
    loop.stop()    # Stop the loop

def tunnel_task(
    service,
    secrets: Optional[TextIO] = None,
    max_idle_timeout: float = MAX_IDLE_TIMEOUT,
    protocol: str = 'quic'
) -> None:
    loop = asyncio.get_event_loop()
    
    tunnel_result = asyncio.run( start_tunnel_collector(
        service,
        secrets,
        max_idle_timeout,
        protocol,
    ) )
    
    print(f'{{ "{tunnel_result.address}", "port": {tunnel_result.port} }}')

    asyncio.set_event_loop(loop)
    
    running_stop_task = stop_task()
    
    #print('setting up signal handler')
    #for sig in [signal.SIGINT, signal.SIGTERM]:
    #    loop.add_signal_handler(
    #        sig, stop_loop, loop, running_stop_task
    #    )
    
    try:
        asyncio.run( running_stop_task )
    except KeyboardInterrupt:
        pass
    except asyncio.CancelledError:
        print("Exiting")
    
    asyncio.run( tunnel_result.client.stop_tunnel() )
    
    logger.info('tunnel was closed')


async def start_tunnel_task_from_ipv6(
    ipv6: str,
) -> None:
    tunnel_service, udid = await get_core_device_tunnel_service_from_ipv6( ipv6 = ipv6 )
    print(f'device udid:{udid}')
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

