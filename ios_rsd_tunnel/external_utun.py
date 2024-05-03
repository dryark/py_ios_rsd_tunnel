# Copyright (c) 2021-2024 doronz <doron88@gmail.com>
from pytun_pmd3 import TunTapDevice

from typing import (
    Callable,
)

class ExternalUtun():
    def __init__(self):
        pass
        
    def write( self, data ):
        self.tun.write( data )
        pass
    
    @asyncio_print_traceback
    async def tun_read_task(self) -> None:
        read_size = self.tun.mtu + len(LOOPBACK_HEADER)
        try:
            async with aiofiles.open(self.tun.fileno(), 'rb', opener=lambda path, flags: path, buffering=0) as f:
                while True:
                    packet = await f.read(read_size)
                    self.callback( packet )
        except ConnectionResetError:
            #self._logger.warning(f'got connection reset in {asyncio.current_task().get_name()}')
            pass
        except OSError:
            #self._logger.warning(f'got oserror in {asyncio.current_task().get_name()}')
            pass
    
    async def up(
        self,
        label:str,
        ipv6:str,
        incoming_data_callback: Callable[[str], None]
    ) -> str:
        self.callback = incoming_data_callback
        self.tun = TunTapDevice()
        self.tun.addr = ipv6
        #self.tun.mtu = mtu
        self.tun.up()
        self._tun_read_task = asyncio.create_task(self.tun_read_task(), name=f'tun-read-{address}')
        
        # Create a utun that is configured to receive traffic to the specified ipv6 range
        # Receive data from the utun async, and call the callback when any comes in
        return "utun3"
    
    # Shutdown the utun
    def down(self) -> None:
        self.tun.down()
        pass

    def __del__(self):
        self.down()