# If you'd like to build your own one of these, go ahead.
# Have fun.

from typing import (
    Callable,
)

class ExternalUtun():
    def __init__(self):
        pass
        
    # This should write data out to the utun
    def write( self, data ):
        pass
    
    # This should create a utun
    # The callback should be setup to be called with data anytime the utun has data
    async def up(
        self,
        label:str,
        ipv6:str,
        incoming_data_callback: Callable[[str], None]
    ) -> str:
        # Do stuffs here
        return "utun3"
    
    # Shutdown the utun
    def down(self) -> None:
        pass

    def __del__(self):
        self.down()