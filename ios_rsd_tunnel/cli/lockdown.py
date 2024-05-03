# Copyright (c) 2024 Dry Ark LLC
# License GPL 3.0
from .remote import run_tunnel
from ..lockdown import lockdown_via_usbmux
from ..remote.tunnel_service import CoreTunnelProxy

def lockdown_tunnel(
    udid: str
) -> None:
    service_provider = lockdown_via_usbmux( serial = udid )
    service = CoreTunnelProxy( service_provider )
    
    run_tunnel(
        service,
        secrets=None,
        protocol='tcp'
    )
