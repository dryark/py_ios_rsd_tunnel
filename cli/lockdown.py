# Copyright (c) 2024 Dry Ark LLC
import asyncio
from .remote import tunnel_task
from ..remote.tunnel_service import CoreDeviceTunnelProxy
from ..lockdown import create_using_usbmux

def lockdown_tunnel(
    udid: str
) -> None:
    service_provider = create_using_usbmux(serial=udid)
    service = CoreDeviceTunnelProxy(service_provider)
    asyncio.run(
        tunnel_task(
            service,
            secrets=None,
            protocol='tcp'
        ), debug=True
    )
