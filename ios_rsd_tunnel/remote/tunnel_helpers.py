# Copyright (c) 2024 Dry Ark LLC <license@dryark.com>
# License AGPL
from contextlib import (
    asynccontextmanager,
)
from typing import (
    AsyncGenerator,
    Optional,
    TextIO,
)

from .remoted_tool import stop_remoted, resume_remoted
from ..exceptions import *
from .remote_service_discovery import (
    RemoteServiceDiscovery,
)
from .tunnel import (
    RemoteQuicTunnel,
)
from .tunnel_service import (
    CoreTunnelProxy,
    TunnelService,
    CoreTunnelService,
    RemoteTunnelService,
    TunnelResult,
)

@asynccontextmanager
async def start_core_tunnel(
    tunnel_service: CoreTunnelService,
    secrets: Optional[TextIO] = None,
    max_idle_timeout: float = RemoteQuicTunnel.MAX_IDLE_TIMEOUT,
    protocol: str = 'quic',
    label: str = "label",
) -> AsyncGenerator[TunnelResult, None]:
    stop_remoted()
    with tunnel_service:
        if protocol == 'quic':
            async with tunnel_service.start_quic_tunnel(
                secrets_log_file=secrets,
                max_idle_timeout=max_idle_timeout,
                label=label,
            ) as tunnel_result:
                resume_remoted()
                yield tunnel_result
        elif protocol == 'tcp':
            async with tunnel_service.start_tcp_tunnel() as tunnel_result:
                resume_remoted()
                yield tunnel_result


@asynccontextmanager 
async def start_remote_tunnel( 
    tunnel_service: RemoteTunnelService,
    secrets: Optional[TextIO] = None, 
    max_idle_timeout: float = RemoteQuicTunnel.MAX_IDLE_TIMEOUT, 
    protocol: str = 'quic',
    label: str = "label",
)  -> AsyncGenerator[TunnelResult, None]:
    with tunnel_service: 
        if protocol == 'quic': 
            async with tunnel_service.start_quic_tunnel(
                secrets_log_file=secrets,
                max_idle_timeout=max_idle_timeout,
                label=label,
            ) as tunnel_result:
                yield tunnel_result
        elif protocol == 'tcp': 
            async with tunnel_service.start_tcp_tunnel() as tunnel_result:
                yield tunnel_result


@asynccontextmanager
async def start_tunnel(
    tunnel_service: TunnelService,
    secrets: Optional[TextIO] = None,
    max_idle_timeout: float = RemoteQuicTunnel.MAX_IDLE_TIMEOUT,
    protocol: str = 'quic'
) -> AsyncGenerator[TunnelResult, None]:
    if isinstance(tunnel_service, CoreTunnelService):
        async with start_core_tunnel(
            tunnel_service,
            secrets=secrets,
            max_idle_timeout=max_idle_timeout,
            protocol=protocol, # Should probably set to tcp here
            label=tunnel_service.udid,
        ) as service:
            yield service
    elif isinstance(tunnel_service, RemoteTunnelService):
        async with start_remote_tunnel(
            tunnel_service,
            secrets=secrets,
            max_idle_timeout=max_idle_timeout,
            protocol=protocol, # Should probably set to quic here
            label=tunnel_service.udid,
        ) as service:
            yield service
    elif isinstance(tunnel_service, CoreTunnelProxy):
        if protocol != 'tcp':
            raise ValueError('CoreTunnelProxy protocol can only be TCP')
        
        async with tunnel_service.start_tcp_tunnel() as service:
            yield service
    else:
        raise Exception(f'Bad value for protocol_handler: {tunnel_service}')

RSD_PORT = 58783

def core_tunnel_service_from_ipv6(
    ipv6: str,
) -> [ CoreTunnelService, str ]:
    stop_remoted()
    rsd = RemoteServiceDiscovery(( ipv6, RSD_PORT ))
    rsd.connect()
    #resume_remoted()
    service = CoreTunnelService( rsd )
    service.connect(autopair=True)
    return service, rsd.udid


async def remote_pair(
    ipv6: str,
    bonjour_timeout: float = 0,
) -> None:
    stop_remoted()
    rsd = RemoteServiceDiscovery(( ipv6, RSD_PORT ))
    rsd.connect()
    resume_remoted()
    service = CoreTunnelService( rsd )
    service.connect(autopair=True)
    service.close()