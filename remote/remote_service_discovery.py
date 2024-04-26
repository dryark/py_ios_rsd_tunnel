# Copyright (c) 2024 Dry Ark LLC
import base64
import logging

from dataclasses import dataclass

from ..home_folder import get_home_folder
from ..exceptions import (
    InvalidServiceError,
)
from ..lockdown import (
    LockdownClient,
    create_using_remote,
)
from ..lockdown_service_provider import LockdownServiceProvider
from ..pair_records import (
    get_local_pairing_record,
    get_remote_pairing_record_filename,
)
from .remotexpc import RemoteXPCConnection
from ..service_connection import ServiceConnection

from typing import (
    Mapping,
    Optional,
    Tuple,
    Union,
)


@dataclass
class RSDDevice:
    hostname: str
    udid: str
    product_type: str
    os_version: str


RSD_PORT = 58783

logger = logging.getLogger(__name__)

class RemoteServiceDiscoveryService(LockdownServiceProvider):
    def __init__(
        self, address: Tuple[str, int], name: Optional[str] = None
    ) -> None:
        super().__init__()
        self.name = name
        self.udid = ""
        self.service = RemoteXPCConnection(address)
        self.peer_info: Optional[Mapping] = None
        self.lockdown: Optional[LockdownClient] = None
        self.all_values: Optional[Mapping] = None

    @property
    def product_version(self) -> str:
        return self.peer_info['Properties']['OSVersion']

    @property
    def ecid(self) -> int:
        return self.peer_info['Properties']['UniqueChipID']

    def connect(self) -> None:
        self.service.connect()
        self.peer_info = self.service.receive_response()
        
        if self.peer_info is None:
            logging.info(f'peer_info is none connecting to RSD service {self.name}')
        
        #logging.info(f'peer_info {peer_info}')
        
        self.udid = self.peer_info['Properties']['UniqueDeviceID']
        self.product_type = self.peer_info['Properties']['ProductType']
        
        try:
            self.lockdown = create_using_remote(
                self.start_lockdown_service('com.apple.mobile.lockdown.remote.trusted')
            )
        except InvalidServiceError:
            self.lockdown = create_using_remote(
                self.start_lockdown_service('com.apple.mobile.lockdown.remote.untrusted')
            )
        
        self.all_values = self.lockdown.all_values

    def get_value(
        self,
        domain: str = None,
        key: str = None,
    ):
        return self.lockdown.get_value(domain, key)

    def start_lockdown_service_without_checkin(
        self,
        name: str
    ) -> ServiceConnection:
        return ServiceConnection.create_using_tcp(
            self.service.address[0],
            self.get_service_port(name)
        )

    def start_lockdown_service(
        self,
        name: str,
        include_escrow_bag: bool = False
    ) -> ServiceConnection:
        service = self.start_lockdown_service_without_checkin(name)
        checkin = {
            'Label': 'iosRsdTunnel',
            'ProtocolVersion': '2',
            'Request': 'RSDCheckin',
        }
        
        if include_escrow_bag:
            pairing_record = get_local_pairing_record(
                get_remote_pairing_record_filename(self.udid),
                get_home_folder()
            )
            checkin['EscrowBag'] = base64.b64decode(
                pairing_record['remote_unlock_host_key']
            )
        
        response = service.send_recv_plist(checkin)
        
        if response['Request'] != 'RSDCheckin':
            raise Exception(f'Invalid response for RSDCheckIn: {response}. Expected "RSDCheckIn"')
        
        response = service.recv_plist()
        
        if response['Request'] != 'StartService':
            raise Exception(f'Invalid response for RSDCheckIn: {response}. Expected "ServiceService"')
        
        return service

    async def aio_start_lockdown_service(
        self,
        name: str,
        include_escrow_bag: bool = False
    ) -> ServiceConnection:
        service = self.start_lockdown_service(
            name,
            include_escrow_bag=include_escrow_bag
        )
        await service.aio_start()
        return service

    def start_remote_service(
        self,
        name: str
    ) -> RemoteXPCConnection:
        #logging.info(f'start_remote_service {name}')
        port = self.get_service_port(name)
        #logging.info(f'  port {port}')
        service = RemoteXPCConnection((self.service.address[0], port))
        return service

    def start_service(
        self,
        name: str
    ) -> Union[RemoteXPCConnection, ServiceConnection]:
        service = self.peer_info['Services'][name]
        service_properties = service.get('Properties', {})
        use_remote_xpc = service_properties.get('UsesRemoteXPC', False)
        return self.start_remote_service(name) if use_remote_xpc else self.start_lockdown_service(name)

    def get_service_port(self, name: str) -> int:
        """takes a service name and returns the port that service is running on if the service exists"""
        #logging.info(f'peer_info {self.peer_info}')
        service = self.peer_info['Services'].get(name)
        if service is None:
            raise InvalidServiceError(f'No such service: {name}')
        return int(service['Port'])

    def close(self) -> None:
        self.service.close()
        if self.lockdown is not None:
            self.lockdown.close()

    def __enter__(self) -> 'RemoteServiceDiscoveryService':
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def __repr__(self) -> str:
        name_str = ''
        if self.name:
            name_str = f' NAME:{self.name}'
        return (f'<{self.__class__.__name__} PRODUCT:{self.product_type} VERSION:{self.product_version} '
                f'UDID:{self.udid}{name_str}>')
