# Copyright (c) 2021-2024 doronz <doron88@gmail.com>
# Copyright (c) 2024 Dry Ark LLC <license@dryark.com>
# License GPL 3.0
import asyncio
import json
import logging
import struct
import sys

from abc import ABC, abstractmethod
from asyncio import CancelledError, StreamReader, StreamWriter

try:
    # Proprietary solution
    from cf_external_utun import ExternalUtun
except ImportError:
    from ..external_utun import ExternalUtun

from construct import (
    Const,
    GreedyBytes,
    Int16ub,
    Prefixed,
    Struct,
)
from contextlib import suppress
from qh3.asyncio import QuicConnectionProtocol
from qh3.asyncio.protocol import QuicStreamHandler
from qh3.quic import packet_builder
from qh3.quic.connection import QuicConnection
from qh3.quic.events import ConnectionTerminated, DatagramFrameReceived, QuicEvent, StreamDataReceived

from socket import (
    AF_INET6,
)
from typing import (
    Mapping,
    Optional,
    #namedtuple,
)
from ..exceptions import *
from ..utils import asyncio_print_traceback

IPV6_HEADER_SIZE = 40
UDP_HEADER_SIZE = 8

# The iOS device uses an MTU of 1500, so we'll have to increase the default QUIC MTU
IOS_DEVICE_MTU_SIZE = 1500
packet_builder.PACKET_MAX_SIZE = IOS_DEVICE_MTU_SIZE - IPV6_HEADER_SIZE - UDP_HEADER_SIZE

if sys.platform == 'darwin':
    UTUN_INET6_HEADER = struct.pack('>I', AF_INET6)
else:
    UTUN_INET6_HEADER = b'\x00\x00\x86\xdd'

CDTunnelPacket = Struct(
    'magic' / Const(b'CDTunnel'),
    'body' / Prefixed(Int16ub, GreedyBytes),
)

class RemoteTunnel(ABC):
    def __init__(self):
        self._queue = asyncio.Queue()
        self._logger = logging.getLogger(f'{__name__}.{self.__class__.__name__}')
        self.tun = None

    @abstractmethod
    async def send_packet_to_device(self, packet: bytes) -> None:
        pass

    @abstractmethod
    async def request_tunnel_establish(self) -> Mapping:
        pass

    @abstractmethod
    async def wait_closed(self) -> None:
        pass

    async def start_tunnel(
        self,
        address: str, # ipv6 address ( range really ) that the utun should use
        mtu: int,
        label: str = "label", # unique device specific label to use if desired
    ) -> None:
        async def handle_data(data):
            if not data.startswith(UTUN_INET6_HEADER):
                return
            data = data[len(UTUN_INET6_HEADER):]
            await self.send_packet_to_device(data)
        
        self.tun = ExternalUtun()
        await self.tun.up(
            ipv6 = address,
            label = label,
            incoming_data_callback = handle_data,
        )

    async def stop_tunnel(self) -> None:
        self._logger.debug('stopping tunnel')
        self.tun.down()

    @staticmethod
    def _encode_cdtunnel_packet(data: Mapping) -> bytes:
        return CDTunnelPacket.build({'body': json.dumps(data).encode()})


class RemoteQuicTunnel(RemoteTunnel, QuicConnectionProtocol):
    MAX_QUIC_DATAGRAM = 14000
    MAX_IDLE_TIMEOUT = 30.0
    REQUESTED_MTU = 1420

    def __init__(
        self,
        quic: QuicConnection,
        stream_handler: Optional[QuicStreamHandler] = None
    ):
        RemoteTunnel.__init__(self)
        QuicConnectionProtocol.__init__(self, quic, stream_handler)
        self._keep_alive_task = None

    def wait_closed_task(self):
        return QuicConnectionProtocol.wait_closed(self)

    async def wait_closed(self) -> None:
        await QuicConnectionProtocol.wait_closed(self)

    async def send_packet_to_device(self, packet: bytes) -> None:
        self._quic.send_datagram_frame(packet)
        self.transmit()

    async def request_tunnel_establish(self) -> Mapping:
        stream_id = self._quic.get_next_available_stream_id()
        # pad the data with random data to force the MTU size correctly
        self._quic.send_datagram_frame(b'x' * 1024)
        self._quic.send_stream_data(
            stream_id,
            self._encode_cdtunnel_packet({
                'type': 'clientHandshakeRequest',
                'mtu': self.REQUESTED_MTU
            })
        )
        self.transmit()
        return await self._queue.get()

    @asyncio_print_traceback
    async def keep_alive_task(self) -> None:
        while True:
            await self.ping()
            await asyncio.sleep(self._quic.configuration.idle_timeout / 2)

    async def start_tunnel(
        self,
        address: str,
        mtu: int,
        label: str = "label",
    ) -> None:
        await super().start_tunnel(address, mtu, label = label)
        self._keep_alive_task = asyncio.create_task(self.keep_alive_task())

    async def stop_tunnel(self) -> None:
        self._keep_alive_task.cancel()
        with suppress(CancelledError):
            await self._keep_alive_task
        await super().stop_tunnel()

    def quic_event_received(
        self,
        event: QuicEvent
    ) -> None:
        if isinstance(event, ConnectionTerminated):
            self.close()
        elif isinstance(event, StreamDataReceived):
            self._queue.put_nowait(
                json.loads(
                    CDTunnelPacket.parse(event.data).body
                )
            )
        elif isinstance(event, DatagramFrameReceived):
            self.tun.write(UTUN_INET6_HEADER + event.data)

    @staticmethod
    def _encode_cdtunnel_packet(data: Mapping) -> bytes:
        return CDTunnelPacket.build({'body': json.dumps(data).encode()})


class RemoteTcpTunnel(RemoteTunnel):
    REQUESTED_MTU = 16000

    def __init__(self, reader: StreamReader, writer: StreamWriter):
        RemoteTunnel.__init__(self)
        self._reader = reader
        self._writer = writer
        self._sock_read_task = None

    async def send_packet_to_device(self, packet: bytes) -> None:
        self._writer.write(packet)
        await self._writer.drain()

    @asyncio_print_traceback
    async def sock_read_task(self) -> None:
        try:
            while True:
                ipv6_header = await self._reader.readexactly(IPV6_HEADER_SIZE)
                ipv6_length = struct.unpack('>H', ipv6_header[4:6])[0]
                ipv6_body = await self._reader.readexactly(ipv6_length)
                self.tun.write(UTUN_INET6_HEADER + ipv6_header + ipv6_body)
        except (OSError, asyncio.exceptions.IncompleteReadError) as e:
            self._logger.warning(f'got {e.__class__.__name__} in {asyncio.current_task().get_name()}')
            await self.wait_closed()

    def wait_closed_task(self):
        return self._writer.wait_closed()

    async def wait_closed(self) -> None:
        try:
            await self._writer.wait_closed()
        except OSError:
            pass

    async def request_tunnel_establish(self) -> Mapping:
        self._writer.write(
            self._encode_cdtunnel_packet({
                'type': 'clientHandshakeRequest',
                'mtu': self.REQUESTED_MTU,
            })
        )
        await self._writer.drain()
        return json.loads(
            CDTunnelPacket.parse(
                await self._reader.read(self.REQUESTED_MTU)
            ).body
        )

    async def start_tunnel(
        self,
        address: str,
        mtu: int,
        label: str = "label",
    ) -> None:
        await super().start_tunnel(address, mtu, label=label)
        
        self._sock_read_task = asyncio.create_task(
            self.sock_read_task(),
            name=f'sock-read-task-{address}'
        )

    async def stop_tunnel(self) -> None:
        self._sock_read_task.cancel()
        
        with suppress(CancelledError):
            await self._sock_read_task
        
            if not self._writer.is_closing():
                self._writer.close()
                try:
                    await self._writer.wait_closed()
                except OSError:
                    pass
        
        await super().stop_tunnel()