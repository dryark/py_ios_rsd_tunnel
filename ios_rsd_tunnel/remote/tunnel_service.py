# Copyright (c) 2021-2024 doronz <doron88@gmail.com>
# Copyright (c) 2024 Dry Ark LLC <license@dryark.com>
# License AGPL 3.0
import asyncio
import base64
import binascii
import dataclasses
import hashlib
import hmac
import json
import logging
import platform
import plistlib

from abc import ABC, abstractmethod
from collections import namedtuple
from construct import (
    Const,
    Container,
    GreedyBytes,
    GreedyRange,
    Int8ul,
    Int16ub,
    Int64ul,
    Prefixed,
    Struct,
)
from construct import Enum as ConstructEnum
from contextlib import (
    asynccontextmanager,
)
from nacl import bindings
from nacl.signing import (
    SigningKey as NaclSigningKey,
    VerifyKey,
)
from nacl.public import (
    PrivateKey as NaclPrivateKey,
)
from oscrypto.asymmetric import (
    PrivateKey as OscPrivateKey,
    PublicKey as OscPublicKey,
    generate_pair,
)

from qh3._hazmat import AeadChaCha20Poly1305 as ChaCha20Poly1305
#from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from certbuilder import (
    pem_armor_certificate,
)
from oscrypto.asymmetric import (
    dump_private_key,
)
from pathlib import Path
from qh3.asyncio.client import connect as aioquic_connect
from qh3.quic.configuration import QuicConfiguration
from socket import (
    create_connection,
)
from srptools import (
    SRPClientSession,
    SRPContext,
)
from srptools.constants import (
    PRIME_3072,
    PRIME_3072_GEN,
)
from ssl import VerifyMode
from typing import (
    AsyncGenerator,
    List,
    Mapping,
    Optional,
    TextIO,
    cast,
)

from .tinyopack import TinyOPack
from .tunnel import (
    RemoteTunnel,
    RemoteQuicTunnel,
    RemoteTcpTunnel,
)
from ..ca import make_cert
from ..exceptions import *
from ..lockdown_service_provider import LockdownServiceProvider
from ..pair_records import (
    create_pair_record_cache_folder,
    generate_host_id,
    get_remote_pair_record_filename,
)
from .remote_service import RemoteService
from .remote_service_discovery import (
    RemoteServiceDiscovery,
)
from .xpc_message import (
    XpcInt64Type,
    XpcUInt64Type,
)
from ..services.lockdown_service import LockdownService
from ..service_connection import ServiceConnection
from ..utils import (
    set_keepalive,
)

PairConsentResult = namedtuple('PairConsentResult', 'public_key salt')

RPPairingPacket = Struct(
    'magic' / Const(b'RPPairing'),
    'body' / Prefixed(Int16ub, GreedyBytes),
)

logger = logging.getLogger(__name__)

PairingDataComponentType = ConstructEnum(
    Int8ul,
    METHOD          = 0x00,
    IDENTIFIER      = 0x01,
    SALT            = 0x02,
    PUBLIC_KEY      = 0x03,
    PROOF           = 0x04,
    ENCRYPTED_DATA  = 0x05,
    STATE           = 0x06,
    ERROR           = 0x07,
    RETRY_DELAY     = 0x08,
    CERTIFICATE     = 0x09,
    SIGNATURE       = 0x0a,
    PERMISSIONS     = 0x0b,
    FRAGMENT_DATA   = 0x0c,
    FRAGMENT_LAST   = 0x0d,
    SESSION_ID      = 0x0e,
    TTL             = 0x0f,
    EXTRA_DATA      = 0x10,
    INFO            = 0x11,
    ACL             = 0x12,
    FLAGS           = 0x13,
    VALIDATION_DATA = 0x14,
    MFI_AUTH_TOKEN  = 0x15,
    MFI_PRODUCT_TYPE= 0x16,
    SERIAL_NUMBER   = 0x17,
    MFI_AUTH_TOKEN_UUID=0x18,
    APP_FLAGS       = 0x19,
    OWNERSHIP_PROOF = 0x1a,
    SETUP_CODE_TYPE = 0x1b,
    PRODUCTION_DATA = 0x1c,
    APP_INFO        = 0x1d,
    SEPARATOR       = 0xff,
)

PairingDataComponentTLV8 = Struct(
    'type' / PairingDataComponentType,
    'data' / Prefixed(Int8ul, GreedyBytes),
)

PairingDataComponentTLVBuf = GreedyRange(PairingDataComponentTLV8)

def hkdf_expand(prk, info=b"", length=64):
    blocks = (length + 511) // 512
    output = b""
    for i in range(1, blocks + 1):
        output += hmac.new(prk, output + info + bytes([i]), hashlib.sha512).digest()
    return output[:length]

def hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha512).digest()
    
def hkdf( key, info, salt=b'', length=32):
    prk = hkdf_extract(salt, key)
    return hkdf_expand(prk, info, length)
    

@dataclasses.dataclass
class TunnelResult:
    interface: str
    address: str
    port: int
    protocol: str
    client: RemoteTunnel


class StartTcpTunnel(ABC):
    REQUESTED_MTU = 16000

    @property
    @abstractmethod
    def remote_identifier(self) -> str:
        pass

    @abstractmethod
    async def start_tcp_tunnel(self) -> AsyncGenerator[TunnelResult, None]:
        pass

class TunnelService(StartTcpTunnel):
    WIRE_PROTOCOL_VERSION = 19

    def __init__(self):
        self.hostname: Optional[str] = None
        self._sequence_number = 0
        self._encrypted_sequence_number = 0
        #self.version = None
        self.handshake_info = None
        self.private_key = NaclPrivateKey.generate()
        self.signing_key = NaclSigningKey.generate()
        self.identifier = generate_host_id()
        self.srp_context = None
        self.session_key: bytes = None
        self.logger = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    def close(self) -> None:
        pass

    @abstractmethod
    def receive_response(self) -> Mapping:
        pass

    @abstractmethod
    def send_request(self, data: Mapping) -> None:
        pass

    def send_receive_request(
        self,
        data: Mapping
    ) -> Mapping:
        self.send_request(data)
        return self.receive_response()

    def connect(
        self,
        autopair: bool = True
    ) -> None:
        self._attempt_pair_verify()
        
        if not self._validate_pairing():
            if autopair:
                self._pair()
        
        self._init_client_server_main_encryption_keys()

    def create_quic_listener(
        self,
        public_key: OscPublicKey,
        private_key: OscPrivateKey,
    ) -> Mapping:
        spki = public_key.asn1.dump()
        request = {
            'request': {
                '_0': {
                    'createListener': {
                        'key': base64.b64encode(
                            spki,
                        ).decode(),
                        'transportProtocolType': 'quic'
                    }
                }
            }
        }

        response = self._send_receive_encrypted_request(request)
        return response['createListener']

    def create_tcp_listener(self) -> Mapping:
        request = {
            'request': {
                '_0': {
                    'createListener': {
                        'key': base64.b64encode(self.session_key).decode(),
                        'transportProtocolType': 'tcp'
                    }
                }
            }
        }
        response = self._send_receive_encrypted_request(request)
        return response['createListener']

    @asynccontextmanager
    async def start_quic_tunnel(
        self,
        secrets_log_file: Optional[TextIO] = None,
        max_idle_timeout: float = RemoteQuicTunnel.MAX_IDLE_TIMEOUT,
        label: str = "label",
    ) -> AsyncGenerator[TunnelResult, None]:
        public_key, private_key = generate_pair( 'rsa', bit_size = 2048 )
        # OscPublicKey and OscPrivateKey
        
        parameters = self.create_quic_listener( public_key, private_key )
        cert = make_cert(
             private_key = private_key,
             public_key = public_key,
        )
        #cert_der = cert.dump()
        
        configuration = QuicConfiguration(
            alpn_protocols=['RemotePairingTunnelProtocol'],
            is_client=True,
            verify_mode=VerifyMode.CERT_NONE,
            verify_hostname=False,
            max_datagram_frame_size=RemoteQuicTunnel.MAX_QUIC_DATAGRAM,
            idle_timeout=max_idle_timeout,
        )
        
        cert_pem = pem_armor_certificate( cert )
        private_key_pem = dump_private_key( private_key, None )
        
        configuration.load_cert_chain(
            certfile = cert_pem,
            keyfile = private_key_pem,
        )
                
        configuration.secrets_log_file = secrets_log_file

        host = self.hostname
        port = parameters['port']

        self.logger.debug(f'Connecting to {host}:{port}')
        async with aioquic_connect(
            host,
            port,
            configuration=configuration,
            create_protocol=RemoteQuicTunnel,
        ) as client:
        
            self.logger.debug('quic connected')
            #client = cast(RemoteQuicTunnel, client)
            await client.wait_connected()
            handshake_response = await client.request_tunnel_establish()
            
            await client.start_tunnel(
                handshake_response['clientParameters']['address'],
                handshake_response['clientParameters']['mtu'],
                label = label,
            )

            try:
                yield TunnelResult(
                    client.tun.name,
                    handshake_response['serverAddress'],
                    handshake_response['serverRSDPort'],
                    'quic',
                    client
                )
            finally:
                await client.stop_tunnel()

    @asynccontextmanager
    async def start_tcp_tunnel(
        self
    ) -> AsyncGenerator[TunnelResult, None]:
        parameters = self.create_tcp_listener()
        host = self.hostname
        port = parameters['port']
        sock = create_connection((host, port))
        set_keepalive(sock)
        ctx = None # SSLPSKContext(ssl.PROTOCOL_TLSv1_2) # None seems to be ok...
        ctx.psk = self.session_key
        ctx.set_ciphers('PSK')
        
        reader, writer = await asyncio.open_connection(
            sock=sock,
            ssl=ctx,
            server_hostname=''
        )
        tunnel = RemoteTcpTunnel(reader, writer)
        handshake_response = await tunnel.request_tunnel_establish()

        tunnel.start_tunnel(
            handshake_response['clientParameters']['address'],
            handshake_response['clientParameters']['mtu'],
        )

        try:
            yield TunnelResult(
                tunnel.tun.name,
                handshake_response['serverAddress'],
                handshake_response['serverRSDPort'],
                'tcp',
                tunnel
            )
        finally:
            await tunnel.stop_tunnel()

    def save_pair_record(self) -> None:
        self.pair_record_path.write_bytes(
            plistlib.dumps({
                'public_key': self.signing_key.verify_key.encode(),
                'private_key': self.signing_key.encode(),
                'remote_unlock_host_key': self.remote_unlock_host_key
            })
        )

    @property
    def pair_record(
        self
    ) -> Optional[Mapping]:
        if self.pair_record_path.exists():
            return plistlib.loads(self.pair_record_path.read_bytes())
        return None

    @property
    def remote_identifier(self) -> str:
        return self.handshake_info['peerDeviceInfo']['identifier']

    @property
    def pair_record_path(self) -> Path:
        pair_record_cache_directory = create_pair_record_cache_folder()
        return (
            pair_record_cache_directory /
            f'{get_remote_pair_record_filename(self.remote_identifier)}.plist'
        )

    def _pair(self) -> None:
        pairing_consent_result = self._request_pair_consent()
        self._init_srp_context(pairing_consent_result)
        self._verify_proof()
        self._save_pair_record_on_peer()
        self._init_client_server_main_encryption_keys()
        self._create_remote_unlock()
        self.save_pair_record()

    def _request_pair_consent(self) -> PairConsentResult:
        """ Display a Trust / Don't Trust dialog """

        tlv = PairingDataComponentTLVBuf.build([
            { 'type': PairingDataComponentType.METHOD, 'data': b'\x00' },
            { 'type': PairingDataComponentType.STATE,  'data': b'\x01' },
        ])

        self._send_pairing_data({
            'data': tlv,
            'kind': 'setupManualPairing',
            'sendingHost': platform.node(),
            'startNewSession': True
        })
        
        self.logger.info('Waiting user pairing consent')
        response = self._receive_plain_response()['event']['_0']
        
        if 'pairingRejectedWithError' in response:
            raise PairingError(
                response['pairingRejectedWithError']['wrappedError']['userInfo']['NSLocalizedDescription']
            )
        elif 'awaitingUserConsent' in response:
            pairingData = self._receive_pairing_data()
        else:
            # On tvOS no consent is needed and pairing data is returned immediately.
            pairingData = self._decode_bytes_if_needed(response['pairingData']['_0']['data'])

        data = self.decode_tlv(
            PairingDataComponentTLVBuf.parse(pairingData)
        )
        
        return PairConsentResult(
            public_key=data[PairingDataComponentType.PUBLIC_KEY],
            salt=data[PairingDataComponentType.SALT]
        )

    def _init_srp_context(
        self,
        pairing_consent_result: PairConsentResult
    ) -> None:
        # Receive server public and salt and process them.
        client_session = SRPClientSession(
            SRPContext(
                'Pair-Setup',
                password='000000',
                prime=PRIME_3072,
                generator=PRIME_3072_GEN,
                hash_func=hashlib.sha512
            )
        )
        client_session.process(
            pairing_consent_result.public_key.hex(),
            pairing_consent_result.salt.hex()
        )
        self.srp_context = client_session
        self.session_key = binascii.unhexlify(self.srp_context.key)
    
    def _verify_proof(self) -> None:
        client_public = binascii.unhexlify(self.srp_context.public)
        client_session_key_proof = binascii.unhexlify(self.srp_context.key_proof)

        tlv = PairingDataComponentTLVBuf.build([
            {'type': PairingDataComponentType.STATE,      'data': b'\x03'},
            {'type': PairingDataComponentType.PUBLIC_KEY, 'data': client_public[:255]},
            {'type': PairingDataComponentType.PUBLIC_KEY, 'data': client_public[255:]},
            {'type': PairingDataComponentType.PROOF,      'data': client_session_key_proof},
        ])

        response = self._send_receive_pairing_data({
            'data': tlv,
            'kind': 'setupManualPairing',
            'sendingHost': platform.node(),
            'startNewSession': False,
        })
        data = self.decode_tlv(
            PairingDataComponentTLVBuf.parse(response)
        )
        assert self.srp_context.verify_proof(
            data[PairingDataComponentType.PROOF].hex().encode()
        )

    def _save_pair_record_on_peer(self) -> Mapping:
        setup_encryption_key = hkdf(
            salt = b'Pair-Setup-Encrypt-Salt',
            info = b'Pair-Setup-Encrypt-Info',
            key = self.session_key,
        )
        
        self.signing_key = NaclSigningKey.generate()
        
        signbuf = hkdf(
            salt = b'Pair-Setup-Controller-Sign-Salt',
            info = b'Pair-Setup-Controller-Sign-Info',
            key = self.session_key,
        )

        signbuf += self.identifier.encode()
        public_raw_bytes = self.signing_key.verify_key.encode()
        
        signbuf += public_raw_bytes
        

        signature = self.signing_key.sign(signbuf).signature

        device_info = TinyOPack.build({
            'altIRK': b'\xe9\xe8-\xc0jIykVoT\x00\x19\xb1\xc7{',
            'btAddr': '11:22:33:44:55:66',
            'mac': b'\x11\x22\x33\x44\x55\x66',
            'remotepairing_serial_number': 'AAAAAAAAAAAA',
            'accountID': self.identifier,
            'model': 'computer-model',
            'name': platform.node(),
        })

        tlv = PairingDataComponentTLVBuf.build([
            {'type': PairingDataComponentType.IDENTIFIER, 'data': self.identifier.encode()},
            {'type': PairingDataComponentType.PUBLIC_KEY, 'data': public_raw_bytes},
            {'type': PairingDataComponentType.SIGNATURE,  'data': signature},
            {'type': PairingDataComponentType.INFO,       'data': device_info},
        ])

        cipher = ChaCha20Poly1305(setup_encryption_key)
        encrypted_data = cipher.encrypt(b'\x00\x00\x00\x00PS-Msg05', tlv, b'')

        tlv = PairingDataComponentTLVBuf.build([
            {'type': PairingDataComponentType.ENCRYPTED_DATA, 'data': encrypted_data[:255]},
            {'type': PairingDataComponentType.ENCRYPTED_DATA, 'data': encrypted_data[255:]},
            {'type': PairingDataComponentType.STATE,          'data': b'\x05'},
        ])

        response = self._send_receive_pairing_data({
            'data': tlv,
            'kind': 'setupManualPairing',
            'sendingHost': platform.node(),
            'startNewSession': False,
        })
        data = self.decode_tlv(PairingDataComponentTLVBuf.parse(response))

        tlv = PairingDataComponentTLVBuf.parse(
            cipher.decrypt(
                b'\x00\x00\x00\x00PS-Msg06',
                data[PairingDataComponentType.ENCRYPTED_DATA],
                b''
            )
        )

        return tlv

    def _init_client_server_main_encryption_keys(self) -> None:
        client_key = hkdf(
            info=b'ClientEncrypt-main',
            key = self.session_key,
        )
        
        self.client_cipher = ChaCha20Poly1305(client_key)

        server_key = hkdf(
            info=b'ServerEncrypt-main',
            key = self.session_key,
        )
        
        self.server_cipher = ChaCha20Poly1305(server_key)

    def _create_remote_unlock(self) -> None:
        response = self._send_receive_encrypted_request({
            'request': {
                '_0': {
                    'createRemoteUnlockKey': {}
                }
            }
        })
        
        if 'errorExtended' in response:
            self.remote_unlock_host_key = None
        else:
            self.remote_unlock_host_key = response['createRemoteUnlockKey']['hostKey']

    def _attempt_pair_verify(self) -> None:
        self.handshake_info = self._send_receive_handshake({
            'hostOptions': {'attemptPairVerify': True},
            'wireProtocolVersion': XpcInt64Type(self.WIRE_PROTOCOL_VERSION),
        })

    @staticmethod
    def _decode_bytes_if_needed(data: bytes) -> bytes:
        return data

    def _validate_pairing(self) -> bool:
        x25519_public_key = self.private_key.public_key
        pairing_data = PairingDataComponentTLVBuf.build([
            {
                'type': PairingDataComponentType.STATE,
                'data': b'\x01',
            },
            {
                'type': PairingDataComponentType.PUBLIC_KEY,
                'data': x25519_public_key.encode()
            },
        ])
        
        response = self._send_receive_pairing_data({
            'data': pairing_data,
            'kind': 'verifyManualPairing',
            'startNewSession': True,
        })

        data = self.decode_tlv(PairingDataComponentTLVBuf.parse(response))

        if PairingDataComponentType.ERROR in data:
            print(f'Error verify 1 {data[PairingDataComponentType.ERROR]}')
            self._send_pair_verify_failed()
            return False

        peer_public_key = VerifyKey( data[ PairingDataComponentType.PUBLIC_KEY ] )
        self.session_key = bindings.crypto_scalarmult( self.private_key._private_key, peer_public_key._key)
        
        derived_key = hkdf(
            salt=b'Pair-Verify-Encrypt-Salt',
            info=b'Pair-Verify-Encrypt-Info',
            key = self.session_key,
        )
        cipher = ChaCha20Poly1305(derived_key)
        
        # TODO: Can verify from received data? For now verifying using next stage

        if self.pair_record is None:
            self.signing_key = NaclSigningKey(b'\x00' * 0x20)
        else:
            self.signing_key = NaclSigningKey(self.pair_record['private_key'])

        signbuf = b''
        signbuf += self.private_key.public_key.encode()
        signbuf += self.identifier.encode()
        signbuf += peer_public_key.encode()

        signature = self.signing_key.sign(signbuf).signature

        encrypted_data = cipher.encrypt(
            b'\x00\x00\x00\x00PV-Msg03',
            PairingDataComponentTLVBuf.build([
                {'type': PairingDataComponentType.IDENTIFIER, 'data': self.identifier.encode()},
                {'type': PairingDataComponentType.SIGNATURE,  'data': signature},
            ]),
            b''
        )

        pairing_data = PairingDataComponentTLVBuf.build([
            {'type': PairingDataComponentType.STATE,          'data': b'\x03'},
            {'type': PairingDataComponentType.ENCRYPTED_DATA, 'data': encrypted_data},
        ])

        response = self._send_receive_pairing_data({
            'data': pairing_data,
            'kind': 'verifyManualPairing',
            'startNewSession': False,
        })
        data = self.decode_tlv(PairingDataComponentTLVBuf.parse(response))

        if PairingDataComponentType.ERROR in data:
            logger.debug("Could not verify remote pairing - maybe expected - %s", f'{data[PairingDataComponentType.ERROR]}')
            self._send_pair_verify_failed()
            return False

        return True

    def _send_pair_verify_failed(self) -> None:
        self._send_plain_request({'event': {'_0': {'pairVerifyFailed': {}}}})

    def _send_receive_encrypted_request(self, request: Mapping) -> Mapping:
        nonce = Int64ul.build(self._encrypted_sequence_number) + b'\x00' * 4
        
        encrypted_data = self.client_cipher.encrypt(
            nonce,
            json.dumps(request).encode(),
            b''
        )

        response = self.send_receive_request({
            'message': {
                'streamEncrypted': {
                    '_0': encrypted_data
                }
            },
            'originatedBy': 'host',
            'sequenceNumber': XpcUInt64Type(self._sequence_number)
        })
        
        self._encrypted_sequence_number += 1

        encrypted_data = self._decode_bytes_if_needed(
            response['message']['streamEncrypted']['_0']
        )
        plaintext = self.server_cipher.decrypt(
            nonce,
            encrypted_data,
            b'',
        )
        return json.loads(plaintext)['response']['_1']

    def _send_receive_handshake(
        self,
        handshake_data: Mapping
    ) -> Mapping:
        response = self._send_receive_plain_request({
            'request': {
                '_0': {
                    'handshake': {
                        '_0': handshake_data
                    }
                }
            }
        })
        return response['response']['_1']['handshake']['_0']

    def _send_receive_pairing_data(
        self,
        pairing_data: Mapping
    ) -> bytes:
        self._send_pairing_data(pairing_data)
        return self._receive_pairing_data()

    def _send_pairing_data(
        self,
        pairing_data: Mapping
    ) -> None:
        self._send_plain_request({
            'event': {
                '_0': {
                    'pairingData': {
                        '_0': pairing_data
                    }
                }
            }
        })

    def _receive_pairing_data(self) -> bytes:
        raw_response = self._receive_plain_response()
        response = raw_response['event']['_0']
        if 'pairingData' in response:
            return self._decode_bytes_if_needed(response['pairingData']['_0']['data'])
        if 'pairingRejectedWithError' in response:
            raise UserDeniedPairingError(
                response['pairingRejectedWithError']
                    .get('wrappedError', {})
                    .get('userInfo', {})
                    .get('NSLocalizedDescription')
            )
        raise Exception(f'Got an unknown state message: {response}')

    def _send_receive_plain_request(
        self,
        plain_request: Mapping
    ):
        self._send_plain_request(plain_request)
        return self._receive_plain_response()

    def _send_plain_request(
        self,
        plain_request: Mapping
    ) -> None:
        self.send_request({
            'message': {
                'plain': {
                    '_0': plain_request
                }
            },
            'originatedBy': 'host',
            'sequenceNumber': XpcUInt64Type(self._sequence_number)
        })
        self._sequence_number += 1

    def _receive_plain_response(self) -> Mapping:
        response = self.receive_response()
        return response['message']['plain']['_0']

    @staticmethod
    def decode_tlv(tlv_list: List[Container]) -> Mapping:
        result = {}
        
        for tlv in tlv_list:
            if tlv.type in result:
                result[tlv.type] += tlv.data
            else:
                result[tlv.type] = tlv.data
        
        return result

    def __enter__(self) -> 'CoreTunnelService':
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


class CoreTunnelService(TunnelService, RemoteService):
    SERVICE_NAME = 'com.apple.internal.dt.coredevice.untrusted.tunnelservice'

    def __init__(
        self,
        rsd: RemoteServiceDiscovery
    ):
        RemoteService.__init__(
            self,
            rsd,
            self.SERVICE_NAME
        )
        TunnelService.__init__(self)
        self.udid = self.rsd.udid
        #self.version: Optional[int] = None

    def connect(
        self,
        autopair: bool = True
    ) -> None:
        RemoteService.connect(self)
        #self.version = 
        self.service.receive_response()#['ServiceVersion']
        TunnelService.connect(self, autopair=autopair)
        self.hostname = self.service.address[0]

    def close(self) -> None:
        self.rsd.close()
        self.service.close()

    def receive_response(self) -> Mapping:
        return self.service.receive_response()['value']

    def send_request(self, data: Mapping) -> None:
        return self.service.send_request({
            'mangledTypeName': 'RemotePairing.ControlChannelMessageEnvelope',
            'value': data,
        })


class RemoteTunnelService(TunnelService):
    def __init__(
        self,
        remote_identifier: str,
        hostname: str,
        port: int
    ) -> None:
        TunnelService.__init__(self)
        self._remote_identifier = remote_identifier
        self.hostname = hostname
        self.port = port
        self._connection: Optional[ServiceConnection] = None

    @property
    def remote_identifier(self) -> str:
        return self._remote_identifier

    def connect(
        self,
        autopair: bool = True
    ) -> None:
        self._connection = ServiceConnection.init_with_tcp(self.hostname, self.port)
        
        self._attempt_pair_verify()
        if not self._validate_pairing():
            raise ConnectionAbortedError()
        self._init_client_server_main_encryption_keys()

    def close(self) -> None:
        self._connection.close()

    def receive_response(self) -> Mapping:
        return json.loads(RPPairingPacket.parse_stream(self._connection).body)

    def send_request(
        self,
        data: Mapping
    ) -> None:
        return self._connection.sendall(
            RPPairingPacket.build({
                'body': json.dumps(
                    data,
                    default=self._default_json_encoder
                ).encode()
            })
        )

    @staticmethod
    def _default_json_encoder(obj) -> str:
        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode()
        raise TypeError()

    @staticmethod
    def _decode_bytes_if_needed(data: bytes) -> bytes:
        return base64.b64decode(data)

    def __repr__(self) -> str:
        return (f'<{self.__class__.__name__} IDENTIFIER:{self.remote_identifier} HOSTNAME:{self.hostname} '
                f'PORT:{self.port}>')


class CoreTunnelProxy(StartTcpTunnel, LockdownService):
    SERVICE_NAME = 'com.apple.internal.devicecompute.CoreDeviceProxy'

    def __init__(
        self,
        lockdown: LockdownServiceProvider
    ) -> None:
        LockdownService.__init__(
            self,
            lockdown,
            self.SERVICE_NAME
        )
        self._lockdown = lockdown
        self._service: Optional[ServiceConnection] = None
        
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        self._loop = loop

    @property
    def remote_identifier(self) -> str:
        return self._lockdown.udid

    @asynccontextmanager
    async def start_tcp_tunnel(self) -> AsyncGenerator['TunnelResult', None]:
        self._service = await self._lockdown.aio_start_lockdown_service(self.SERVICE_NAME)
        
        tunnel = RemoteTcpTunnel(
            self._service.reader,
            self._service.writer,
        )
        
        handshake_response = await tunnel.request_tunnel_establish()
        
        await tunnel.start_tunnel(
            handshake_response['clientParameters']['address'],
            handshake_response['clientParameters']['mtu'],
            label = self._lockdown.udid,
        )
        
        try:
            yield TunnelResult(
                tunnel.tun.name,
                handshake_response['serverAddress'],
                handshake_response['serverRSDPort'],
                'tcp',
                tunnel
            )
        finally:
            await tunnel.stop_tunnel()

    async def aio_close(self) -> None:
        await self._service.aio_close()
