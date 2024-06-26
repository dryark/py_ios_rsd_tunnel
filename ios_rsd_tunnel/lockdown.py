# Copyright (c) 2012-2023 Mathieu Renard
# Copyright (c) 2021-2024 matan1008 <matan1008@gmail.com>
# Copyright (c) 2021-2024 doronz <doron88@gmail.com>
# Copyright (c) 2024 Dry Ark LLC <license@dryark.com>
# License GPL 3.0
import logging
import os
import plistlib
import tempfile
import time

from abc import (
    ABC,
    abstractmethod,
)
from contextlib import (
    contextmanager,
    suppress,
)
from enum import Enum
from functools import wraps
from oscrypto.keys import parse_pkcs12
from oscrypto.asymmetric import PrivateKey
from pathlib import Path
from ssl import SSLZeroReturnError
from typing import (
    Mapping,
    Optional,
)

from .ca import gen_rsa_and_certs
from . import usbmux
from .exceptions import *
from .lockdown_service_provider import LockdownServiceProvider
from .pair_records import (
    create_pair_record_cache_folder,
    generate_host_id,
    get_pair_record,
)
from .service_connection import ServiceConnection
from .usbmux import PlistMuxConnection

# Magic number. Where did this come from? Can it be anything?
SYSTEM_BUID = '30142955-444094379208051516'

DEFAULT_LABEL = 'iosRsdTunnel'
LOCKDOWN_PORT = 62078


class DeviceClass(Enum):
    IPHONE = 'iPhone'
    IPAD = 'iPad'
    IPOD = 'iPod'
    WATCH = 'Watch'
    APPLE_TV = 'AppleTV'
    UNKNOWN = 'Unknown'


def _reconnect_on_remote_close(f):
    # lockdownd's _socket_select will close the connection after 60 seconds of inactivity.
    #    When this happens, attempt to reconnect.

    @wraps(f)
    def _inner_reconnect_on_remote_close(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except (BrokenPipeError, ConnectionTerminatedError):
            self: LockdownClient = args[0]

            self._reestablish_connection()
            self.validate_pairing()
            return f(*args, **kwargs)

    return _inner_reconnect_on_remote_close


class LockdownClient(ABC, LockdownServiceProvider):
    def __init__(
        self,
        service:                  ServiceConnection,       # lockdownd connection handler
        host_id:                  str,                     # host identifier for the handshake
        identifier:               str     = None,          # identifier to look for the device pair record
        label:                    str     = DEFAULT_LABEL, # lockdownd user-agent
        system_buid:              str     = SYSTEM_BUID,   # System's unique identifier
        pair_record:              Mapping = None,
        pair_record_cache_folder: Path    = None,
        port:                     int     = LOCKDOWN_PORT
    ):
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self.service = service
        self.identifier = identifier
        self.label = label
        self.host_id = host_id
        self.system_buid = system_buid
        self.pair_record = pair_record
        self.paired = False
        self.session_id = None
        self.pair_record_cache_folder = pair_record_cache_folder
        self.port = port

        if self.query_type() != 'com.apple.mobile.lockdown':
            raise IncorrectModeError()

        self.all_values = self.get_value()
        self.udid = self.all_values.get('UniqueDeviceID')
        self.unique_chip_id = self.all_values.get('UniqueChipID')
        self.device_public_key = self.all_values.get('DevicePublicKey')
        self.product_type = self.all_values.get('ProductType')

    @classmethod
    def create(
        cls,
        service: ServiceConnection,       # lockdownd connection handler
        identifier: str = None,           # identifier to look for the device pair record
        system_buid: str = SYSTEM_BUID,   # System's unique identifier
        label: str = DEFAULT_LABEL,       # lockdownd user-agent
        autopair: bool = True,
        pair_timeout: float = None,
        local_hostname: str = None,       # seed to generate the HostID
        pair_record: Mapping = None,      # Pair record instead of the default
        pair_record_cache_folder: Path = None,
        port: int = LOCKDOWN_PORT,
        private_key: Optional[PrivateKey] = None, # RSA key for pairing. generated if None
        **cls_specific_args               # Additional members to pass into LockdownClient subclasses
    ):
        host_id = generate_host_id(local_hostname)
        pair_record_cache_folder = create_pair_record_cache_folder(pair_record_cache_folder)

        lockdown_client = cls(
            service,
            host_id=host_id,
            identifier=identifier,
            label=label,
            system_buid=system_buid,
            pair_record=pair_record,
            pair_record_cache_folder=pair_record_cache_folder,
            port=port,
            **cls_specific_args
        )
        lockdown_client._handle_autopair(
            autopair,
            pair_timeout,
            private_key=private_key
        )
        return lockdown_client

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__} ID:{self.identifier} VERSION:{self.product_version} ' \
               f'TYPE:{self.product_type} PAIRED:{self.paired}>'

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    @property
    def product_version(self) -> str:
        return self.all_values.get('ProductVersion')

    def query_type(self) -> str:
        return self._request('QueryType').get('Type')

    def stop_session(self) -> Mapping:
        if self.session_id and self.service:
            response = self._request('StopSession', {'SessionID': self.session_id})
            self.session_id = None
            if not response or response.get('Result') != 'Success':
                raise CannotStopSessionError()
            return response

    def validate_pairing(self) -> bool:
        if self.pair_record is None:
            try:
                self.fetch_pair_record()
            except NotPairedError:
                pass

        if self.pair_record is None:
            return False

        self.host_id = self.pair_record.get('HostID', self.host_id)
        self.system_buid = self.pair_record.get('SystemBUID', self.system_buid)

        try:
            start_session = self._request('StartSession', {'HostID': self.host_id, 'SystemBUID': self.system_buid})
        except (InvalidHostIDError, InvalidConnectionError):
            # no host id means there is no such pairing record
            return False

        self.session_id = start_session.get('SessionID')
        if start_session.get('EnableSessionSSL'):
            with self.ssl_file() as f:
                try:
                    self.service.ssl_start(f)
                except SSLZeroReturnError:
                    # possible when we have a pair record, but it was removed on-device
                    self._reestablish_connection()
                    return False

        self.paired = True

        # reload data after pairing
        self.all_values = self.get_value()
        self.udid = self.all_values.get('UniqueDeviceID')

        return True

    @_reconnect_on_remote_close
    def pair(
        self,
        timeout: float = None,
        private_key: Optional[PrivateKey] = None
    ) -> None:
        self.device_public_key = self.get_value('', 'DevicePublicKey')
        if not self.device_public_key:
            self.logger.error('Unable to retrieve DevicePublicKey')
            self.service.close()
            raise PairingError()

        self.logger.info('Creating host key & certificate')
        
        cert_pem, private_key_pem, device_certificate_pem = gen_rsa_and_certs(
            device_public_key_pem = self.device_public_key,
            private_key = private_key,
        )

        pair_record = {
            'DevicePublicKey':   self.device_public_key,
            'DeviceCertificate': device_certificate_pem,
            'HostCertificate':   cert_pem,
            'HostID':            self.host_id,
            'RootCertificate':   cert_pem,
            'RootPrivateKey':    private_key_pem,
            #'WiFiMACAddress':    self.wifi_mac_address,
            'SystemBUID':        self.system_buid,
        }

        pair_options = {
            'PairRecord': pair_record,
            'ProtocolVersion': '2',
            'PairingOptions': {'ExtendedPairingErrors': True},
        }

        pair = self._request_pair(pair_options, timeout=timeout)

        pair_record['HostPrivateKey'] = private_key_pem
        escrow_bag = pair.get('EscrowBag')

        if escrow_bag is not None:
            pair_record['EscrowBag'] = pair.get('EscrowBag')

        self.pair_record = pair_record
        self.save_pair_record()
        self.paired = True

    @_reconnect_on_remote_close
    def pair_supervised(
        self,
        timeout: float = None,
        p12file: Path = None,
        password: str = None
    ) -> None:

        keystore_data = p12file.read()
        try:
            #decrypted_p12 = load_pkcs12(
            #    keystore_data, password.encode('utf-8')
            #)
            # private_key_info: asn1crypto.keys.PrivateKeyInfo
            # cert: asn1crypto.x509.Certificate
            p12_private_key_info, p12_cert, _ = parse_pkcs12(
                keystore_data, # should be in der format
                password.encode('utf-8'), # should be a byte string
            )
        except Exception as pkcs12_error:
            self.service.close()
            raise Exception(f'load_pkcs12 error: {pkcs12_error}')

        self.device_public_key = self.get_value('', 'DevicePublicKey')
        if not self.device_public_key:
            self.logger.error('Unable to retrieve DevicePublicKey')
            self.service.close()
            raise PairingError()

        self.logger.info('Creating host key & certificate')
        cert_pem, private_key_pem, device_certificate = gen_rsa_and_certs(
            device_public_key_pem = self.device_public_key,
        )

        pair_record = {
            'DevicePublicKey':   self.device_public_key,
            'DeviceCertificate': device_certificate,
            'HostCertificate':   cert_pem,
            'HostID':            self.host_id,
            'RootCertificate':   cert_pem,
            'RootPrivateKey':    private_key_pem,
            'WiFiMACAddress':    self.wifi_mac_address,
            'SystemBUID':        self.system_buid,
        }

        pair_options = {
            'PairRecord': pair_record, 'ProtocolVersion': '2',
            'PairingOptions': {
                #'SupervisorCertificate': decrypted_p12.cert.certificate.public_bytes(Encoding.DER),
                'SupervisorCertificate': p12_cert.dump(),
                'ExtendedPairingErrors': True,
            }
        }

        # first pair with SupervisorCertificate as PairingOptions to get Challenge
        pair = self._request_pair(pair_options, timeout=timeout)
        if pair.get('Error') == 'MCChallengeRequired':
            extendedresponse = pair.get('ExtendedResponse')
            if extendedresponse is not None:
                pairingchallenge = extendedresponse.get('PairingChallenge')
                
                #signed_response = PKCS7SignatureBuilder().set_data(pairingchallenge).add_signer(
                #    decrypted_p12.cert.certificate,
                #    decrypted_p12.key,
                #    hashes.SHA256()
                #).sign(Encoding.DER, [])
                
                # TODO: implement sign_data_get_pkcs7_der
                signed_response = sign_data_get_pkcs7_der(
                    private_key_pem,
                    pairingchallenge,
                )
                #signature = asymmetric.rsa_pkcs1v15_sign( private_key, pairingchallenge, 'sha256' )
                
                
                pair_options = {
                    'PairRecord': pair_record,
                    'ProtocolVersion': '2',
                    'PairingOptions': {
                        'ChallengeResponse': signed_response,
                        'ExtendedPairingErrors': True,
                    }
                }
                # second pair with Response to Challenge
                pair = self._request_pair(pair_options, timeout=timeout)

        pair_record['HostPrivateKey'] = private_key_pem
        escrow_bag = pair.get('EscrowBag')

        if escrow_bag is not None:
            pair_record['EscrowBag'] = pair.get('EscrowBag')

        self.pair_record = pair_record
        self.save_pair_record()
        self.paired = True

    @_reconnect_on_remote_close
    def unpair(self, host_id: str = None) -> None:
        pair_record = self.pair_record if host_id is None else {'HostID': host_id}
        
        self._request(
            'Unpair',
            {
                'PairRecord': pair_record,
                'ProtocolVersion': '2'
            },
            verify_request=False
        )

    @_reconnect_on_remote_close
    def reset_pairing(self):
        return self._request(
            'ResetPairing',
            {
                'FullReset': True
            }
        )

    @_reconnect_on_remote_close
    def get_value(self, domain: str = None, key: str = None):
        options = {}

        if domain:
            options['Domain'] = domain
        if key:
            options['Key'] = key

        res = self._request('GetValue', options)
        if res:
            r = res.get('Value')
            if hasattr(r, 'data'):
                return r.data
            return r

    def get_service_connection_attributes(
        self,
        name: str,
        include_escrow_bag: bool = False
    ) -> Mapping:
        if not self.paired:
            raise NotPairedError()

        options = {'Service': name}
        
        if include_escrow_bag:
            options['EscrowBag'] = self.pair_record['EscrowBag']

        response = self._request('StartService', options)
        
        if not response or response.get('Error'):
            if response.get('Error', '') == 'PasswordProtected':
                raise PasswordRequiredError(
                    'your device is protected with password, please enter password in device and try again')
            raise StartServiceError(response.get('Error'))
        
        return response

    @_reconnect_on_remote_close
    def start_lockdown_service(
        self,
        name: str,
        include_escrow_bag: bool = False
    ) -> ServiceConnection:
        attr = self.get_service_connection_attributes(
            name,
            include_escrow_bag=include_escrow_bag
        )
        service_connection = self._create_service_connection(attr['Port'])

        if attr.get('EnableServiceSSL', False):
            with self.ssl_file() as f:
                service_connection.ssl_start(f)
        
        return service_connection

    async def aio_start_lockdown_service(
        self,
        name: str,
        include_escrow_bag: bool = False
    ) -> ServiceConnection:
        attr = self.get_service_connection_attributes(
            name,
            include_escrow_bag=include_escrow_bag
        )
        service_connection = self._create_service_connection(attr['Port'])

        if attr.get('EnableServiceSSL', False):
            with self.ssl_file() as f:
                await service_connection.aio_ssl_start(f)
        
        return service_connection

    def close(self) -> None:
        self.service.close()

    @contextmanager
    def ssl_file(self) -> str:
        cert_pem = self.pair_record['HostCertificate']
        private_key_pem = self.pair_record['HostPrivateKey']

        # use delete=False and manage the deletion ourselves because Windows
        # cannot use in-use files
        with tempfile.NamedTemporaryFile('w+b', delete=False) as f:
            if isinstance(cert_pem, str):
                cert_pem = bytes( cert_pem, 'utf-8' )
            if isinstance(private_key_pem, str):
                private_key_pem = bytes( private_key_pem, 'utf-8' )
            combined = cert_pem + b'\n' + private_key_pem
            f.write( combined )
            filename = f.name

        try:
            yield filename
        finally:
            os.unlink(filename)

    def _handle_autopair(
        self,
        autopair: bool,
        timeout: float,
        private_key: Optional[PrivateKey] = None
    ) -> None:
        if self.validate_pairing():
            return

        # device is not paired yet
        if not autopair:
            # but pairing by default was not requested
            return
        self.pair(
            timeout=timeout,
            private_key=private_key
        )
        # get session_id
        if not self.validate_pairing():
            raise FatalPairingError()

    @abstractmethod
    def _create_service_connection(self, port: int) -> ServiceConnection:
        """ Used to establish a new ServiceConnection to a given port """
        pass

    def _request(
        self,
        request: str,
        options: Mapping = None,
        verify_request: bool = True
    ) -> Mapping:
        message = {
            'Label': self.label,
            'Request': request,
        }
        
        if options:
            message.update(options)
        
        response = self.service.send_recv_plist(message)

        if verify_request and response['Request'] != request:
            raise LockdownError(f'incorrect response returned. got {response["Request"]} instead of {request}')

        error = response.get('Error')
        if error is not None:
            # return response if supervisor cert challenge is required, to work with pair_supervisor
            if error == 'MCChallengeRequired':
                return response
            
            exception_errors = {
                'PasswordProtected': PasswordRequiredError,
                'PairingDialogResponsePending': PairingDialogResponsePendingError,
                'UserDeniedPairing': UserDeniedPairingError,
                'InvalidHostID':     InvalidHostIDError,
                'GetProhibited':     GetProhibitedError,
                'SetProhibited':     SetProhibitedError,
                'MissingValue':      MissingValueError,
                'InvalidService':    InvalidServiceError,
                'InvalidConnection': InvalidConnectionError,
            }
            raise exception_errors.get(error, LockdownError)(error)

        # iOS < 5: 'Error' is not present, so we need to check the 'Result' instead
        if response.get('Result') == 'Failure':
            raise LockdownError()

        return response

    def _request_pair(
        self,
        pair_options: Mapping,
        timeout: float = None,
    ) -> Mapping:
        try:
            return self._request('Pair', pair_options)
        except PairingDialogResponsePendingError:
            if timeout == 0:
                raise

        self.logger.info('waiting user pairing dialog...')
        start = time.time()
        
        while timeout is None or time.time() <= start + timeout:
            with suppress(PairingDialogResponsePendingError):
                return self._request('Pair', pair_options)
            time.sleep(1)
        
        raise PairingDialogResponsePendingError()

    def fetch_pair_record(self) -> None:
        if self.identifier is not None:
            self.pair_record = get_pair_record(
                self.identifier,
                self.pair_record_cache_folder,
            )

    def save_pair_record(self) -> None:
        pair_record_file = self.pair_record_cache_folder / f'{self.identifier}.plist'
        
        pair_record_file.write_bytes(
            plistlib.dumps(
                self.pair_record
            )
        )

    def _reestablish_connection(self) -> None:
        self.close()
        self.service = self._create_service_connection(self.port)


class UsbmuxLockdownClient(LockdownClient):
    def __init__(
        self,
        service: ServiceConnection,
        host_id: str,
        identifier:               str           = None,
        label:                    str           = DEFAULT_LABEL,
        system_buid:              str           = SYSTEM_BUID,
        pair_record:              Mapping       = None,
        pair_record_cache_folder: Path          = None,
        port:                     int           = LOCKDOWN_PORT,
        usbmux_address:           Optional[str] = None,
    ):
        super().__init__(
            service,
            host_id,
            identifier,
            label,
            system_buid,
            pair_record,
            pair_record_cache_folder,
            port
        )
        self.usbmux_address = usbmux_address

    def fetch_pair_record(self) -> None:
        if self.identifier is not None:
            self.pair_record = get_pair_record(
                self.identifier,
                self.pair_record_cache_folder,
                usbmux_address=self.usbmux_address,
            )

    def _create_service_connection(self, port: int) -> ServiceConnection:
        return ServiceConnection.init_with_usbmux(
            self.identifier,
            port,
            self.service.mux_device.connection_type,
            usbmux_address=self.usbmux_address,
        )


class RemoteLockdownClient(LockdownClient):
    def _create_service_connection(self, port: int) -> ServiceConnection:
        raise NotImplementedError(
            'RemoteXPC service connections should only be created using RemoteServiceDiscovery')

    def _handle_autopair(self, *args, **kwargs):
        # The RemoteXPC version of lockdown doesn't support pairing operations
        return None

    def pair(self, *args, **kwargs) -> None:
        raise NotImplementedError('RemoteXPC lockdown version does not support pairing operations')

    def unpair(self, timeout: float = None) -> None:
        raise NotImplementedError('RemoteXPC lockdown version does not support pairing operations')

    def __init__(
        self,
        service: ServiceConnection,      # lockdownd connection handler
        host_id: str,                    # host identifier for the handshake
        identifier: str = None,          # identifier to look for the device pair record
        label: str = DEFAULT_LABEL,      # lockdownd user-agent
        system_buid: str = SYSTEM_BUID,  # System's unique identifier
        pair_record: Mapping = None,     # Pair record instead of the default
        pair_record_cache_folder: Path = None,
        port: int = LOCKDOWN_PORT,
    ):
        super().__init__(
            service, 
            host_id, 
            identifier,
            label,
            system_buid,
            pair_record,
            pair_record_cache_folder,
            port 
        )


class PlistUsbmuxLockdownClient(UsbmuxLockdownClient):
    def save_pair_record(self) -> None:
        super().save_pair_record()
        record_data = plistlib.dumps(self.pair_record)
        with usbmux.create_mux() as client:
            client.save_pair_record(self.identifier, self.service.mux_device.devid, record_data)


def lockdown_via_usbmux(
    serial: str = None,            # Usbmux serial identifier
    identifier: str = None,        # identifier to look for the device pair record
    label: str = DEFAULT_LABEL,    # lockdownd user-agent
    autopair: bool = True,
    connection_type: str = None,   # Force usbmux connection type ('usb'/'wifi')
    pair_timeout: float = None,    # Timeout for autopair
    local_hostname: str = None,    # Used as a seed to generate the HostID
    pair_record: Mapping = None,   # Pair record instead of the default
    pair_record_cache_folder: Path = None,
    port: int = LOCKDOWN_PORT,
    usbmux_address: Optional[str] = None,
) -> UsbmuxLockdownClient:
    service = ServiceConnection.init_with_usbmux(
        serial,
        port,
        connection_type=connection_type,
        usbmux_address=usbmux_address,
    )
    
    cls = UsbmuxLockdownClient
    
    with usbmux.create_mux(usbmux_address=usbmux_address) as client:
        if isinstance(client, PlistMuxConnection):
            # Only the Plist version of usbmuxd supports this message type
            system_buid = client.get_buid()
            cls = PlistUsbmuxLockdownClient

    if identifier is None:
        # attempt get identifier from mux device serial
        identifier = service.mux_device.serial

    return cls.create(
        service,
        identifier=identifier,
        label=label,
        system_buid=system_buid,
        local_hostname=local_hostname,
        pair_record=pair_record,
        pair_record_cache_folder=pair_record_cache_folder,
        pair_timeout=pair_timeout,
        autopair=autopair,
        usbmux_address=usbmux_address
    )


def lockdown_via_remote(
    service: ServiceConnection,
    identifier:               str     = None,
    label:                    str     = DEFAULT_LABEL,
    autopair:                 bool    = True,
    pair_timeout:             float   = None,
    local_hostname:           str     = None,
    pair_record:              Mapping = None,
    pair_record_cache_folder: Path    = None,
    port:                     int     = LOCKDOWN_PORT
) -> RemoteLockdownClient:
    client = RemoteLockdownClient.create(
        service,
        identifier=identifier,
        label=label,
        local_hostname=local_hostname,
        pair_record=pair_record,
        pair_record_cache_folder=pair_record_cache_folder,
        pair_timeout=pair_timeout,
        autopair=autopair,
        port=port,
    )
    
    return client
