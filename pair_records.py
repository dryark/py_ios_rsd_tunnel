# Copyright (c) 2024 Dry Ark LLC
import logging
import platform
import plistlib
import uuid

from contextlib import suppress
from pathlib import Path
from . import usbmux
from .home_folder import get_home_folder
from .exceptions import *
from .usbmux import PlistMuxConnection
from typing import (
    Generator,
    Mapping,
    Optional,
)

logger = logging.getLogger(__name__)

def generate_host_id(hostname: str = None) -> str:
    hostname = platform.node() if hostname is None else hostname
    host_id = uuid.uuid3(uuid.NAMESPACE_DNS, hostname)
    return str(host_id).upper()

def get_local_pair_record(
    identifier: str,
    local_pairing_path: Path
) -> Optional[Mapping]:
    logger.debug('Looking for local(~) pairing record')
    path = local_pairing_path / f'{identifier}.plist'
    
    if not path.exists():
        logger.debug(f'No pairing found for {identifier} in {local_pairing_path}')
        return None
    
    return plistlib.loads( path.read_bytes() )

def get_pair_record(
    identifier: str,
    pair_record_cache_folder: Path,
    usbmux_address: Optional[str] = None,
) -> Optional[Mapping]:
    # usbmuxd
    with suppress(NotPairedError, MuxException):
        with usbmux.create_mux(usbmux_address=usbmux_address) as mux:
            if isinstance(mux, PlistMuxConnection):
                pair_record = mux.get_pair_record(identifier)
                if pair_record is not None:
                    return pair_record

    # TODO on Linux use /var/db/lockdown

    # local storage
    return get_local_pair_record( identifier, pair_record_cache_folder )


def create_pair_record_cache_folder(pair_record_cache_folder: Path = None) -> Path:
    if pair_record_cache_folder is None:
        pair_record_cache_folder = get_home_folder()
    else:
        pair_record_cache_folder.mkdir(parents=True, exist_ok=True)
    
    return pair_record_cache_folder


def get_remote_pair_record_filename(identifier: str) -> str:
    return f'remote_{identifier}'


def iter_remote_pair_records() -> Generator[Path, None, None]:
    return get_home_folder().glob('remote_*')


def iter_remote_paired_identifiers() -> Generator[str, None, None]:
    for file in iter_remote_pair_records():
        yield file.parts[-1].split('remote_', 1)[1].split('.', 1)[0]
