# Copyright (c) 2024 Dry Ark LLC
import asyncio
import platform
import socket
import traceback

from functools import wraps
from typing import Callable


DEFAULT_AFTER_IDLE_SEC = 3
DEFAULT_INTERVAL_SEC = 3
DEFAULT_MAX_FAILS = 3
_DARWIN_TCP_KEEPALIVE = 0x10
_DARWIN_TCP_KEEPINTVL = 0x101
_DARWIN_TCP_KEEPCNT = 0x102


def asyncio_print_traceback(f: Callable):
    @wraps(f)
    async def wrapper(*args, **kwargs):
        try:
            return await f(*args, **kwargs)
        except Exception as e:  # noqa: E72
            if not isinstance(e, asyncio.CancelledError):
                traceback.print_exc()
            raise

    return wrapper


def set_keepalive(
    sock: socket.socket,
    after_idle_sec: int = DEFAULT_AFTER_IDLE_SEC,
    interval_sec: int = DEFAULT_INTERVAL_SEC,
    max_fails: int = DEFAULT_MAX_FAILS
) -> None:
    """
    set keep-alive parameters on a given socket

    :param sock: socket to operate on
    :param after_idle_sec: idle time used when SO_KEEPALIVE is enabled
    :param interval_sec: interval between keepalives
    :param max_fails: number of keepalives before close

    """
    plat = platform.system()
    if plat == 'Darwin':
        return _set_keepalive_darwin(sock, after_idle_sec, interval_sec, max_fails)
    
    raise RuntimeError(f'Unsupported platform {plat}')


def _set_keepalive_darwin(
    sock: socket.socket,
    after_idle_sec: int = DEFAULT_AFTER_IDLE_SEC,
    interval_sec: int = DEFAULT_INTERVAL_SEC,
    max_fails: int = DEFAULT_MAX_FAILS
) -> None:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.setsockopt(socket.IPPROTO_TCP, _DARWIN_TCP_KEEPALIVE, after_idle_sec)
    sock.setsockopt(socket.IPPROTO_TCP, _DARWIN_TCP_KEEPINTVL, interval_sec)
    sock.setsockopt(socket.IPPROTO_TCP, _DARWIN_TCP_KEEPCNT, max_fails)

