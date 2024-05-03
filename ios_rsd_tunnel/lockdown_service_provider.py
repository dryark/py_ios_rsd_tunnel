# Copyright (c) 2024 Dry Ark LLC
# License GPL 3.0
from abc import abstractmethod
from .service_connection import ServiceConnection
from typing import Optional


class LockdownServiceProvider:
    def __init__(self):
        self.udid: Optional[str] = None
        self.product_type: Optional[str] = None

    @property
    @abstractmethod
    def product_version(self) -> str:
        pass

    @property
    @abstractmethod
    def ecid(self) -> int:
        pass

    @abstractmethod
    def start_lockdown_service(
        self,
        name: str,
        include_escrow_bag: bool = False
    ) -> ServiceConnection:
        pass

    @abstractmethod
    async def aio_start_lockdown_service(
        self,
        name: str,
        include_escrow_bag: bool = False
    ) -> ServiceConnection:
        pass
