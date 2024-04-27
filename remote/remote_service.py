# Copyright (c) 2024 Dry Ark LLC
import logging

from .remote_service_discovery import RemoteServiceDiscovery
from .remotexpc import RemoteXPCConnection
from typing import Optional


class RemoteService:
    def __init__(
        self,
        rsd: RemoteServiceDiscovery,
        service_name: str
    ):
        self.service_name = service_name
        self.rsd = rsd
        self.service: Optional[RemoteXPCConnection] = None
        self.logger = logging.getLogger(self.__module__)

    def connect(self) -> None:
        self.service = self.rsd.start_remote_service(self.service_name)
        self.service.connect()

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self) -> None:
        self.service.close()
