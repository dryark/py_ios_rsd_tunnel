# Copyright (c) 2024 Dry Ark LLC
# License GPL 3.0
import logging
from ..lockdown_service_provider import LockdownServiceProvider
from ..service_connection import ServiceConnection

class LockdownService:
    def __init__(
        self,
        lockdown: LockdownServiceProvider,  # server provider
        service_name: str,                  # wrapped service name - will attempt
        service: ServiceConnection = None,  # an established service. If none, will attempt connecting to service_name 
        include_escrow_bag: bool = False
    ):
        if service is None:
            start_service = lockdown.start_lockdown_service
            service = start_service(service_name, include_escrow_bag=include_escrow_bag)
            
        self.service_name = service_name
        self.lockdown = lockdown
        self.service = service
        self.logger = logging.getLogger(self.__module__)

    def __enter__(self):
        return self

    async def __aenter__(self) -> 'LockdownService':
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.service.aio_close()

    def close(self) -> None:
        self.service.close()
