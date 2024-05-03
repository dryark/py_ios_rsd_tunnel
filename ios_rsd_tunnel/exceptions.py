# Copyright (c) 2024 Dry Ark LLC <license@dryark.com>
# License GPL 3.0
class Exception(Exception):                  pass
class IncorrectModeError(Exception):         pass
class PairingError(Exception):               pass
class NotPairedError(Exception):             pass
class CannotStopSessionError(Exception):     pass
class PasswordRequiredError(PairingError):   pass
class StartServiceError(Exception):          pass
class FatalPairingError(Exception):          pass
class NoDeviceConnectedError(Exception):     pass
class MuxException(Exception):               pass
class MuxVersionError(MuxException):         pass
class BadCommandError(MuxException):         pass
class ConnectionTerminatedError(Exception):  pass
class ConnectionFailedError(MuxException):   pass
class ConnectionFailedToUsbmuxdError(ConnectionFailedError): pass
class BadDevError(MuxException):             pass
class LockdownError(Exception):              pass
class SetProhibitedError(LockdownError):     pass
class GetProhibitedError(LockdownError):     pass
class UserDeniedPairingError(PairingError):  pass
class InvalidHostIDError(PairingError):      pass
class InvalidServiceError(LockdownError):    pass
class PasscodeRequiredError(LockdownError):  pass
class InvalidConnectionError(LockdownError): pass
class AccessDeniedError(Exception):          pass
class StreamClosedError(ConnectionTerminatedError): pass # Sending a message to a closed stream
class InternalError(Exception):              pass # Internal Apple error
class MissingValueError(LockdownError):      pass # Query of a non-existent domain/key

class DeviceNotFoundError(Exception):
    def __init__(self, udid: str):
        super().__init__()
        self.udid = udid

class PairingDialogResponsePendingError(PairingError):
    pass # User hasn't yet confirmed pairing

__all__ = [
    name for name, cls in locals().items() if isinstance(cls, type) and (
        issubclass(cls, Exception)
    )
]
