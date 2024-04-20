# Copyright (c) 2024 Dry Ark LLC
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

class DeviceNotFoundError(Exception):
    def __init__(self, udid: str):
        super().__init__()
        self.udid = udid

class StreamClosedError(ConnectionTerminatedError):
    """ Raise when trying to send a message on a closed stream. """
    pass

class InternalError(Exception):
    """ Some internal Apple error """
    pass

class PairingDialogResponsePendingError(PairingError):
    """ User hasn't yet confirmed the device is trusted """
    pass

class MissingValueError(LockdownError):
    """ raised when attempting to query non-existent domain/key """
    pass

__all__ = [name for name, obj in locals().items() if isinstance(obj, type)]