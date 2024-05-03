# Copyright (c) 2024 Dry Ark LLC
# License AGPL

import argparse
import logging

from .cli.remote import (
    cli_list,
    remote_tunnel,
)
from .cli.lockdown import (
    lockdown_tunnel,
)
from .exceptions import *

logging.getLogger('quic').disabled = True
logging.getLogger('asyncio').disabled = True
logger = logging.getLogger(__name__)

def main() -> None:
    parser = argparse.ArgumentParser(description='iOS RSD Tunnel Tool')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode')
    subparsers = parser.add_subparsers(title='Commands', dest='command')
    
    subparsers.add_parser('remote-list', help='List Remote ( ipv6 ) Connectable Devices')
    
    remote_tunnel_cmd = subparsers.add_parser('remote-tunnel', help='Start RSD Tunnel via ipv6 remote')
    group = remote_tunnel_cmd.add_mutually_exclusive_group( required=True )
    group.add_argument('-i', '--ipv6', help='ipv6 of device')
    group.add_argument('-u', '--udid', help='udid of device')
    
    tunnel_cmd = subparsers.add_parser('tunnel', help='Start RSD Tunnel via lockdown')
    tunnel_cmd.add_argument('-u', '--udid', help='udid of device')
    
    args = parser.parse_args()
    
    cmd = args.command
    try:
        logging.basicConfig( level = ( logging.DEBUG if args.verbose else logging.INFO ) )
        
        if cmd == 'remote-list':
            cli_list()
        elif cmd == 'remote-tunnel':
            if args.ipv6:
                remote_tunnel( ipv6 = args.ipv6 )
            if args.udid:
                remote_tunnel( udid = args.udid )
        elif cmd == 'tunnel':
            lockdown_tunnel( udid = args.udid )
        else:
            parser.print_help()
    
    except NoDeviceConnectedError:            logger.error('Device is not connected')
    #except ConnectionAbortedError:            logger.error('Device was disconnected')
    except NotPairedError:                    logger.error('Device is not paired')
    except UserDeniedPairingError:            logger.error('User refused trust prompt')
    except PairingDialogResponsePendingError: logger.error('Waiting for user trust approval')
    except SetProhibitedError:                logger.error('lockdownd denied the access')
    except MissingValueError:                 logger.error('No such value')
    except ConnectionFailedToUsbmuxdError:    logger.error('Failed to connect to /var/run/usbmuxd')
    except InternalError:                     logger.error('Internal Error')
    except InvalidServiceError:               logger.error('Failed to start service')
    except PasswordRequiredError:             logger.error('Device is password protected. Please unlock')
    except AccessDeniedError:                 logger.error('This command requires root privileges.')
    except BrokenPipeError:
        logger.error('Broken pipe')
        #traceback.print_exc()
    except DeviceNotFoundError as e:
        logger.error(f'Device not found: {e.udid}')

if __name__ == '__main__':
    main()
