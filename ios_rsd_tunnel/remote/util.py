# Copyright (c) 2024 Dry Ark LLC <license@dryark.com>
# License AGPL 3.0
from .remotexpc import RemoteXPCConnection
from cf_mdns import (
    get_remoted_interfaces,
    get_service_info,
)
from cf_iface import get_potential_remoted_ifaces
from .remoted_tool import (
    stop_remoted,
    resume_remoted,
)
from ..home_folder import get_home_folder
import fcntl
import csv

class CSVKV:
    def __init__(self, fd):
        self.fd = fd
        self.data = {}
        self.read()

    def read(self):
        reader = csv.reader( self.fd )
        for row in reader:
            etype = row[0]
            key = row[1]
            val = row[2]
            #print(f'row {row}')
            if etype not in self.data:
                self.data[etype] = { key: val }
            else:
                self.data[etype][key] = val

    def write(self):
        self.fd.truncate(0)
        writer = csv.writer(self.fd)
        for type, key_values in self.data.items():
            for key, value in key_values.items():
                writer.writerow([type, key, value])

    def getval( self, etype, key ):
        if not etype in self.data:
            return None
        return self.data[ etype ].get( key )

    def setval(self, etype, key, val ):
        if not etype in self.data:
            self.data[ etype ] = { key: val }
            return
        self.data[ etype ][ key ] = val
    
    def delval( self, etype, key ):
        if not etype in self.data:
            return
        del self.data[ etype ][ key ]
    
    def gettype(self, etype):
        if not etype in self.data:
            newdict = {}
            self.data[ etype ] = newdict
            return newdict
        return self.data[ etype ]

def rsd_addr_to_udid( rsdAddr: str ):
    rsd = RemoteXPCConnection( ( rsdAddr, 58783 ) )
    rsd.connect()
    info = rsd.receive_response()
    udid = info['Properties']['UniqueDeviceID']
    rsd.close()
    return udid

def udid_to_rsd_addr(
    udid: str,
    skipResume: bool=False,
) -> str:
    home_path = get_home_folder()
    file_path = home_path / 'mapping.csv'
    with open( file_path, 'a+' ) as fd:
        fcntl.flock(fd, fcntl.LOCK_SH)
        fd.seek(0)
        kv = CSVKV( fd )
        fd.seek(0)
        
        stop_remoted()
        #print( f'udid2rsd {kv.gettype("udid2rsd")}' )
        if udid in kv.gettype('udid2rsd'):
            potential_rsd = kv.getval( 'udid2rsd', udid )
            #print( f'step 1 potential_rsd {potential_rsd}' )
            check_udid = rsd_addr_to_udid( potential_rsd )
            if udid == check_udid:
                if not skipResume:
                    resume_remoted()
                kv.write()
                #print( f'found step1 match' )
                return potential_rsd
            # didn't match, erase the entry
            kv.delval( 'udid2rsd', udid )
            
        # We didn't already have it mapped
        # First fetch all potential en# that could work
        ens = get_potential_remoted_ifaces()
        
        # Then check the ones not in the en_to_ipv6 mapping
        for en in ens:
            if en not in kv.gettype('en2rsd'):
                info = get_service_info( en ) # services and ipv6(rsd)
                
                if 'remotepairing' not in info['services']:
                    kv.setval( 'en2rsd', en, 'not17' )
                    continue
                # It's new and ios17+; maybe this is the one?
                ipv6 = info['ipv6']
                kv.setval( 'en2rsd', en, ipv6 )
                # figure out the udid using the rsd
                ipv6en = f'{ipv6}%{en}'
                #print( f'ipv6en = {ipv6en}' )
                check_udid = rsd_addr_to_udid( ipv6en )
                kv.setval( 'udid2rsd', check_udid, ipv6en )
                if udid == check_udid:
                    if not skipResume:
                        resume_remoted()
                    kv.write()
                    #print( f'found step2 match' )
                    return ipv6en
        
        # We still didn't find it. Look through all the remaining en's
        interfaces = get_remoted_interfaces( ios17only = True, exclude_ens = ens )
        
        old_ens = { info['interface']: info['ipv6'] for info in interfaces }
        for en,ipv6 in old_ens.items():
            if kv.getval( 'en2rsd', en ) != ipv6:
                kv.setval( 'en2rsd', en, ipv6 )
            ipv6en = f'{ipv6}%{en}'
            check_udid = rsd_addr_to_udid( ipv6en )
            if kv.getval( 'udid2rsd', check_udid ) != ipv6en:
                kv.setval( 'udid2rsd', check_udid, ipv6en )
            if udid == check_udid:
                if not skipResume:
                    resume_remoted()
                kv.write()
                #print( f'found step3 match' )
                return ipv6en
                
        # We didn't find it. Crud.
        if not skipResume:
            resume_remoted()
        kv.write()
        return 'missing'