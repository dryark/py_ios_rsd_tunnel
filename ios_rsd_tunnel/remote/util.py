from .remotexpc import RemoteXPCConnection

import csv
import os
import fcntl

class FileKeyValueStore:
    def __init__(self, file_path):
        self.file_path = file_path
        self.data = {}  # Data dictionary to hold all key-value pairs for each type
        #self.last_mtime = None
        self.watch_thread = None
        self._read_file()  # Read existing data from the file on initialization
        self.watch_for_changes()

    def read_file(self):
        #mtime = os.path.getmtime(self.file_path)
        #if mtime == self.last_mtime:
        #    return  # File hasn't been modified since last read
        with open(self.file_path, 'r') as file:
            fcntl.flock(file, fcntl.LOCK_SH)
            reader = csv.reader(file)
            for row in reader:
                type = row[0]
                key = row[1]
                value = row[2]
                if type not in self.data:
                    self.data[type] = {}
                self.data[type][key] = value
            fcntl.flock(file, fcntl.LOCK_UN)

    def write_file(self):
        with open(self.file_path, 'w') as file:
            fcntl.flock(file, fcntl.LOCK_EX)
            writer = csv.writer(file)
            for type, key_values in self.data.items():
                for key, value in key_values.items():
                    writer.writerow([type, key, value])
            fcntl.flock(file, fcntl.LOCK_UN)

    def get_values_for_type(self, type):
        return self.data.get(type, {})

    def write_values_for_type(self, type, values):
        self.data[type] = values
        self.write_file()
        
    def watch_for_changes(self):
        def handle_event(event):
            if event.name == self.file_path and event.mask & inotify.constants.IN_MODIFY:
                self.read_file()

        self.watch_thread = inotify.adapters.Inotify()
        self.watch_thread.add_watch(self.file_path, mask=inotify.constants.IN_MODIFY)
        self.watch_thread.loop(callback=handle_event)    
    
    def __getitem__(self, type):
        #self.read_file()
        if type not in self.data:
            self.data[type] = {}
        return KeyValueProxy(self.data[type], self, type)
    
    def __setitem__(self, type, values):
        #self.read_file()
        self.data[type] = values
        self.write_file()
    
    def __del__(self):
        if self.watch_thread:
            self.watch_thread.remove_watch(self.file_path)

class KeyValueProxy:
    def __init__(self, data, store, type):
        self.data = data
        self.store = store
        self.type = type

    def __getitem__(self, key):
        return self.data.get(key, None)

    def __setitem__(self, key, value):
        self.data[key] = value
        self.store.write_values_for_type(self.type, self.data)

    def __delitem__(self, key):
        del self.data[key]
        self.store.write_values_for_type(self.type, self.data)

def rsd_addr_to_udid( rsdAddr: str ):
    rsd = RemoteXPCConnection( rsdAddr )
    rsd.connect()
    info = rsd.receive_response()
    udid = info['Properties']['UniqueDeviceID']
    rsd.close()
    return udid

def udid_to_rsd_addr( udid: str ):
    kv = FileKeyValueStore( 'data.csv' )
    
    stop_remoted()
    if udid in kv['udid2rsd']:
        potential_rsd = kv['udid2rsd'][udid]
        
        check_udid = rsd_addr_to_udid( potential_rsd )
        if udid == check_udid:
            resume_remoted()
            return potential_rsd
        # didn't match, erase the entry
        del kv['udid2rsd'][udid]
        
    # We didn't already have it mapped
    # First fetch all potential en# that could work
    ens = get_potential_remoted_ifaces()
    
    # Then check the ones not in the en_to_ipv6 mapping
    for en in ens:
        if en not in en_to_rsd:
            info = get_service_info( en ) # services and ipv6(rsd)
            
            if 'remotepairing' not in info['services']:
                kv['en2rsd'][en] = 'not17'
                continue
            # It's new and ios17+; maybe this is the one?
            kv['en2rsd'][en] = ipv6
            # figure out the udid using the rsd
            check_udid = rsd_addr_to_udid( f'{ipv6}%{en}' )
            kv['udid2rsd'][ check_udid ] = f'{ipv6}%{en}'
            if udid == check_udid:
                resume_remoted()
                return f'{ipv6}%{en}'
    
    # We still didn't find it. Look through all the remaining en's
    interfaces = get_remoted_interfaces( ios17only = True, exclude_ens = ens )
    
    old_ens = { info['interface']: info['ipv6'] for info in interfaces }
    for en,ipv6 in old_ens.items():
        if kv['en2rsd'][en] != ipv6:
            kv['en2rsd'][ en ] = ipv6
        check_udid = rsd_addr_to_udid( f'{ipv6}%{en}' )
        if kv['udid2rsd'][ check_udid ] != f'{ipv6}%{en}':
            kv['udid2rsd'][ check_udid ] = f'{ipv6}%{en}'
        if udid == check_udid:
            resume_remoted()
            return f'{ipv6}%{en}'
            
    # We didn't find it. Crud.
    resume_remoted()
    return 'missing'