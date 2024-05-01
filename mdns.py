# If you'd like to build your own one of these, go ahead.
# The idea is to use mdns/dns-sd to query potential ipv6
#   interfaces and return the ones that are actually iPhones.

def get_remoted_interfaces( ios17only: bool ):
    # Scan interfaces to see which have an ipv6 range and no ipv4 range
    # Those are likely iPhones
    
    # For each of those interfaces,
    #   send a mdns _services._dns-sd._udp.local. query
    #   send it just to the specific interface
    
    # It's easy to do all this with Python dnslib.
    
    # Some will have _remotepairing. Return true if so for that.
    # That means it is iOS 17+
    
    # Various iPhones before iOS 17 will have _remoted also, but no _remotepairing
    
    return [{
        'interface': 'en3',
        'ipv6': '[ipv6 address of interface]',
        'hasRemotePairing': True,
    }]
