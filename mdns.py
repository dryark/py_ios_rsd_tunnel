# If you'd like to build your own one of these, go ahead.
# The idea is to use mdns/dns-sd to query potential ipv6
#   interfaces and return the ones that are actually iPhones.

def get_remoted_interfaces( ios17only: bool ):
    return [{
        'interface': 'en3',
        'ipv6': '[ipv6 address of interface]',
        'hasRemotePairing': True,
    }]
