# Copyright (c) 2024 Dry Ark LLC
from asn1crypto import (
    x509,
)
from certbuilder import (
    CertificateBuilder,
    pem_armor_certificate,
)
from datetime import (
    datetime,
    timedelta,
)
from oscrypto.asymmetric import (
    PrivateKey,
    generate_pair,
    dump_private_key,
    load_public_key,
)
from typing import (
    Optional,
)

import zoneinfo
def make_cert(
    private_key,
    public_key,
    common_name=None
) -> x509.Certificate:
    source = {
        'common_name': 'Device',
    }
    
    now = datetime.now( zoneinfo.ZoneInfo('UTC') )
    begin = (now - timedelta(minutes=1))
    end = (now + timedelta(days=365 * 10))
    
    builder = CertificateBuilder(
        source,
        public_key,
    )
    builder.serial_number = 1
    builder.begin_date = begin
    builder.end_date = end
    #builder.issuer = source
    builder.hash_algo = 'sha256'
    
    builder.self_signed = True
    cert = builder.build( private_key )
    return cert

def ca_do_everything(
    device_public_key_pem: str,
    private_key: Optional[PrivateKey] = None
):
    if private_key is None:
        public_key, private_key = generate_pair('rsa', bit_size=2048)
    else:
        public_key = private_key.public_key()
    
    cert = make_cert(
        private_key,
        public_key,
    )
    
    device_public_key = load_public_key( device_public_key_pem )
    device_cert = make_cert(
        private_key,
        device_public_key,
        'Device',
    )
    #private_key_der = private_key.dump()
    #private_key_pem = pem.armor('CERTIFICATE', private_key_der)
    return [
        pem_armor_certificate( cert ),
        dump_private_key( private_key, None ),#, 'pkcs8' ),
        pem_armor_certificate( device_cert ),
    ]