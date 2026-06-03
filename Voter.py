from typing import Optional

from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.x509 import CertificateSigningRequestBuilder, CertificateSigningRequest

import Certificate


class Voter:
        def __init__(self ,name ,key_bits = 2048):
            self.name = name
            self.certificate : Optional[Certificate] = None #initially voter is not certified
            #Object PrivateKey
            self.private_key: RSAPrivateKey = rsa.generate_private_key(public_exponent=65537,key_size=key_bits)
            #Object PublicKey
            self.public_key: RSAPublicKey = self.private_key.public_key()

        def get_public_key(self) -> RSAPublicKey:
            return self.public_key

        #Method to generate a request of certificate:
        #This is used when voter asks for a certificate to his/her certificate authority
        #This request is signed by the voter using his private key
        def generate_certificate_request(self):
            csr:CertificateSigningRequest=x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, self.name),
            ])).sign(self.private_key, hashes.SHA256())
            return csr

        def set_certificate(self, cert: x509.Certificate):
            """To save certificate given from CA """
            self.certificate = cert


