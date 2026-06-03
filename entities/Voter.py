from typing import Optional
from cryptography import x509
from cryptography.x509.oid import NameOID  # Nota: NameOID è solitamente qui
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.x509 import CertificateSigningRequest


class Voter:
    def __init__(self, name: str, key_bits: int = 2048):
        self.name = name

        self.certificate: Optional[x509.Certificate] = None

        self.private_key: RSAPrivateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_bits
        )
        self.public_key: RSAPublicKey = self.private_key.public_key()

    def get_public_key(self) -> RSAPublicKey:
        return self.public_key

    def generate_certificate_request(self) -> CertificateSigningRequest:
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.name),
        ])).sign(self.private_key, hashes.SHA256())
        return csr

    def set_certificate(self, cert: x509.Certificate):
        """Salva il certificato x509 generato dalla CA"""
        self.certificate=cert