from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from pki.StateCA import StateCA


class CountingAuthority:
    """Counting Authority (CA).
    Responsible for counting votes while ensuring pseudo-anonymity.
    Possesses an end-entity certificate signed directly by the StateCA."""

    def __init__(self, common_name: str, state_ca: StateCA):
        self.common_name = common_name

        # Generate RSA 4096 bit key pair
        self._private_key: RSAPrivateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )

        # Create CSR and send it to the StateCA for signing
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.common_name),
        ])).sign(self._private_key, hashes.SHA256())

        # Obtain the certificate signed by the StateCA (end-entity, ca=False)
        self.certificate: x509.Certificate = state_ca.sign_authority_csr(csr)

    def get_public_key(self) -> RSAPublicKey:
        """Returns the public key of the Counting Authority"""
        return self._private_key.public_key()
