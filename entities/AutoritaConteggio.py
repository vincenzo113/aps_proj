from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from pki.StateCA import StateCA


class AutoritaConteggio:
    """Autorità di Conteggio (AC).
    Responsabile del conteggio dei voti garantendo pseudoanonimato.
    Possiede un certificato end-entity firmato direttamente dalla StateCA."""

    def __init__(self, common_name: str, state_ca: StateCA):
        self.common_name = common_name

        # Genera coppia di chiavi RSA 4096 bit
        self._private_key: RSAPrivateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )

        # Crea CSR e lo invia alla StateCA per la firma
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.common_name),
        ])).sign(self._private_key, hashes.SHA256())

        # Ottiene il certificato firmato dalla StateCA (end-entity, ca=False)
        self.certificate: x509.Certificate = state_ca.sign_authority_csr(csr)

    def get_public_key(self) -> RSAPublicKey:
        """Restituisce la chiave pubblica dell'AC"""
        return self._private_key.public_key()
