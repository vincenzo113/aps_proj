from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives import hashes


class PublicDirectory:
    """Registro pubblico dei certificati.
    Mantiene i certificati dei Comuni e delle Autorità (AE, AC),
    tutti firmati dalla StateCA e liberamente accessibili/verificabili."""

    def __init__(self):
        self.root_ca_cert = None  # Certificato root della StateCA
        self.municipality_certs = {}  # Nome Comune -> Certificato
        self.authority_certs = {}  # Nome Autorità -> Certificato

    # --- Root CA ---

    def set_root_ca(self, cert: x509.Certificate):
        """Imposta il certificato root della StateCA (trust anchor per le verifiche)"""
        self.root_ca_cert = cert

    # --- Comuni ---

    def add_municipality(self, cert: x509.Certificate):
        """Pubblica il certificato di un Comune"""
        name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        self.municipality_certs[name] = cert

    def get_municipality(self, issuer_name: str):
        """Recupera il certificato di un Comune per nome"""
        return self.municipality_certs.get(issuer_name)

    # --- Autorità (AE, AC) ---

    def add_authority(self, cert: x509.Certificate):
        """Pubblica il certificato di un'autorità (AE o AC)"""
        name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        self.authority_certs[name] = cert

    def get_authority(self, name: str):
        """Recupera il certificato di un'autorità per nome"""
        return self.authority_certs.get(name)

    # --- Verifica crittografica ---

    def verify_certificate(self, cert: x509.Certificate) -> bool:
        """Verifica crittografica che il certificato sia firmato dalla root CA (StateCA).
        Controlla che la firma digitale sul certificato sia autentica,
        usando la chiave pubblica della StateCA."""
        if self.root_ca_cert is None:
            raise ValueError("Root CA certificate non impostato nel PublicDirectory")

        try:
            # Verifica che la firma sul certificato sia della StateCA
            root_public_key = self.root_ca_cert.public_key()
            root_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                PKCS1v15(),
                cert.signature_hash_algorithm
            )
            return True
        except Exception:
            return False

    def verify_certificate_chain(self, voter_cert, comune_cert) -> bool:
        """Verifica l'intera catena di certificati (elettore → ComuneCA → StateCA)"""

        # Step 1: be sure the municipality certificate is signed by the StateCA
        if not self.verify_certificate(comune_cert):
            return False

        # Step 2: be sure the voter certificate is signed by the ComuneCA
        try:
            comune_public_key = comune_cert.public_key()
            comune_public_key.verify(
                voter_cert.signature,
                voter_cert.tbs_certificate_bytes,
                PKCS1v15(),
                voter_cert.signature_hash_algorithm
            )
            return True
        except Exception:
            return False