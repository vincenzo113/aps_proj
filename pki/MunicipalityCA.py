from datetime import datetime, timedelta # Aggiunto timedelta
from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives import hashes

from .Authority import Authority
from .StateCA import StateCA


class MunicipalityCA(Authority):
    def __init__(self, common_name: str, state_ca: StateCA):
        super().__init__(common_name)

        # 1. Crea la richiesta (CSR) per lo Stato
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.common_name),
        ])).sign(self._private_key, hashes.SHA256())

        # 2. Ottiene il certificato firmato dallo Stato
        self.certificate = state_ca.sign_municipality_csr(csr)

    def sign_voter_csr(self, csr: x509.CertificateSigningRequest):
        """Metodo usato dal Comune per autorizzare un Elettore"""
        cert = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            self.certificate.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow() # Rimosso .datetime
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=1) # Rimosso .datetime e .timedelta
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        ).sign(self._private_key, hashes.SHA256())

        return cert