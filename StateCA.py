from datetime import datetime

from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives import hashes
from Authority import Authority


class StateCA(Authority):
    def __init__(self, common_name: str = "CA Stato"):
        super().__init__(common_name)

        '''Root certificate , signed by itself'''
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.common_name),
        ])

        self.certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.get_public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=3650)  # Dura 10 anni
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).sign(self._private_key, hashes.SHA256())


    #Method used from a state to certificate a municipality
    def sign_municipality_csr(self, csr: x509.CertificateSigningRequest)-> x509.Certificate:
        cert = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            self.certificate.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=1825)  # 5 anni
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True
        ).sign(self._private_key, hashes.SHA256())

        return cert