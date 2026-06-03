from cryptography.x509.oid import NameOID

#Mantains entries {municipality name: certificate}
class PublicDirectory:
    def __init__(self):
        self.root_ca_cert = None
        self.municipality_certs = {} # Nome Comune -> Certificato

    def add_municipality(self, cert):
        name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        self.municipality_certs[name] = cert

    def get_municipality(self, issuer_name):
        return self.municipality_certs[issuer_name]

