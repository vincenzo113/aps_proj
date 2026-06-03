from cryptography.hazmat._oid import NameOID

from entities.Voter import Voter
from pki.StateCA import StateCA
from pki.MunicipalityCA import MunicipalityCA

state_ca = StateCA("Italia")
comune = MunicipalityCA("Salerno", state_ca)
voter = Voter("Davide Quaranta")

csr_voter = voter.generate_certificate_request()

certificato_rilasciato = comune.sign_voter_csr(csr_voter)

voter.set_certificate(certificato_rilasciato)


print(f"Certificato emesso per: {voter.name}")
print(f"Firmato da: {voter.certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")