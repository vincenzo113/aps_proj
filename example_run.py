from cryptography.hazmat._oid import NameOID

from archive.PublicDirectory import PublicDirectory
from entities.Voter import Voter
from pki.StateCA import StateCA
from pki.MunicipalityCA import MunicipalityCA

state_true = StateCA("Italy")
comune_true = MunicipalityCA("Vietri Sul Mare" , state_true)
voter = Voter("Peppe")
state_fake = StateCA("Fake")
comune_fake = MunicipalityCA("Fake" , state_fake)
pd = PublicDirectory()
pd.add_municipality(comune_fake.certificate)
pd.add_municipality(comune_true.certificate)

csr = voter.generate_certificate_request()
certificate = comune_fake.sign_voter_csr(csr)
voter.set_certificate(certificate)

voter.set_certificate(certificate)

# 2. Inizia la fase di verifica (Simuliamo l'autorità di conteggio)
# Recuperiamo il nome del comune che ha firmato il certificato di Peppe
issuer_name = voter.certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

# 3. Cerchiamo il certificato di quel comune nel Public Directory
comune_che_ha_firmato = pd.get_municipality(issuer_name)

if comune_che_ha_firmato is not None:
    # 4. CONTROLLO CRUCIALE: Chi ha firmato il certificato di questo comune?
    # Vogliamo che l'issuer del comune sia lo Stato "Italy"
    issuer_dello_stato = comune_che_ha_firmato.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

    if issuer_dello_stato == state_true.common_name:
        print(
            f"✅ VOTO ACCETTATO: {voter.name} ha un certificato valido emesso da {issuer_name}, autorizzato da {issuer_dello_stato}.")
    else:
        print(
            f"❌ VOTO RESPINTO: Il comune {issuer_name} non è autorizzato dallo Stato legittimo (Emettitore: {issuer_dello_stato}).")
else:
    print(f"❌ VOTO RESPINTO: Il comune {issuer_name} non esiste nel registro pubblico.")