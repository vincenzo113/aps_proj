from cryptography.hazmat._oid import NameOID

from archive.PublicDirectory import PublicDirectory
from entities.Voter import Voter
from entities.AutoritaElettorale import AutoritaElettorale
from entities.AutoritaConteggio import AutoritaConteggio
from pki.StateCA import StateCA
from pki.MunicipalityCA import MunicipalityCA

# ============================================================
# FASE 0: Setup della PKI
# ============================================================
print("=" * 60)
print("FASE 0: Setup della PKI")
print("=" * 60)

# Creazione della CA radice (Stato)
state_ca = StateCA("Italy")
print(f"✅ StateCA '{state_ca.common_name}' creata (certificato auto-firmato)")

# Creazione della CA comunale
comune = MunicipalityCA("Vietri Sul Mare", state_ca)
print(f"✅ MunicipalityCA '{comune.common_name}' creata (certificato firmato da StateCA)")

# ============================================================
# FASE 1: Creazione delle Autorità (AE e AC)
# ============================================================
print("\n" + "=" * 60)
print("FASE 1: Creazione Autorità Elettorale (AE) e Autorità di Conteggio (AC)")
print("=" * 60)

# Creazione AE - Autorità Elettorale
ae = AutoritaElettorale("Autorita Elettorale Nazionale", state_ca)
print(f"✅ AE '{ae.common_name}' creata (certificato firmato da StateCA, ca=False)")

# Creazione AC - Autorità di Conteggio
ac = AutoritaConteggio("Autorita di Conteggio Nazionale", state_ca)
print(f"✅ AC '{ac.common_name}' creata (certificato firmato da StateCA, ca=False)")

# ============================================================
# FASE 2: Pubblicazione nel Public Directory
# ============================================================
print("\n" + "=" * 60)
print("FASE 2: Pubblicazione certificati nel Public Directory")
print("=" * 60)

pd = PublicDirectory()

# Imposta il trust anchor (certificato root della StateCA)
pd.set_root_ca(state_ca.certificate)
print(f"✅ Root CA '{state_ca.common_name}' impostata come trust anchor")

# Pubblica il certificato del Comune
pd.add_municipality(comune.certificate)
print(f"✅ Certificato di '{comune.common_name}' pubblicato nel registro")

# Pubblica i certificati delle autorità
pd.add_authority(ae.certificate)
print(f"✅ Certificato di AE '{ae.common_name}' pubblicato nel registro")

pd.add_authority(ac.certificate)
print(f"✅ Certificato di AC '{ac.common_name}' pubblicato nel registro")

# ============================================================
# FASE 3: L'elettore verifica i certificati delle autorità
# ============================================================
print("\n" + "=" * 60)
print("FASE 3: L'elettore verifica i certificati di AE e AC")
print("=" * 60)

voter = Voter("Peppe")
print(f"👤 Elettore '{voter.name}' creato")

# L'elettore verifica il certificato dell'AE
ae_valid = voter.verify_authority_certificate("Autorita Elettorale Nazionale", pd)
if ae_valid:
    print(f"✅ Elettore '{voter.name}': certificato AE verificato con successo (firma StateCA valida)")
else:
    print(f"❌ Elettore '{voter.name}': certificato AE NON valido!")

# L'elettore verifica il certificato dell'AC
ac_valid = voter.verify_authority_certificate("Autorita di Conteggio Nazionale", pd)
if ac_valid:
    print(f"✅ Elettore '{voter.name}': certificato AC verificato con successo (firma StateCA valida)")
else:
    print(f"❌ Elettore '{voter.name}': certificato AC NON valido!")

# ============================================================
# FASE 4: Test con autorità falsa (CA non legittima)
# ============================================================
print("\n" + "=" * 60)
print("FASE 4: Test di sicurezza — Autorità con CA falsa")
print("=" * 60)

# Creiamo una StateCA falsa e un'autorità firmata da essa
state_fake = StateCA("Stato Falso")
ae_fake = AutoritaElettorale("AE Falsa", state_fake)
print(f"⚠️  AE falsa creata: '{ae_fake.common_name}' (firmata da '{state_fake.common_name}')")

# Proviamo a inserirla nel Public Directory e verificarla
pd.add_authority(ae_fake.certificate)
print(f"⚠️  Certificato AE falsa pubblicato nel registro")

# L'elettore prova a verificarla — deve fallire!
ae_fake_valid = voter.verify_authority_certificate("AE Falsa", pd)
if ae_fake_valid:
    print(f"❌ ERRORE DI SICUREZZA: il certificato dell'AE falsa è stato accettato!")
else:
    print(f"✅ Certificato AE falsa RIFIUTATO: la firma non corrisponde alla StateCA legittima")

# ============================================================
# FASE 5: Autenticazione elettore (flusso esistente)
# ============================================================
print("\n" + "=" * 60)
print("FASE 5: Autenticazione dell'elettore tramite il Comune")
print("=" * 60)

# L'elettore genera CSR e ottiene certificato dal Comune
csr = voter.generate_certificate_request()
certificate = comune.sign_voter_csr(csr)
voter.set_certificate(certificate)
print(f"✅ Elettore '{voter.name}' ha ottenuto certificato da '{comune.common_name}'")

# Verifica della catena: chi ha firmato il certificato dell'elettore?
issuer_name = voter.certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
comune_cert = pd.get_municipality(issuer_name)

#verify the chain is correct starting from the voter cert and going up till the ROOT CA
if pd.verify_certificate_chain(voter.certificate , comune_cert):
    print(f"✅ CATENA RISALITA CORRETTAMENTE")
else:
    print(f"❌ CATENA NON RISPETTATA CORRETTAMENTE")

# ============================================================
# Riepilogo
# ============================================================
print("\n" + "=" * 60)
print("RIEPILOGO: Stato pronto per lo scambio delle schede")
print("=" * 60)
print(f"  🏛️  StateCA:    '{state_ca.common_name}'")
print(f"  📋  AE:         '{ae.common_name}' — certificato verificato: {ae_valid}")
print(f"  🔢  AC:         '{ac.common_name}' — certificato verificato: {ac_valid}")
print(f"  🏘️  Comune:     '{comune.common_name}'")
print(f"  👤  Elettore:   '{voter.name}' — autenticato e pronto")
print(f"\n  ➡️  L'elettore conosce le chiavi pubbliche di AE e AC.")
print(f"  ➡️  Si può procedere con lo scambio delle schede.")