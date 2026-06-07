"""
Simulazione del protocollo di voto elettronico.

Fasi:
  0. PKI Setup (StateCA, MunicipalityCA)
  1. Creazione Autorità (EA, CA)
  2. Pubblicazione certificati nel PublicDirectory
  3. Elettore verifica i certificati delle autorità
  4. Security test — Autorità con CA fasulla
  5. Autenticazione elettore (MunicipalityCA → certificato)
  6. Protocollo di invio scheda di voto (referendum SI/NO)
     + Security tests: double voting, firma manomessa, CA non registrata
"""

import base64 as _b64

from cryptography.hazmat._oid import NameOID

from archive.PublicDirectory import PublicDirectory
from entities.Voter import Voter
from entities.ElectoralAuthority import ElectoralAuthority, InvalidBallotRequest, InvalidBallotSubmission
from entities.CountingAuthority import CountingAuthority
from pki.StateCA import StateCA
from pki.MunicipalityCA import MunicipalityCA

# ============================================================
# PHASE 0: PKI Setup
# ============================================================
print("=" * 60)
print("PHASE 0: PKI Setup")
print("=" * 60)

state_ca = StateCA("Italy")
print(f"✅ StateCA '{state_ca.common_name}' created (self-signed certificate)")

municipality = MunicipalityCA("Vietri Sul Mare", state_ca)
print(f"✅ MunicipalityCA '{municipality.common_name}' created (certificate signed by StateCA)")

# ============================================================
# PHASE 1: Creation of Authorities (EA and CA)
# ============================================================
print("\n" + "=" * 60)
print("PHASE 1: Creation of Electoral Authority (EA) and Counting Authority (CA)")
print("=" * 60)

ea = ElectoralAuthority("National Electoral Authority", state_ca)
print(f"✅ EA '{ea.common_name}' created (certificate signed by StateCA, ca=False)")

ca = CountingAuthority("National Counting Authority", state_ca)
print(f"✅ CA '{ca.common_name}' created (certificate signed by StateCA, ca=False)")

# ============================================================
# PHASE 2: Publication in the Public Directory
# ============================================================
print("\n" + "=" * 60)
print("PHASE 2: Certificate publication in the Public Directory")
print("=" * 60)

pd = PublicDirectory()

pd.set_root_ca(state_ca.certificate)
print(f"✅ Root CA '{state_ca.common_name}' set as trust anchor")

pd.add_municipality(municipality.certificate)
print(f"✅ Certificate of '{municipality.common_name}' published in the registry")

pd.add_authority(ea.certificate)
print(f"✅ EA Certificate '{ea.common_name}' published in the registry")

pd.add_authority(ca.certificate)
print(f"✅ CA Certificate '{ca.common_name}' published in the registry")

# ============================================================
# PHASE 3: The voter verifies the authorities' certificates
# ============================================================
print("\n" + "=" * 60)
print("PHASE 3: The voter verifies EA and CA certificates")
print("=" * 60)

voter = Voter("Peppe")
print(f"👤 Voter '{voter.name}' created")

ea_valid = voter.verify_authority_certificate("National Electoral Authority", pd)
if ea_valid:
    print(f"✅ Voter '{voter.name}': EA certificate verified successfully (valid StateCA signature)")
else:
    print(f"❌ Voter '{voter.name}': EA certificate INVALID!")

ca_valid = voter.verify_authority_certificate("National Counting Authority", pd)
if ca_valid:
    print(f"✅ Voter '{voter.name}': CA certificate verified successfully (valid StateCA signature)")
else:
    print(f"❌ Voter '{voter.name}': CA certificate INVALID!")

# ============================================================
# PHASE 4: Security test (Fake Authority)
# ============================================================
print("\n" + "=" * 60)
print("PHASE 4: Security Test — Authority with Fake CA")
print("=" * 60)

fake_state = StateCA("Fake State")
fake_ea = ElectoralAuthority("Fake EA", fake_state)
print(f"⚠️  Fake EA created: '{fake_ea.common_name}' (signed by '{fake_state.common_name}')")

pd.add_authority(fake_ea.certificate)
print(f"⚠️  Fake EA certificate published in the registry")

fake_ea_valid = voter.verify_authority_certificate("Fake EA", pd)
if fake_ea_valid:
    print(f"❌ SECURITY ERROR: Fake EA certificate was accepted!")
else:
    print(f"✅ Fake EA certificate REJECTED: signature does not match the legitimate StateCA")

# ============================================================
# PHASE 5: Voter Authentication
# ============================================================
print("\n" + "=" * 60)
print("PHASE 5: Voter authentication through the Municipality")
print("=" * 60)

csr = voter.generate_certificate_request()
certificate = municipality.sign_voter_csr(csr)
voter.set_certificate(certificate)
print(f"✅ Voter '{voter.name}' obtained certificate from '{municipality.common_name}'")

issuer_name = voter.certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
municipality_cert = pd.get_municipality(issuer_name)

if pd.verify_certificate_chain(voter.certificate, municipality_cert):
    print(f"✅ CHAIN VERIFIED CORRECTLY")
else:
    print(f"❌ CHAIN NOT RESPECTED CORRECTLY")

# ============================================================
# PHASE 6: Ballot Submission Protocol
# Referendum: "Sei favorevole alla proposta di legge X?" (SI / NO)
# ============================================================
print("\n" + "=" * 60)
print("PHASE 6: Ballot Submission — Referendum SI/NO")
print("=" * 60)

# L'elettore recupera pkAC dal PublicDirectory (certificati delle autorità sono pubblici)
ac_public_key = pd.get_authority_public_key("National Counting Authority")
ae_public_key  = ea.get_public_key()

# ----------------------------------------------------------
# Passo 1 — Richiesta scheda:  Enc(pkAE, ballot_request ‖ Cert_elettore)
# ----------------------------------------------------------
print("\n[Passo 1] Elettore → AE : Enc(pkAE, ballot_request ‖ Cert_elettore)")
encrypted_request = voter.request_ballot(ae_public_key)
print(f"  📨 Richiesta cifrata inviata ({len(encrypted_request)} byte)")

# ----------------------------------------------------------
# Passi 2-3 — AE verifica la catena → (schedavuota, σ_AE)
# ----------------------------------------------------------
print("\n[Passi 2-3] AE verifica catena → AE → Elettore : (schedavuota, σ_AE)")
try:
    blank_ballot_bytes, ae_signature = ea.receive_ballot_request(encrypted_request, pd)
    print(f"  ✅ Catena certificato elettore verificata (Voter → MunicipalityCA → StateCA)")
    print(f"  📋 Scheda vuota firmata da AE inviata all'elettore")
except InvalidBallotRequest as exc:
    print(f"  ❌ Richiesta rifiutata: {exc}")
    raise SystemExit(1)

# L'elettore verifica la firma AE sulla scheda vuota
blank_ballot = voter.receive_blank_ballot(blank_ballot_bytes, ae_signature, ae_public_key)
print(f"  ✅ Elettore ha verificato σ_AE sulla scheda vuota")
print(f"  📋 Quesito referendario: \"{blank_ballot.question}\"")

# ----------------------------------------------------------
# Passo 4 — Compilazione e invio scheda
#   schedacifrata        = Enc(pkAC, ballot)          [RSA-OAEP, dim. fissa]
#   schedacifratacifrata = Enc(pkAE, schedacifrata ‖ voter_id)   [cifratura ibrida]
#   σ                    = Sign(skEletore, schedacifratacifrata)
#
#   Messaggio: <IDelettore, schedacifratacifrata, σ>
# ----------------------------------------------------------
choice = "SI"
print(f"\n[Passo 4] Elettore → AE : <IDelettore, Enc(pkAE, Enc(pkAC, ballot) ‖ ID), σ_elettore>")
print(f"  Scelta: '{choice}'")
submission_payload = voter.submit_ballot(choice, ae_public_key, ac_public_key)
print(f"  📨 Payload di invio costruito")

# ----------------------------------------------------------
# Passi 5-7 — AE valida, registra e rilascia ricevuta
# ----------------------------------------------------------
print("\n[Passi 5-7] AE: verifica σ → controlla ID consumati → registra → ricevuta")
try:
    receipt = ea.receive_encrypted_ballot(submission_payload, voter.get_public_key(), ac_public_key)
    print(f"  ✅ Vrfy(pkEletore, encrypted_payload, σ) = 1")
    print(f"  ✅ ID elettore non presente nella lista 'consumati'")
    print(f"  ✅ Dimensione crittogramma AC corretta ({ca.get_public_key().key_size // 8} byte)")
    print(f"  ✅ ID aggiunto alla lista 'consumati'")
    print(f"  📌 Scheda pubblicata su bacheca B  ({len(ea.bulletin_board)} voce/voci)")
    print(f"  🧾 Ricevuta: Sign(skAE, Hash(Enc(pkAC, ballot)))  →  {len(receipt)} byte")
except InvalidBallotSubmission as exc:
    print(f"  ❌ Invio rifiutato: {exc}")
    raise SystemExit(1)

# L'elettore verifica la ricevuta
receipt_valid = voter.verify_receipt(receipt, ae_public_key)
print(f"\n  {'✅' if receipt_valid else '❌'} Verifica ricevuta: "
      f"{'valida — voto registrato correttamente' if receipt_valid else 'NON VALIDA!'}")

# ----------------------------------------------------------
# Security Test A — Double voting (U.1)
# ----------------------------------------------------------
print("\n" + "-" * 50)
print("Security Test A: Tentativo di voto doppio (U.1)")
print("-" * 50)
try:
    ea.receive_encrypted_ballot(submission_payload, voter.get_public_key(), ac_public_key)
    print("  ❌ ERRORE DI SICUREZZA: voto doppio accettato!")
except InvalidBallotSubmission as exc:
    print(f"  ✅ Voto doppio RIFIUTATO: {exc}")

# ----------------------------------------------------------
# Security Test B — Firma manomessa (I.1)
# ----------------------------------------------------------
print("\n" + "-" * 50)
print("Security Test B: Firma manomessa sull'invio (I.1)")
print("-" * 50)

# Secondo elettore (diverso voter_id → nessun blocco per double-voting)
voter2 = Voter("Mario")
csr2 = voter2.generate_certificate_request()
voter2.set_certificate(municipality.sign_voter_csr(csr2))

tampered_payload = voter2.submit_ballot("NO", ae_public_key, ac_public_key)
# Corrompe il primo byte della firma (base64-decodificata)
raw_sig = _b64.b64decode(tampered_payload["signature"])
corrupted_sig = bytes([raw_sig[0] ^ 0xFF]) + raw_sig[1:]
tampered_payload["signature"] = _b64.b64encode(corrupted_sig).decode()

try:
    ea.receive_encrypted_ballot(tampered_payload, voter2.get_public_key(), ac_public_key)
    print("  ❌ ERRORE DI SICUREZZA: firma manomessa accettata!")
except InvalidBallotSubmission as exc:
    print(f"  ✅ Firma manomessa RIFIUTATA: {exc}")

# ----------------------------------------------------------
# Security Test C — MunicipalityCA non registrata nel PublicDirectory
# ----------------------------------------------------------
print("\n" + "-" * 50)
print("Security Test C: Elettore con certificato di CA non registrata")
print("-" * 50)

unknown_municipality = MunicipalityCA("Comune Sconosciuto", state_ca)  # non pubblicata in pd
voter3 = Voter("Hacker")
csr3 = voter3.generate_certificate_request()
voter3.set_certificate(unknown_municipality.sign_voter_csr(csr3))

forged_request = voter3.request_ballot(ae_public_key)
try:
    ea.receive_ballot_request(forged_request, pd)
    print("  ❌ ERRORE DI SICUREZZA: catena non valida accettata!")
except InvalidBallotRequest as exc:
    print(f"  ✅ Richiesta RIFIUTATA: {exc}")

# ============================================================
# Summary
# ============================================================
print("\n" + "=" * 60)
print("SUMMARY: Protocollo completato con successo")
print("=" * 60)
print(f"  🏛️  StateCA:       '{state_ca.common_name}'")
print(f"  📋  EA:            '{ea.common_name}' — cert verificato: {ea_valid}")
print(f"  🔢  AC:            '{ca.common_name}' — cert verificato: {ca_valid}")
print(f"  🏘️  Municipality:  '{municipality.common_name}'")
print(f"  👤  Voter:         '{voter.name}' — voto registrato ✓")
print(f"  📌  Bacheca B:     {len(ea.bulletin_board)} scheda/e pubblicata/e")
print(f"  🔒  ID consumati:  {len(ea._consumed_ids)}")
print(f"\n  ✅  Fase 6 completata — pronto per il conteggio (CountingAuthority)")