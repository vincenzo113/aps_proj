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
# FASE 0: PKI Setup
# ============================================================
print("=" * 60)
print("FASE 0: PKI Setup")
print("=" * 60)

state_ca = StateCA("Italy")
print(f"StateCA '{state_ca.common_name}' creato (certificato autofirmato)")

municipality = MunicipalityCA("Vietri Sul Mare", state_ca)
print(f"MunicipalityCA '{municipality.common_name}' creato (certificato firmato da StateCA)")

# ============================================================
# FASE 1: Creazione delle autorità (EA e CA)
# ============================================================
print("\n" + "=" * 60)
print("FASE 1: Creazione dell'Autorità Elettorale (AE) e dell'Autorità di Scrutinio (AC)")
print("=" * 60)

ea = ElectoralAuthority("National Electoral Authority", state_ca)
print(f"EA '{ea.common_name}' creato (certificato firmato da StateCA, ca=False)")

ca = CountingAuthority("National Counting Authority", state_ca)
print(f"CA '{ca.common_name}' creato (certificato firmato da StateCA, ca=False)")

# ============================================================
# FASE 2: Pubblicazione del certificato nell'annuario pubblico
# ============================================================
print("\n" + "=" * 60)
print("FASE 2: Pubblicazione del certificato nell'annuario pubblico")
print("=" * 60)

pd = PublicDirectory()

pd.set_root_ca(state_ca.certificate)
print(f"Root CA '{state_ca.common_name}' settata")

pd.add_municipality(municipality.certificate)
print(f"il certificato di '{municipality.common_name}' pubblicato nel registro")

pd.add_authority(ea.certificate)
print(f"Certificato EA '{ea.common_name}' pubblicato nel registro")

pd.add_authority(ca.certificate)
print(f"Certificato CA '{ca.common_name}' pubblicato nel registro")

# ============================================================
# PHASE 3: L'elettore verifica i certificati EA e CA
# ============================================================
print("\n" + "=" * 60)
print("FASE 3: L'elettore verifica i certificati EA e CA")
print("=" * 60)

voter = Voter("Peppe")
print(f"Voter '{voter.name}' creato")

ea_valid = voter.verify_authority_certificate("National Electoral Authority", pd)
if ea_valid:
    print(f"Voter '{voter.name}': Certificato EA verificato con successo (firma StateCA valida)")
else:
    print(f"Voter '{voter.name}': Certificato EA NON VALIDO!")

ca_valid = voter.verify_authority_certificate("National Counting Authority", pd)
if ca_valid:
    print(f"Voter '{voter.name}': Certificato CA verificato con successo (firma StateCA valida)")
else:
    print(f"Voter '{voter.name}': Certificato CA NON VALIDO!")

# ============================================================
# FASE 4: Security test (Fake Authority)
# ============================================================
print("\n" + "=" * 60)
print("FASE 4: Security Test — Autorità con finta CA")
print("=" * 60)

fake_state = StateCA("Fake State")
fake_ea = ElectoralAuthority("Fake EA", fake_state)
print(f"Falso account EA creato: '{fake_ea.common_name}' (signed by '{fake_state.common_name}')")

pd.add_authority(fake_ea.certificate)
print(f"Certificato EA falso pubblicato nel registro")

fake_ea_valid = voter.verify_authority_certificate("Fake EA", pd)
if fake_ea_valid:
    print(f"ERRORE DI SICUREZZA: è stato accettato un certificato EA falso!")
else:
    print(f"Certificato EA falso RIFIUTATO: la firma non corrisponde a quella del certificato StateCA legittimo")

# ============================================================
# FASE 5: Voter Authentication
# ============================================================
print("\n" + "=" * 60)
print("FASE 5: Autenticazione degli elettori tramite il Comune")
print("=" * 60)

csr = voter.generate_certificate_request()
certificate = municipality.sign_voter_csr(csr)
voter.set_certificate(certificate)
print(f"Voter '{voter.name}' ha ricevuto il certificato da '{municipality.common_name}'")

issuer_name = voter.certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
municipality_cert = pd.get_municipality(issuer_name)

if pd.verify_certificate_chain(voter.certificate, municipality_cert):
    print(f"CATENA VERIFICATA CORRETTAMENTE")
else:
    print(f"CATENA NON RISPETTATA CORRETTAMENTE")

# ============================================================
# FASE 6: Sottomissione Scheda
# Referendum: "Sei favorevole alla proposta di legge X?" (SI / NO)
# ============================================================
print("\n" + "=" * 60)
print("FASE 6: Sottomissione Scheda — Referendum SI/NO")
print("=" * 60)

# L'elettore recupera pkAC dal PublicDirectory (certificati delle autorità sono pubblici)
ac_public_key = pd.get_authority_public_key("National Counting Authority")
ae_public_key  = ea.get_public_key()

# ----------------------------------------------------------
# Passo 1 — Richiesta scheda:  Enc(pkAE, ballot_request || Cert_elettore)
# ----------------------------------------------------------
print("\n[Passo 1] Elettore -> AE : Enc(pkAE, ballot_request || Cert_elettore)")
encrypted_request = voter.request_ballot(ae_public_key)
print(f"Richiesta cifrata inviata ({len(encrypted_request)} byte)")

# ----------------------------------------------------------
# Passi 2-3 — AE verifica la catena -> (schedavuota, σ_AE)
# ----------------------------------------------------------
print("\n[Passi 2-3] AE verifica catena -> AE -> Elettore : (schedavuota, σ_AE)")
try:
    blank_ballot_bytes, ae_signature = ea.receive_ballot_request(encrypted_request, pd)
    print(f"Catena certificato elettore verificata (Voter -> MunicipalityCA -> StateCA)")
    print(f"Scheda vuota firmata da AE inviata all'elettore")
except InvalidBallotRequest as exc:
    print(f"Richiesta rifiutata: {exc}")
    raise SystemExit(1)

# L'elettore verifica la firma AE sulla scheda vuota
blank_ballot = voter.receive_blank_ballot(blank_ballot_bytes, ae_signature, ae_public_key)
print(f"Elettore ha verificato σ_AE sulla scheda vuota")
print(f"Quesito referendario: \"{blank_ballot.question}\"")

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
print(f"Payload di invio costruito")

# ----------------------------------------------------------
# Passi 5-7 — AE valida, registra e rilascia ricevuta
# ----------------------------------------------------------
print("\n[Passi 5-7] AE: verifica σ -> controlla ID consumati -> registra -> ricevuta")
try:
    receipt = ea.receive_encrypted_ballot(submission_payload, voter.get_public_key(), ac_public_key)
    print(f"Vrfy(pkEletore, encrypted_payload, σ) = 1")
    print(f"ID elettore non presente nella lista 'consumati'")
    print(f"Dimensione crittogramma AC corretta ({ca.get_public_key().key_size // 8} byte)")
    print(f"ID aggiunto alla lista 'consumati'")
    print(f"Scheda pubblicata su bacheca B  ({len(ea.bulletin_board)} voce/voci)")
    print(f"Ricevuta: Sign(skAE, Hash(Enc(pkAC, ballot)))  ->  {len(receipt)} byte")
except InvalidBallotSubmission as exc:
    print(f"Invio rifiutato: {exc}")
    raise SystemExit(1)

# L'elettore verifica la ricevuta
receipt_valid = voter.verify_receipt(receipt, ae_public_key)
print(f"\n  {'corretto' if receipt_valid else 'sbagliato'} Verifica ricevuta: "
      f"{'valida — voto registrato correttamente' if receipt_valid else 'NON VALIDA!'}")

# ----------------------------------------------------------
# Security Test A — Double voting
# ----------------------------------------------------------
print("\n" + "-" * 50)
print("Security Test A: Tentativo di voto doppio")
print("-" * 50)
try:
    ea.receive_encrypted_ballot(submission_payload, voter.get_public_key(), ac_public_key)
    print("ERRORE DI SICUREZZA: voto doppio accettato!")
except InvalidBallotSubmission as exc:
    print(f"Voto doppio RIFIUTATO: {exc}")

# ----------------------------------------------------------
# Security Test B — Firma manomessa
# ----------------------------------------------------------
print("\n" + "-" * 50)
print("Security Test B: Firma manomessa sull'invio")
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
    print("ERRORE DI SICUREZZA: firma manomessa accettata!")
except InvalidBallotSubmission as exc:
    print(f"Firma manomessa RIFIUTATA: {exc}")

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
    print("ERRORE DI SICUREZZA: catena non valida accettata!")
except InvalidBallotRequest as exc:
    print(f"Richiesta RIFIUTATA: {exc}")

# ----------------------------------------------------------
# Registrazione di altri elettori per lo scrutinio multi-voto
# ----------------------------------------------------------
print("\n" + "-" * 50)
print("Registrazione elettori aggiuntivi per lo scrutinio")
print("-" * 50)

# Voter 2 — vota NO (voter2 è già creato nel Security Test B, ma non ha votato validamente)
voter2 = Voter("Mario")
csr2 = voter2.generate_certificate_request()
voter2.set_certificate(municipality.sign_voter_csr(csr2))
encrypted_request2 = voter2.request_ballot(ae_public_key)
blank2, sig2 = ea.receive_ballot_request(encrypted_request2, pd)
voter2.receive_blank_ballot(blank2, sig2, ae_public_key)
payload2 = voter2.submit_ballot("NO", ae_public_key, ac_public_key)
receipt2 = ea.receive_encrypted_ballot(payload2, voter2.get_public_key(), ac_public_key)
print(f" '{voter2.name}' ha votato NO — ricevuta verificata: {voter2.verify_receipt(receipt2, ae_public_key)}")

# Voter 4 — vota ASTENUTO
voter4 = Voter("Lucia")
csr4 = voter4.generate_certificate_request()
voter4.set_certificate(municipality.sign_voter_csr(csr4))
encrypted_request4 = voter4.request_ballot(ae_public_key)
blank4, sig4 = ea.receive_ballot_request(encrypted_request4, pd)
voter4.receive_blank_ballot(blank4, sig4, ae_public_key)
payload4 = voter4.submit_ballot("ASTENUTO", ae_public_key, ac_public_key)
receipt4 = ea.receive_encrypted_ballot(payload4, voter4.get_public_key(), ac_public_key)
print(f" '{voter4.name}' ha votato ASTENUTO — ricevuta verificata: {voter4.verify_receipt(receipt4, ae_public_key)}")

# Voter 5 — vota SI
voter5 = Voter("Giovanni")
csr5 = voter5.generate_certificate_request()
voter5.set_certificate(municipality.sign_voter_csr(csr5))
encrypted_request5 = voter5.request_ballot(ae_public_key)
blank5, sig5 = ea.receive_ballot_request(encrypted_request5, pd)
voter5.receive_blank_ballot(blank5, sig5, ae_public_key)
payload5 = voter5.submit_ballot("SI", ae_public_key, ac_public_key)
receipt5 = ea.receive_encrypted_ballot(payload5, voter5.get_public_key(), ac_public_key)
print(f" '{voter5.name}' ha votato SI — ricevuta verificata: {voter5.verify_receipt(receipt5, ae_public_key)}")

print(f"\nBacheca B contiene ora {len(ea.bulletin_board)} scheda/e")
print(f"ID consumati: {len(ea._consumed_ids)}")
print(f"Voti attesi: SI=2 (Peppe, Giovanni), NO=1 (Mario), ASTENUTO=1 (Lucia)")

# ============================================================
# FASE 7: Scrutinio e Conteggio dei Voti 
# ============================================================
print("\n" + "=" * 60)
print("FASE 7: Scrutinio e Conteggio dei Voti")
print("=" * 60)

# ----------------------------------------------------------
# AC preleva la bacheca pubblica di AE
# ----------------------------------------------------------
print("AC preleva le schede cifrate dalla bacheca pubblica di AE")
print(f"Schede sulla bacheca: {len(ea.bulletin_board)}")

# ----------------------------------------------------------
# Verifica, decifrazione e conteggio
# ----------------------------------------------------------
print("\nAC: Vrfy(pkAE, σ) -> Dec(skAC, scheda) -> conteggio")
tally_result = ca.tally_votes(ea.bulletin_board, ea.get_public_key())

print(f"\n  --- Risultati dello scrutinio ---")
print(f"Schede verificate e decifrate: {tally_result['total_valid']}")
print(f"Anomalie (firma AE invalida): {tally_result['total_anomalies']}")
print(f"Decifrature invalide: {tally_result['total_invalid']}")
print(f"\n Conteggio finale:")
print(f"     SI:       {tally_result['count_si']}")
print(f"     NO:       {tally_result['count_no']}")
print(f"     NULLO:    {tally_result['count_null']}")
print(f"     TOTALE:   {tally_result['total_valid']}")

# Verifica correttezza conteggio
assert tally_result["count_si"] == 2, f"Attesi 2 SI, ottenuti {tally_result['count_si']}"
assert tally_result["count_no"] == 1, f"Atteso 1 NO, ottenuti {tally_result['count_no']}"
assert tally_result["count_null"] == 1, f"Atteso 1 NULLO, ottenuti {tally_result['count_null']}"
assert tally_result["total_anomalies"] == 0, "Non ci dovrebbero essere anomalie"
print(f"\n Asserzioni di correttezza superate!")

# ----------------------------------------------------------
# Verifica universale
# ----------------------------------------------------------
print("\nVerifica Universale ")

# Verifica firma di AC sul risultato
sig_valid = CountingAuthority.verify_tally(
    tally_result["signed_payload"],
    tally_result["ac_signature"],
    ca.get_public_key(),
)
print(f"{'corretto' if sig_valid else 'sbagliato'} Vrfy(pkAC, σAC, payload) = {'1 — firma valida' if sig_valid else '0 — INVALIDA!'}")

# Confronto schede cifrate (bacheca AE vs payload AC)
ballot_match = CountingAuthority.verify_ballot_consistency(
    tally_result["signed_payload"],
    ea.bulletin_board,
)
print(f"  {'corretto --' if ballot_match else 'sbagliato --'} Confronto schede bacheca AE - payload AC: "
      f"{'coerente — nessuna scheda aggiunta/rimossa' if ballot_match else 'INCOERENTE!'}")

# ----------------------------------------------------------
# Security Test D — Scheda fraudolenta iniettata nella bacheca
# ----------------------------------------------------------
print("\n" + "-" * 50)
print("Security Test D: Scheda fraudolenta iniettata nella bacheca")
print("-" * 50)

import os
# Costruiamo una scheda cifrata fasulla con firma AE inventata
fake_encrypted_ballot = os.urandom(512)  # 512 byte casuali
fake_ae_signature = os.urandom(512)      # firma fasulla

# Inietto nella bacheca una copia con la scheda fraudolenta
tampered_board = list(ea.bulletin_board) + [{
    "encrypted_ballot": fake_encrypted_ballot,
    "ae_signature": fake_ae_signature,
}]

tally_tampered = ca.tally_votes(tampered_board, ea.get_public_key())

if tally_tampered["total_anomalies"] == 1:
    print(f"Scheda fraudolenta RILEVATA come anomalia")
    print(f"     Motivo: {tally_tampered['anomalies'][0]['reason']}")
    print(f"Conteggio non alterato: SI={tally_tampered['count_si']}, "
          f"NO={tally_tampered['count_no']}, NULLO={tally_tampered['count_null']}")
else:
    print(f"ERRORE DI SICUREZZA: scheda fraudolenta non rilevata!")

# ----------------------------------------------------------
# Security Test E — Manomissione del risultato pubblicato
# ----------------------------------------------------------
print("\n" + "-" * 50)
print("Security Test E: Manomissione del risultato firmato da AC")
print("-" * 50)

# Altero un byte del payload firmato
original_payload = tally_result["signed_payload"]
tampered_payload_bytes = bytearray(original_payload)
tampered_payload_bytes[10] ^= 0xFF  # flip di un byte
tampered_payload_bytes = bytes(tampered_payload_bytes)

tamper_detected = not CountingAuthority.verify_tally(
    tampered_payload_bytes,
    tally_result["ac_signature"],
    ca.get_public_key(),
)

if tamper_detected:
    print(f"Manomissione RILEVATA: Vrfy(pkAC, σAC, payload_alterato) = 0")
else:
    print(f"ERRORE DI SICUREZZA: manomissione non rilevata!")

# ============================================================
# Summary
# ============================================================
print("\n" + "=" * 60)
print("SUMMARY: Protocollo completato con successo")
print("=" * 60)
print(f"StateCA:       '{state_ca.common_name}'")
print(f"EA:            '{ea.common_name}' — cert verificato: {ea_valid}")
print(f"AC:            '{ca.common_name}' — cert verificato: {ca_valid}")
print(f"Municipality:  '{municipality.common_name}'")
print(f"Elettori registrati: {len(ea._consumed_ids)}")
print(f"Bacheca B:     {len(ea.bulletin_board)} scheda/e pubblicata/e")
print(f"ID consumati:  {len(ea._consumed_ids)}")
print(f"\nRisultato scrutinio:")
print(f"SI:    {tally_result['count_si']}")
print(f"NO:    {tally_result['count_no']}")
print(f"NULLO: {tally_result['count_null']}")
print(f"\nVerifica universale (VU.1): firma AC valida, schede coerenti")
print(f"Security Test D: scheda fraudolenta rilevata")
print(f"Security Test E: manomissione risultato rilevata")
print(f"\nTutte le fasi del protocollo completate con successo!")