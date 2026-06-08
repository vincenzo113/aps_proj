"""
Autorità di Conteggio (AC) — Counting Authority.

Responsabile di:
  1. Prelevare le schede cifrate dalla bacheca pubblica di AE (§2.3.1).
  2. Verificare l'autenticità di ciascuna scheda tramite la firma di AE (§2.3.2).
  3. Decifrare le schede con la propria chiave privata skAC (§2.3.3).
  4. Conteggiare i risultati e pubblicare il tutto firmato digitalmente (§2.3.4).

La separazione tra la fase di raccolta (AE) e la fase di decifrazione (AC)
costituisce il nucleo architetturale che garantisce la segretezza del voto (S.1, S.3).
"""

from __future__ import annotations

import base64
import json

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from pki.StateCA import StateCA
from entities.Ballot import Ballot, VALID_VOTE_VALUES
from utils.crypto_utils import rsa_decrypt, sign_pss, verify_pss, sha256


class CountingAuthority:
    """Counting Authority (AC).

    Responsible for counting votes while ensuring pseudo-anonymity.
    Possesses an end-entity certificate signed directly by the StateCA.

    AC è l'unica entità in possesso della chiave privata di decifrazione skAC,
    che non è mai stata condivisa con AE né con alcun altro attore del sistema.
    """

    def __init__(self, common_name: str, state_ca: StateCA):
        self.common_name = common_name

        # Generate RSA 4096 bit key pair
        self._private_key: RSAPrivateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )

        # Create CSR and send it to the StateCA for signing
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.common_name),
        ])).sign(self._private_key, hashes.SHA256())

        # Obtain the certificate signed by the StateCA (end-entity, ca=False)
        self.certificate: x509.Certificate = state_ca.sign_authority_csr(csr)

        # Registro anomalie riscontrate durante lo scrutinio
        self.anomalies: list[dict] = []

    def get_public_key(self) -> RSAPublicKey:
        """Returns the public key of the Counting Authority"""
        return self._private_key.public_key()

    # ------------------------------------------------------------------
    # §2.3 — Fase di Scrutinio e Conteggio dei Voti
    # ------------------------------------------------------------------

    def tally_votes(
        self,
        bulletin_board: list[dict],
        ae_public_key: RSAPublicKey,
    ) -> dict:
        """Esegue l'intera fase di scrutinio (§2.3).

        Flusso:
          1. Preleva le schede cifrate dalla bacheca pubblica di AE (§2.3.1).
          2. Verifica la firma di AE su ciascuna scheda (§2.3.2).
          3. Decifra le schede valide con skAC (§2.3.3).
          4. Conteggia e pubblica il risultato firmato (§2.3.4).

        Args:
            bulletin_board: La bacheca pubblica di AE, lista di dict con
                            ``encrypted_ballot`` (bytes) e ``ae_signature`` (bytes).
            ae_public_key:  Chiave pubblica di AE per la verifica delle firme.

        Returns:
            dict con i campi:
              - ``count_si``        : numero di voti "SI"
              - ``count_no``        : numero di voti "NO"
              - ``count_null``      : numero di voti nulli / astensioni
              - ``total_valid``     : totale schede decifrate valide
              - ``total_anomalies`` : totale schede scartate (firma AE invalida)
              - ``total_invalid``   : totale schede decifrate con valore non valido
              - ``anomalies``       : dettaglio anomalie
              - ``signed_payload``  : payload firmato per pubblicazione
              - ``ac_signature``    : firma digitale di AC sul payload
        """
        self.anomalies = []

        # ----- §2.3.2  Verifica delle schede cifrate -----
        verified_ballots: list[bytes] = []
        all_encrypted_ballots: list[bytes] = []

        for idx, entry in enumerate(bulletin_board):
            encrypted_ballot = entry["encrypted_ballot"]
            ae_signature = entry["ae_signature"]
            all_encrypted_ballots.append(encrypted_ballot)

            # Vrfy(pkAE, σAE || schedacifrata) =? 1
            # La firma di AE è calcolata su Hash(encrypted_ballot)
            ballot_hash = sha256(encrypted_ballot)
            if verify_pss(ae_signature, ballot_hash, ae_public_key):
                verified_ballots.append(encrypted_ballot)
            else:
                self.anomalies.append({
                    "index": idx,
                    "reason": "Firma AE non valida: Vrfy(pkAE, σAE, Hash(schedacifrata)) ≠ 1",
                    "type": "INVALID_AE_SIGNATURE",
                })

        # ----- §2.3.3  Decifrazione delle schede -----
        votes: list[int] = []  # v ∈ {1, 0, -1}
        invalid_decryptions = 0

        for encrypted_ballot in verified_ballots:
            try:
                # votoplain = RSApaddedDEC(skAC, schedacifrata)
                plaintext = rsa_decrypt(encrypted_ballot, self._private_key)
                ballot = Ballot.from_bytes(plaintext)
                vote_value = ballot.to_vote_value()

                # Il risultato atteso è v ∈ {1, 0, -1}
                if vote_value not in VALID_VOTE_VALUES:
                    invalid_decryptions += 1
                    continue

                votes.append(vote_value)
            except Exception:
                invalid_decryptions += 1

        # ----- §2.3.4  Conteggio e pubblicazione del risultato -----
        count_si = sum(1 for v in votes if v == 1)
        count_no = sum(1 for v in votes if v == 0)
        count_null = sum(1 for v in votes if v == -1)

        risultato = {
            "count_si": count_si,
            "count_no": count_no,
            "count_null": count_null,
            "total_valid": len(votes),
            "total_on_board": len(bulletin_board),
            "total_anomalies": len(self.anomalies),
            "total_invalid_decryptions": invalid_decryptions,
        }

        # Costruzione del payload firmato:
        #   payload_data = risultato || {schedacifrate_i}
        #   σ = Sign(skAC, payload_data)
        #   pubblicazione = <AC, payload_data, σ>
        payload_data = json.dumps({
            "authority": self.common_name,
            "result": risultato,
            "encrypted_ballots": [
                base64.b64encode(eb).decode() for eb in all_encrypted_ballots
            ],
        }, ensure_ascii=False).encode()

        ac_signature = sign_pss(payload_data, self._private_key)


        return {
            "count_si": count_si,
            "count_no": count_no,
            "count_null": count_null,
            "total_valid": len(votes),
            "total_anomalies": len(self.anomalies),
            "total_invalid": invalid_decryptions,
            "anomalies": list(self.anomalies),
            "signed_payload": payload_data,
            "ac_signature": ac_signature,
        }

    # ------------------------------------------------------------------
    # §2.3.4 — Verifica Universale (VU.1)
    # ------------------------------------------------------------------

    @staticmethod
    def verify_tally(
        signed_payload: bytes,
        ac_signature: bytes,
        ac_public_key: RSAPublicKey,
    ) -> bool:
        """Verifica universale del risultato pubblicato da AC (VU.1).

        Un osservatore esterno può:
          1. Verificare la firma di AC sul payload pubblicato.
          2. Estrarre le schede cifrate dal payload e confrontarle con
             quelle presenti sulla bacheca pubblica di AE.

        Args:
            signed_payload: Payload pubblicato da AC (JSON bytes).
            ac_signature:   Firma digitale di AC sul payload.
            ac_public_key:  Chiave pubblica di AC per la verifica.

        Returns:
            True se la firma è valida, False altrimenti.
        """
        return verify_pss(ac_signature, signed_payload, ac_public_key)

    @staticmethod
    def verify_ballot_consistency(
        signed_payload: bytes,
        bulletin_board: list[dict],
    ) -> bool:
        """Confronta le schede cifrate nel payload di AC con quelle
        sulla bacheca pubblica di AE (parte della verifica universale VU.1).

        Verifica che nessuna scheda sia stata aggiunta o rimossa da AC
        rispetto a quanto pubblicato da AE.

        Args:
            signed_payload: Payload pubblicato da AC (JSON bytes).
            bulletin_board: La bacheca pubblica di AE.

        Returns:
            True se le schede coincidono, False altrimenti.
        """
        try:
            payload_data = json.loads(signed_payload.decode())
            payload_ballots = [
                base64.b64decode(eb) for eb in payload_data["encrypted_ballots"]
            ]
            board_ballots = [entry["encrypted_ballot"] for entry in bulletin_board]

            if len(payload_ballots) != len(board_ballots):
                return False

            return all(
                pb == bb for pb, bb in zip(payload_ballots, board_ballots)
            )
        except Exception:
            return False
