"""
Ballot — scheda elettorale per referendum (SI / NO).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional

VALID_CHOICES = {"SI", "NO"}
REFERENDUM_QUESTION = "Sei favorevole alla proposta di legge X?"


@dataclass
class Ballot:
    """Rappresenta una scheda di voto per un referendum SI/NO.

    Attributes:
        question: Il quesito referendario (fisso per tutta la sessione di voto).
        choice:   La scelta dell'elettore; None = scheda vuota (blank),
                  "SI" o "NO" = scheda compilata.
    """

    question: str = REFERENDUM_QUESTION
    choice: Optional[str] = None  # None = blank ballot

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    def to_bytes(self) -> bytes:
        """Serializza la scheda in JSON (UTF-8)."""
        return json.dumps({"question": self.question, "choice": self.choice}).encode()

    @classmethod
    def from_bytes(cls, data: bytes) -> "Ballot":
        """Deserializza da JSON."""
        d = json.loads(data.decode())
        return cls(question=d["question"], choice=d.get("choice"))

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def is_blank(self) -> bool:
        return self.choice is None

    def is_valid(self) -> bool:
        """Una scheda compilata è valida se la scelta è SI o NO."""
        return self.choice in VALID_CHOICES
