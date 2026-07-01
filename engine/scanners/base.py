"""
base.py — Gemeinsame Schnittstelle für alle Scanner-Module.

Jeder Scanner (Header, TLS, E-Mail/DNS, ...) erbt von `Scanner` und implementiert
`run()`. Neue Prüfbereiche werden dadurch zu reinen Add-ons: in scan.py registrieren,
fertig — Schema, Risiko-Aggregation und Report bleiben unverändert.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from core.result import Finding


class Scanner(ABC):
    """Basisklasse für alle Scanner."""

    #: Anzeigename der Kategorie, unter der die Findings im Report erscheinen.
    category: str = "Allgemein"

    @abstractmethod
    def run(self, domain: str, context: dict) -> list[Finding]:
        """
        Führt die Prüfung für `domain` durch und liefert eine Liste von Findings.

        `context` ist ein gemeinsamer Zwischenspeicher (z.B. eine bereits geholte
        HTTP-Response), damit sich Scanner Arbeit teilen können, statt sie zu wiederholen.
        """
        raise NotImplementedError
