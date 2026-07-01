"""
result.py — Einheitliches Ergebnis-Schema der Scan-Engine.

Alle Scanner (Header, TLS, E-Mail/DNS, ...) liefern ihre Ergebnisse als Liste von
`Finding`-Objekten zurück. Das stellt sicher, dass Risiko-Aggregation (risk.py) und
das PHP-Frontend mit einem einzigen, stabilen Datenformat arbeiten — neue Scanner
können hinzugefügt werden, ohne Schema oder Report anzupassen.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum


class Severity(str, Enum):
    """Schweregrad eines Fundes. Die Reihenfolge bestimmt die Priorisierung im Report."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        """Punktabzug für die Risiko-Berechnung (höher = gravierender)."""
        return {
            Severity.CRITICAL: 40,
            Severity.HIGH: 20,
            Severity.MEDIUM: 10,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }[self]


class Status(str, Enum):
    """Prüfergebnis eines einzelnen Checks."""
    PASS = "pass"    # Anforderung erfüllt
    WARN = "warn"    # vorhanden, aber verbesserungswürdig
    FAIL = "fail"    # Anforderung nicht erfüllt
    INFO = "info"    # rein informativ, nicht bewertet


class Effort(str, Enum):
    """Geschätzter Umsetzungsaufwand für die empfohlene Maßnahme (laienverständlich)."""
    LOW = "gering"
    MEDIUM = "mittel"
    HIGH = "hoch"


@dataclass
class Finding:
    """
    Ein einzelner Sicherheits-Befund.

    Die Felder `explanation` und `recommendation` sind bewusst laienverständlich
    formuliert ("Was bedeutet das?" / "Was muss ich tun?"), da die Zielgruppe
    Kleinunternehmer ohne IT-Hintergrund sind.
    """
    id: str                       # eindeutige Kennung, z.B. "headers.hsts_missing"
    category: str                 # Kategorie/Prüfbereich, z.B. "HTTP-Sicherheit"
    title: str                    # kurze Überschrift
    severity: Severity
    status: Status
    explanation: str              # Was bedeutet das für mein Unternehmen?
    recommendation: str           # Was muss ich konkret tun?
    effort: Effort = Effort.MEDIUM
    affected: str = ""            # betroffenes Element (Header-Name, Cookie, ...)
    evidence: str = ""            # tatsächlich gemessener Wert/Beleg
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["status"] = self.status.value
        d["effort"] = self.effort.value
        return d


@dataclass
class ScanResult:
    """Gesamtergebnis eines Scans über alle Scanner hinweg."""
    target: str
    domain: str
    scan_time: str
    findings: list[Finding] = field(default_factory=list)
    meta: dict = field(default_factory=dict)   # z.B. Erreichbarkeit, Latenz, Status-Code
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "domain": self.domain,
            "scan_time": self.scan_time,
            "error": self.error,
            "meta": self.meta,
            "findings": [f.to_dict() for f in self.findings],
        }
