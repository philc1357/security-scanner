"""
email_dns.py — E-Mail- & DNS-Scanner (Phase 3).

Prüft passiv über DNS, ob die Domain gegen das Fälschen von Absenderadressen
(E-Mail-Spoofing / Phishing im Namen des Unternehmens) abgesichert ist:

- SPF  (Sender Policy Framework):   Welche Server dürfen in Ihrem Namen senden?
- DMARC (Domain-based Message ...): Was sollen Empfänger mit Fälschungen tun?
- DKIM (DomainKeys Identified ...):  digitale Signatur — nur als Hinweis (siehe unten).

Bewusste Einschränkung bei DKIM:
DKIM-Einträge liegen unter '<selector>._domainkey.<domain>'. Der Selector ist von
außen nicht zuverlässig ermittelbar, daher wird DKIM nicht aktiv gemessen, sondern
nur als laienverständlicher INFO-Hinweis ausgegeben (vermeidet Fehlalarme).

Nutzt 'dnspython' mit harter Zeitbegrenzung, damit ein langsamer/gestörter
DNS-Server den Scan nicht blockiert.
"""

from __future__ import annotations

import dns.exception
import dns.resolver

from core import recommendations as R
from core.result import Effort, Finding, Severity, Status
from scanners.base import Scanner

# Harte Obergrenze pro DNS-Abfrage (Sekunden) — analog zu den Timeouts der anderen Scanner.
DNS_TIMEOUT = 5


class EmailDnsScanner(Scanner):
    category = "E-Mail & DNS (Spoofing-Schutz)"

    def __init__(self) -> None:
        # Eigener Resolver mit Zeitlimit, damit ein hängender DNS-Server nicht den Scan blockiert.
        self._resolver = dns.resolver.Resolver()
        self._resolver.timeout = DNS_TIMEOUT
        self._resolver.lifetime = DNS_TIMEOUT

    def run(self, domain: str, context: dict) -> list[Finding]:
        findings: list[Finding] = []
        findings.append(self._check_spf(domain))
        findings.append(self._check_dmarc(domain))
        findings.append(self._check_dkim())
        return findings

    # ------------------------------------------------------------------
    # SPF: TXT-Eintrag der Domain mit 'v=spf1'
    # ------------------------------------------------------------------
    def _check_spf(self, domain: str) -> Finding:
        records, error = self._query_txt(domain)
        if error is not None:
            return error

        spf = next((r for r in records if r.lower().startswith("v=spf1")), None)
        if spf is None:
            return self._make(
                "email_dns.spf_missing", R.EMAIL_SPF_MISSING, Severity.MEDIUM, Status.FAIL,
                affected="SPF", evidence="(kein SPF-Eintrag gefunden)", effort=Effort.LOW,
            )

        # '+all' (oder ein nacktes 'all') erlaubt jedem das Senden → Schutzwirkung aufgehoben.
        tokens = spf.lower().split()
        if "+all" in tokens or "all" in tokens:
            return self._make(
                "email_dns.spf_weak", R.EMAIL_SPF_WEAK, Severity.LOW, Status.WARN,
                affected="SPF", evidence=spf, effort=Effort.LOW,
            )

        return self._make(
            "email_dns.spf_ok", R.EMAIL_SPF_OK, Severity.INFO, Status.PASS,
            affected="SPF", evidence=spf,
        )

    # ------------------------------------------------------------------
    # DMARC: TXT-Eintrag unter '_dmarc.<domain>' mit 'v=DMARC1'
    # ------------------------------------------------------------------
    def _check_dmarc(self, domain: str) -> Finding:
        records, error = self._query_txt(f"_dmarc.{domain}")
        if error is not None:
            return error

        dmarc = next((r for r in records if r.lower().startswith("v=dmarc1")), None)
        if dmarc is None:
            return self._make(
                "email_dns.dmarc_missing", R.EMAIL_DMARC_MISSING, Severity.MEDIUM, Status.FAIL,
                affected="DMARC", evidence="(kein DMARC-Eintrag gefunden)", effort=Effort.LOW,
            )

        policy = self._dmarc_policy(dmarc)
        if policy in ("quarantine", "reject"):
            return self._make(
                "email_dns.dmarc_ok", R.EMAIL_DMARC_OK, Severity.INFO, Status.PASS,
                affected="DMARC", evidence=f"p={policy}",
            )
        # p=none oder fehlende/ungültige Policy → nur Beobachtung, kein wirksamer Schutz.
        return self._make(
            "email_dns.dmarc_weak", R.EMAIL_DMARC_WEAK, Severity.LOW, Status.WARN,
            affected="DMARC", evidence=dmarc, effort=Effort.LOW,
        )

    @staticmethod
    def _dmarc_policy(record: str) -> str:
        """Liest die 'p='-Policy aus einem DMARC-Eintrag; '' wenn nicht vorhanden."""
        for part in record.split(";"):
            key, _, value = part.strip().partition("=")
            if key.strip().lower() == "p":
                return value.strip().lower()
        return ""

    # ------------------------------------------------------------------
    # DKIM: bewusst nur Hinweis (Selector passiv nicht ermittelbar)
    # ------------------------------------------------------------------
    def _check_dkim(self) -> Finding:
        return self._make(
            "email_dns.dkim_info", R.EMAIL_DKIM_INFO, Severity.INFO, Status.INFO,
            affected="DKIM",
        )

    # ------------------------------------------------------------------
    # Hilfsfunktion: TXT-Records abfragen, DNS-Fehler kontrolliert behandeln
    # ------------------------------------------------------------------
    def _query_txt(self, name: str) -> tuple[list[str], Finding | None]:
        """
        Liefert (Liste der TXT-Strings, None) bei Erfolg.
        Fehlt der Name/die Antwort, gilt das als „kein Eintrag" → (leere Liste, None).
        Bei echten DNS-Störungen (Timeout, kein Nameserver) → ([], INFO-Finding),
        damit ein Ausfall den Score nicht verfälscht.
        """
        try:
            answer = self._resolver.resolve(name, "TXT")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return [], None
        except (dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout,
                dns.exception.Timeout, dns.exception.DNSException) as exc:
            return [], self._make(
                "email_dns.error", R.EMAIL_DNS_ERROR, Severity.INFO, Status.INFO,
                affected=name, evidence=str(exc),
            )

        # Jeder TXT-Record kann aus mehreren Teilstrings bestehen — zusammenfügen.
        records: list[str] = []
        for rdata in answer:
            records.append("".join(part.decode() for part in rdata.strings))
        return records, None

    # ------------------------------------------------------------------
    # Hilfsfunktion: Finding aus einem Textbaustein bauen
    # ------------------------------------------------------------------
    def _make(self, fid: str, texts: dict, severity: Severity, status: Status,
              affected: str = "", evidence: str = "", effort: Effort = Effort.MEDIUM) -> Finding:
        return Finding(
            id=fid,
            category=self.category,
            title=texts["title"],
            severity=severity,
            status=status,
            explanation=texts["explanation"],
            recommendation=texts["recommendation"],
            effort=effort,
            affected=affected,
            evidence=evidence,
        )
