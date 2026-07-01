"""
privacy.py — Datenschutz-/DSGVO-Scanner (Phase 4).

Wertet rein passiv die bereits vom HeaderScanner geholte HTML-Antwort
(`context["response"]`) aus — es wird also kein zusätzlicher Seitenabruf gestartet.
Geprüft werden die für Kleinunternehmen typischen DSGVO-Stolperfallen:

- Tracker:        bekannte Tracking-Dienste (Google Analytics/GTM, Facebook-Pixel, ...)
- Cookie-Banner:  Hinweise auf ein Einwilligungs-Tool (Consent-Management)
- Externe Ressourcen: Inhalte von Drittanbietern (z.B. Google Fonts) — IP-Abfluss
- Datenschutzhinweis: Link zur Datenschutzerklärung vorhanden?

Bewusste Einschränkung (passive Prüfung):
Banner und Tracker, die erst per JavaScript nachgeladen werden, können übersehen werden.
Die Bewertung ist daher vorsichtig (eher WARN / LOW–MEDIUM), um Fehlalarme zu vermeiden.
Die Befunde sind Hinweise und kein Rechtsrat.
"""

from __future__ import annotations

from urllib.parse import urlparse

from bs4 import BeautifulSoup

from core import recommendations as R
from core.result import Effort, Finding, Severity, Status
from scanners.base import Scanner

# Bekannte Tracker: Anzeigename -> Liste von Erkennungsmustern (in src/href/Inline-Skript).
# Bewusst auf die für KMU häufigsten Dienste beschränkt, um Fehlalarme gering zu halten.
TRACKERS = {
    "Google Analytics": ["google-analytics.com", "gtag(", "ga('create'", "_gaq.push"],
    "Google Tag Manager": ["googletagmanager.com"],
    "Facebook/Meta Pixel": ["connect.facebook.net", "fbq("],
    "Google Ads / DoubleClick": ["doubleclick.net", "googleadservices.com"],
    "Hotjar": ["hotjar.com", "hj("],
    "LinkedIn Insight": ["snap.licdn.com"],
    "TikTok Pixel": ["analytics.tiktok.com", "ttq."],
}

# Hinweise auf ein Consent-/Cookie-Banner: bekannte Anbieter-Bibliotheken ...
CONSENT_LIBRARIES = [
    "cookiebot", "usercentrics", "borlabs", "cookieconsent", "klaro",
    "onetrust", "consentmanager", "cookieyes", "complianz", "iubenda",
    "didomi", "termly", "osano",
]
# ... sowie generische Schlüsselwörter im sichtbaren Text (Deutsch/Englisch).
CONSENT_KEYWORDS = [
    "cookie-einstellung", "cookie einstellung", "einwilligung", "zustimmen",
    "akzeptieren", "cookie", "consent", "datenschutz-präferenz",
]

# Schlüsselwörter für einen Datenschutz-Link (in href oder Linktext).
PRIVACY_LINK_HINTS = ["datenschutz", "privacy", "data-protection", "datenschutzerklärung"]


class PrivacyScanner(Scanner):
    category = "Datenschutz & DSGVO"

    def run(self, domain: str, context: dict) -> list[Finding]:
        resp = context.get("response")
        if resp is None:
            # HeaderScanner hat die Seite nicht erreicht — keine HTML-Auswertung möglich.
            return []

        # Gesamte Auswertung defensiv: ein Parser-Problem darf den Scan nicht abbrechen.
        try:
            soup = BeautifulSoup(resp.text, "html.parser")
        except Exception as exc:  # pragma: no cover
            return [self._make(
                "privacy.parse_error", R.PRIVACY_PARSE_ERROR, Severity.INFO, Status.INFO,
                affected=getattr(resp, "url", domain), evidence=str(exc),
            )]

        own_base = self._base_domain(urlparse(getattr(resp, "url", f"https://{domain}")).hostname or domain)

        # Banner zuerst ermitteln — das Ergebnis fließt in die Tracker-Bewertung ein.
        has_banner, banner_evidence = self._detect_banner(soup, resp.text)

        findings: list[Finding] = []
        findings.append(self._check_trackers(soup, resp.text, has_banner))
        findings.append(self._check_cookie_banner(soup, resp.text, has_banner, banner_evidence))
        findings.append(self._check_external_resources(soup, own_base))
        findings.append(self._check_privacy_link(soup))
        return findings

    # ------------------------------------------------------------------
    # Tracker: bekannte Dienste in src/href und Inline-Skripten
    # ------------------------------------------------------------------
    def _check_trackers(self, soup: BeautifulSoup, html: str, has_banner: bool) -> Finding:
        haystack = self._collect_resource_refs(soup) + "\n" + html.lower()
        found = [name for name, patterns in TRACKERS.items()
                 if any(p.lower() in haystack for p in patterns)]

        if not found:
            return self._make(
                "privacy.trackers_none", R.PRIVACY_TRACKERS_NONE, Severity.INFO, Status.PASS,
                affected="Tracking", evidence="(keine bekannten Tracker gefunden)",
            )

        evidence = ", ".join(found)
        if has_banner:
            return self._make(
                "privacy.trackers_with_consent", R.PRIVACY_TRACKERS_WITH_CONSENT,
                Severity.LOW, Status.INFO, affected="Tracking", evidence=evidence, effort=Effort.LOW,
            )
        return self._make(
            "privacy.trackers_no_consent", R.PRIVACY_TRACKERS_NO_CONSENT,
            Severity.MEDIUM, Status.WARN, affected="Tracking", evidence=evidence, effort=Effort.MEDIUM,
        )

    # ------------------------------------------------------------------
    # Cookie-/Einwilligungs-Banner
    # ------------------------------------------------------------------
    def _check_cookie_banner(self, soup: BeautifulSoup, html: str, has_banner: bool,
                             banner_evidence: str) -> Finding:
        if has_banner:
            return self._make(
                "privacy.banner_present", R.PRIVACY_BANNER_PRESENT, Severity.INFO, Status.PASS,
                affected="Cookie-Banner", evidence=banner_evidence,
            )
        # Kein Banner: nur dann ein Mangel, wenn auch Tracker vorhanden sind.
        haystack = self._collect_resource_refs(soup) + "\n" + html.lower()
        trackers_present = any(
            any(p.lower() in haystack for p in patterns) for patterns in TRACKERS.values()
        )
        if trackers_present:
            return self._make(
                "privacy.banner_missing", R.PRIVACY_BANNER_MISSING, Severity.LOW, Status.WARN,
                affected="Cookie-Banner", evidence="(kein Consent-Banner erkannt)", effort=Effort.MEDIUM,
            )
        return self._make(
            "privacy.banner_present", R.PRIVACY_BANNER_PRESENT, Severity.INFO, Status.PASS,
            affected="Cookie-Banner", evidence="(kein Banner nötig — keine Tracker erkannt)",
        )

    def _detect_banner(self, soup: BeautifulSoup, html: str) -> tuple[bool, str]:
        """Erkennt Hinweise auf ein Consent-Banner. Liefert (gefunden, Beleg)."""
        refs = self._collect_resource_refs(soup)
        for lib in CONSENT_LIBRARIES:
            if lib in refs or lib in html.lower():
                return True, f"Consent-Tool erkannt: {lib}"
        # Generische Heuristik: sichtbarer Text enthält Cookie-/Einwilligungs-Begriffe.
        text = soup.get_text(separator=" ", strip=True).lower()
        hits = [kw for kw in CONSENT_KEYWORDS if kw in text]
        # „cookie" allein ist schwach — mindestens zwei Treffer oder ein Einwilligungs-Begriff.
        strong = any(kw in text for kw in ("einwilligung", "consent", "zustimmen", "cookie-einstellung"))
        if strong or len(hits) >= 2:
            return True, f"Hinweise im Seitentext: {', '.join(hits[:4])}"
        return False, ""

    # ------------------------------------------------------------------
    # Externe Ressourcen (Drittanbieter-Inhalte)
    # ------------------------------------------------------------------
    def _check_external_resources(self, soup: BeautifulSoup, own_base: str) -> Finding:
        third_party: set[str] = set()
        for tag, attr in (("script", "src"), ("link", "href"), ("img", "src"), ("iframe", "src")):
            for el in soup.find_all(tag):
                url = el.get(attr)
                if not url:
                    continue
                host = urlparse(url).hostname
                if not host:  # relative URL oder data:-URI → eigene Seite
                    continue
                if self._base_domain(host) != own_base:
                    third_party.add(host)

        if not third_party:
            return self._make(
                "privacy.external_none", R.PRIVACY_EXTERNAL_NONE, Severity.INFO, Status.PASS,
                affected="Externe Ressourcen", evidence="(keine Drittanbieter erkannt)",
            )

        hosts = sorted(third_party)
        evidence = f"{len(hosts)} Drittanbieter: " + ", ".join(hosts[:8])
        if len(hosts) > 8:
            evidence += f" … (+{len(hosts) - 8} weitere)"
        return self._make(
            "privacy.external_resources", R.PRIVACY_EXTERNAL_RESOURCES, Severity.LOW, Status.INFO,
            affected="Externe Ressourcen", evidence=evidence, effort=Effort.MEDIUM,
        )

    # ------------------------------------------------------------------
    # Datenschutzerklärung verlinkt?
    # ------------------------------------------------------------------
    def _check_privacy_link(self, soup: BeautifulSoup) -> Finding:
        for a in soup.find_all("a"):
            href = (a.get("href") or "").lower()
            text = a.get_text(strip=True).lower()
            if any(h in href or h in text for h in PRIVACY_LINK_HINTS):
                return self._make(
                    "privacy.policy_present", R.PRIVACY_POLICY_PRESENT, Severity.INFO, Status.PASS,
                    affected="Datenschutzerklärung", evidence=a.get("href") or text or "(Link gefunden)",
                )
        return self._make(
            "privacy.policy_missing", R.PRIVACY_POLICY_MISSING, Severity.MEDIUM, Status.FAIL,
            affected="Datenschutzerklärung", evidence="(kein Link gefunden)", effort=Effort.MEDIUM,
        )

    # ------------------------------------------------------------------
    # Hilfsfunktionen
    # ------------------------------------------------------------------
    @staticmethod
    def _collect_resource_refs(soup: BeautifulSoup) -> str:
        """Sammelt alle src/href-Werte (kleingeschrieben) zu einem durchsuchbaren String."""
        parts: list[str] = []
        for tag, attr in (("script", "src"), ("link", "href"), ("img", "src"), ("iframe", "src")):
            for el in soup.find_all(tag):
                val = el.get(attr)
                if val:
                    parts.append(val.lower())
        return "\n".join(parts)

    @staticmethod
    def _base_domain(host: str) -> str:
        """
        Vereinfachte Basis-Domain (letzte zwei Labels), nur zur Einstufung
        „eigene vs. dritte Partei". Bewusst simpel gehalten — keine vollständige
        Public-Suffix-Auswertung (würde eine zusätzliche Abhängigkeit erfordern).
        """
        host = (host or "").lower().strip(".")
        labels = host.split(".")
        if len(labels) <= 2:
            return host
        return ".".join(labels[-2:])

    # ------------------------------------------------------------------
    # Finding aus einem Textbaustein bauen (identisch zu den übrigen Scannern)
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
