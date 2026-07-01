"""
headers.py — HTTP-Sicherheitsheader-Scanner (Phase 1).

Refaktoriert aus dem ursprünglichen headerscan.py. Prüft:
- die wichtigsten Security-Header,
- die automatische HTTP→HTTPS-Weiterleitung,
- Cookie-Schutzkennzeichen (Secure/HttpOnly/SameSite),
- verräterische Server-Header (Information Disclosure).

Die geholte HTTP-Response wird im `context` abgelegt, damit spätere Scanner sie
wiederverwenden können, ohne die Seite erneut abzurufen.
"""

from __future__ import annotations

import time

import requests

from core.recommendations import (
    COOKIE_FLAGS,
    CSP_OK,
    CSP_WEAK,
    HEADER_TEXTS,
    HTTPS_REDIRECT,
    INFO_DISCLOSURE,
    XXSS_DISABLED_OK,
)
from core.result import Effort, Finding, Severity, Status
from scanners.base import Scanner

USER_AGENT = "Website_Scanner/1.0 (+IT-Sicherheits-Check)"

# Prüfregeln je Header.
#   required: muss vorhanden sein (sonst FAIL)
#   severity: Schweregrad bei Fehlen/Problem
#   check:    Funktion(Wert) -> bool, ob der vorhandene Wert in Ordnung ist
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "required": True,
        "severity": Severity.HIGH,
        "check": lambda v: "max-age" in v and _max_age(v) >= 31536000,
    },
    "Content-Security-Policy": {
        "required": True,
        "severity": Severity.HIGH,
        # Sonderbewertung in _assess_csp(): vorhanden+stark / vorhanden+abgeschwächt / fehlt.
        "check": None,
    },
    "X-Frame-Options": {
        "required": True,
        "severity": Severity.MEDIUM,
        "check": lambda v: v.strip().upper() in ("DENY", "SAMEORIGIN"),
    },
    "X-Content-Type-Options": {
        "required": True,
        "severity": Severity.MEDIUM,
        "check": lambda v: v.strip().lower() == "nosniff",
    },
    "Referrer-Policy": {
        "required": True,
        "severity": Severity.LOW,
        "check": lambda v: v.strip().lower() not in ("unsafe-url", "no-referrer-when-downgrade", ""),
    },
    "Permissions-Policy": {
        "required": False,
        "severity": Severity.LOW,
        "check": lambda v: len(v.strip()) > 0,
    },
    "X-XSS-Protection": {
        "required": False,
        "severity": Severity.INFO,
        # Sonderbewertung in _assess_xss(): '0' ist korrekt (PASS), '1...' veraltet (WARN).
        "check": None,
    },
}

DISCLOSURE_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator")


def _max_age(value: str) -> int:
    """Liest die max-age-Sekunden aus einem HSTS-Header; 0 wenn nicht ermittelbar."""
    try:
        part = next(p for p in value.split(";") if "max-age" in p)
        return int(part.split("=")[1].strip())
    except (StopIteration, IndexError, ValueError):
        return 0


class HeaderScanner(Scanner):
    category = "HTTP-Sicherheit"

    def run(self, domain: str, context: dict) -> list[Finding]:
        findings: list[Finding] = []
        url = f"https://{domain}"

        # --- Seite abrufen (Ergebnis für andere Scanner im Context ablegen) ---
        try:
            t0 = time.time()
            resp = requests.get(
                url, timeout=15, allow_redirects=True,
                headers={"User-Agent": USER_AGENT},
            )
            context["response"] = resp
            context["meta"] = {
                "reachable": True,
                "status_code": resp.status_code,
                "latency_ms": round((time.time() - t0) * 1000),
                "final_url": resp.url,
            }
        except requests.RequestException as exc:
            context["meta"] = {"reachable": False, "error": str(exc)}
            findings.append(Finding(
                id="headers.unreachable",
                category=self.category,
                title="Website nicht erreichbar",
                severity=Severity.HIGH,
                status=Status.FAIL,
                explanation="Die Website konnte über HTTPS nicht abgerufen werden. "
                            "Eine Sicherheitsprüfung der Header ist daher nicht möglich.",
                recommendation="Prüfen Sie, ob die Domain korrekt ist und die Seite über "
                               "https:// erreichbar ist.",
                effort=Effort.MEDIUM,
                affected=url,
                evidence=str(exc),
            ))
            return findings

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        findings.extend(self._check_security_headers(headers_lower))
        findings.extend(self._check_disclosure(headers_lower))
        findings.extend(self._check_cookies(resp))
        findings.extend(self._check_https_redirect(domain))
        return findings

    # --- Security-Header bewerten ---
    def _check_security_headers(self, headers_lower: dict) -> list[Finding]:
        out = []
        for name, rules in SECURITY_HEADERS.items():
            value = headers_lower.get(name.lower())
            texts = HEADER_TEXTS[name]

            if name == "Content-Security-Policy":
                status, severity, texts = self._assess_csp(value, rules)
            elif name == "X-XSS-Protection":
                status, severity, texts = self._assess_xss(value, texts)
            elif value is None:
                if not rules["required"]:
                    # Optionaler Header fehlt → nur INFO, kein Risiko
                    status, severity = Status.INFO, Severity.INFO
                else:
                    status, severity = Status.FAIL, rules["severity"]
            else:
                try:
                    ok = rules["check"](value)
                except Exception:
                    ok = False
                status = Status.PASS if ok else Status.WARN
                severity = Severity.INFO if ok else rules["severity"]

            out.append(Finding(
                id=f"headers.{name.lower().replace('-', '_')}",
                category=self.category,
                title=texts["title"],
                severity=severity,
                status=status,
                explanation=texts["explanation"],
                recommendation=texts["recommendation"],
                effort=Effort.LOW if name != "Content-Security-Policy" else Effort.MEDIUM,
                affected=name,
                evidence=value or "(nicht gesetzt)",
            ))
        return out

    # --- Sonderfall Content-Security-Policy ---
    # Eine vorhandene CSP ist kein "kein Schutz". Unterschieden wird:
    #   fehlt            → FAIL/HIGH ("Kein Schutz …")
    #   abgeschwächt     → WARN/MEDIUM ('unsafe-eval' oder 'unsafe-inline' ohne 'strict-dynamic')
    #   stark            → PASS/INFO (z.B. Nonce + 'strict-dynamic', das 'unsafe-inline' neutralisiert)
    def _assess_csp(self, value: str | None, rules: dict) -> tuple[Status, Severity, dict]:
        if value is None:
            return Status.FAIL, rules["severity"], HEADER_TEXTS["Content-Security-Policy"]
        v = value.lower()
        has_strict_dynamic = "strict-dynamic" in v
        # 'unsafe-inline' wird von CSP3-Browsern ignoriert, sobald 'strict-dynamic' gesetzt ist.
        weak_inline = "unsafe-inline" in v and not has_strict_dynamic
        if "unsafe-eval" in v or weak_inline:
            return Status.WARN, Severity.MEDIUM, CSP_WEAK
        return Status.PASS, Severity.INFO, CSP_OK

    # --- Sonderfall X-XSS-Protection ---
    # '0' deaktiviert den veralteten Filter bewusst (OWASP-Empfehlung) → korrekt.
    # Jeder aktivierende Wert ('1', '1; mode=block') gilt dagegen als veraltet → WARN.
    def _assess_xss(self, value: str | None, texts: dict) -> tuple[Status, Severity, dict]:
        if value is None:
            return Status.INFO, Severity.INFO, texts
        if value.strip() == "0":
            return Status.PASS, Severity.INFO, XXSS_DISABLED_OK
        return Status.WARN, Severity.LOW, texts

    # --- Verräterische Server-Header ---
    def _check_disclosure(self, headers_lower: dict) -> list[Finding]:
        disclosed = {h: headers_lower[h.lower()] for h in DISCLOSURE_HEADERS if h.lower() in headers_lower}
        if not disclosed:
            return []
        evidence = ", ".join(f"{k}: {v}" for k, v in disclosed.items())
        return [Finding(
            id="headers.information_disclosure",
            category=self.category,
            title=INFO_DISCLOSURE["title"],
            severity=Severity.LOW,
            status=Status.WARN,
            explanation=INFO_DISCLOSURE["explanation"],
            recommendation=INFO_DISCLOSURE["recommendation"],
            effort=Effort.LOW,
            affected=", ".join(disclosed.keys()),
            evidence=evidence,
        )]

    # --- Cookie-Schutzkennzeichen ---
    def _check_cookies(self, resp: requests.Response) -> list[Finding]:
        problem_cookies = []
        for cookie in resp.cookies:
            issues = []
            if not cookie.secure:
                issues.append("Secure")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("HttpOnly")
            if not cookie.get_nonstandard_attr("SameSite"):
                issues.append("SameSite")
            if issues:
                problem_cookies.append(f"{cookie.name} (fehlt: {', '.join(issues)})")

        if not problem_cookies:
            return []
        return [Finding(
            id="headers.cookie_flags",
            category=self.category,
            title=COOKIE_FLAGS["title"],
            severity=Severity.HIGH,
            status=Status.WARN,
            explanation=COOKIE_FLAGS["explanation"],
            recommendation=COOKIE_FLAGS["recommendation"],
            effort=Effort.MEDIUM,
            affected=f"{len(problem_cookies)} Cookie(s)",
            evidence="; ".join(problem_cookies),
        )]

    # --- HTTP→HTTPS-Weiterleitung ---
    def _check_https_redirect(self, domain: str) -> list[Finding]:
        try:
            resp = requests.get(f"http://{domain}", timeout=10, allow_redirects=True)
            redirected = resp.url.startswith("https://")
            evidence = resp.url
        except requests.RequestException as exc:
            redirected = False
            evidence = str(exc)

        if redirected:
            return [Finding(
                id="headers.https_redirect",
                category=self.category,
                title="Automatische Weiterleitung auf HTTPS aktiv",
                severity=Severity.INFO,
                status=Status.PASS,
                explanation="Aufrufe über unverschlüsseltes HTTP werden korrekt auf die "
                            "verschlüsselte HTTPS-Version umgeleitet.",
                recommendation="Keine Maßnahme nötig.",
                effort=Effort.LOW,
                affected="HTTP → HTTPS",
                evidence=evidence,
            )]
        return [Finding(
            id="headers.https_redirect",
            category=self.category,
            title=HTTPS_REDIRECT["title"],
            severity=Severity.MEDIUM,
            status=Status.FAIL,
            explanation=HTTPS_REDIRECT["explanation"],
            recommendation=HTTPS_REDIRECT["recommendation"],
            effort=Effort.LOW,
            affected="HTTP → HTTPS",
            evidence=evidence,
        )]
