"""
tls.py — TLS/SSL-Scanner (Phase 2).

Prüft die Transportverschlüsselung einer Domain über Port 443:
- Ist das Zertifikat gültig, vertrauenswürdig und passt es zur Domain?
- Wann läuft es ab (abgelaufen / läuft bald ab)?
- Werden veraltete Protokolle (TLS 1.0/1.1) noch angeboten?
- Ist mindestens ein modernes Protokoll (TLS 1.2/1.3) verfügbar?

Bewusst nur mit der Standardbibliothek `ssl` umgesetzt, um keine schwere
Zusatz-Abhängigkeit einzuführen. Die Cipher-Detailanalyse (schwache Cipher-Suites)
bleibt einer späteren Ausbaustufe vorbehalten.
"""

from __future__ import annotations

import socket
import ssl
import warnings
from datetime import datetime, timezone

# Das gezielte Testen veralteter Protokolle löst DeprecationWarnings aus.
# Das ist hier beabsichtigt — Warnungen daher unterdrücken, damit stderr sauber bleibt.
warnings.filterwarnings("ignore", category=DeprecationWarning, module="ssl")

from core import recommendations as R
from core.result import Effort, Finding, Severity, Status
from scanners.base import Scanner

HTTPS_PORT = 443
CONNECT_TIMEOUT = 10
# Unterhalb dieser Restlaufzeit (Tage) wird vor dem Ablauf gewarnt.
EXPIRY_WARN_DAYS = 14

# Protokollversionen, die separat auf Unterstützung getestet werden.
_PROTOCOLS = {
    "TLS 1.0": ssl.TLSVersion.TLSv1,
    "TLS 1.1": ssl.TLSVersion.TLSv1_1,
    "TLS 1.2": ssl.TLSVersion.TLSv1_2,
    "TLS 1.3": ssl.TLSVersion.TLSv1_3,
}


class TlsScanner(Scanner):
    category = "Verschlüsselung (TLS/SSL)"

    def run(self, domain: str, context: dict) -> list[Finding]:
        findings: list[Finding] = []

        # --- 1) Verifizierter Handshake: Vertrauen, Hostname, Zertifikatsdaten ---
        cert, trust_finding = self._check_certificate(domain)
        findings.append(trust_finding)

        # Wenn überhaupt keine TLS-Verbindung möglich war, ist alles Weitere sinnlos.
        if trust_finding.id == "tls.no_connection":
            return findings

        # --- 2) Ablaufdatum prüfen (nur wenn Zertifikatsdaten vorliegen) ---
        expiry_finding = self._check_expiry(cert)
        if expiry_finding is not None:
            findings.append(expiry_finding)

        # --- 3) Unterstützte Protokollversionen testen ---
        findings.extend(self._check_protocols(domain))
        return findings

    # ------------------------------------------------------------------
    # 1) Zertifikat: vertrauenswürdiger Handshake mit Standard-Kontext
    # ------------------------------------------------------------------
    def _check_certificate(self, domain: str) -> tuple[dict | None, Finding]:
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((domain, HTTPS_PORT), timeout=CONNECT_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    proto = ssock.version()
            return cert, self._make(
                "tls.cert_trusted", R.TLS_CERT_TRUSTED, Severity.INFO, Status.PASS,
                affected=domain, evidence=f"verbunden über {proto}",
            )

        except ssl.SSLCertVerificationError as exc:
            # Verifizierung fehlgeschlagen — Ursache klassifizieren.
            reason = (getattr(exc, "verify_message", "") or str(exc)).lower()
            if "expired" in reason:
                texts, fid, sev = R.TLS_CERT_EXPIRED, "tls.cert_expired", Severity.HIGH
            elif "hostname" in reason or "match" in reason:
                texts, fid, sev = R.TLS_CERT_HOSTNAME, "tls.cert_hostname", Severity.HIGH
            else:
                texts, fid, sev = R.TLS_CERT_UNTRUSTED, "tls.cert_untrusted", Severity.HIGH
            return None, self._make(
                fid, texts, sev, Status.FAIL,
                affected=domain, evidence=getattr(exc, "verify_message", str(exc)),
            )

        except (ssl.SSLError, socket.timeout, OSError) as exc:
            # Kein TLS-Handshake möglich (Port zu, kein HTTPS, Netzwerkfehler).
            return None, self._make(
                "tls.no_connection", R.TLS_NO_CONNECTION, Severity.HIGH, Status.FAIL,
                affected=f"{domain}:{HTTPS_PORT}", evidence=str(exc),
            )

    # ------------------------------------------------------------------
    # 2) Restlaufzeit des Zertifikats
    # ------------------------------------------------------------------
    def _check_expiry(self, cert: dict | None) -> Finding | None:
        not_after = (cert or {}).get("notAfter")
        if not not_after:
            return None
        try:
            # Format: 'Jun 23 12:00:00 2026 GMT'
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        except ValueError:
            return None

        days_left = (expires - datetime.now(timezone.utc)).days
        evidence = f"gültig bis {expires.date().isoformat()} ({days_left} Tage)"

        if days_left < 0:
            return self._make("tls.expiry", R.TLS_CERT_EXPIRED, Severity.HIGH, Status.FAIL,
                              affected="Zertifikat", evidence=evidence, effort=Effort.LOW)
        if days_left < EXPIRY_WARN_DAYS:
            return self._make("tls.expiry", R.TLS_CERT_EXPIRING, Severity.MEDIUM, Status.WARN,
                              affected="Zertifikat", evidence=evidence, effort=Effort.LOW)
        return self._make("tls.expiry", R.TLS_VALID_DAYS_OK, Severity.INFO, Status.PASS,
                          affected="Zertifikat", evidence=evidence)

    # ------------------------------------------------------------------
    # 3) Unterstützte Protokollversionen
    # ------------------------------------------------------------------
    def _check_protocols(self, domain: str) -> list[Finding]:
        supported = {
            name: self._supports_version(domain, version)
            for name, version in _PROTOCOLS.items()
        }

        out: list[Finding] = []

        # Veraltete Protokolle (TLS 1.0 / 1.1)
        deprecated = [name for name in ("TLS 1.0", "TLS 1.1") if supported.get(name)]
        if deprecated:
            out.append(self._make(
                "tls.deprecated_protocols", R.TLS_DEPRECATED_PROTOCOLS,
                Severity.MEDIUM, Status.WARN,
                affected=", ".join(deprecated), evidence="aktiviert: " + ", ".join(deprecated),
            ))
        else:
            out.append(self._make(
                "tls.deprecated_protocols", R.TLS_NO_DEPRECATED,
                Severity.INFO, Status.PASS, affected="TLS 1.0 / 1.1",
            ))

        # Moderne Protokolle (TLS 1.2 / 1.3)
        modern = [name for name in ("TLS 1.2", "TLS 1.3") if supported.get(name)]
        if modern:
            out.append(self._make(
                "tls.modern_protocols", R.TLS_MODERN_OK, Severity.INFO, Status.PASS,
                affected=", ".join(modern), evidence="verfügbar: " + ", ".join(modern),
            ))
        else:
            out.append(self._make(
                "tls.modern_protocols", R.TLS_NO_MODERN, Severity.HIGH, Status.FAIL,
                affected="TLS 1.2 / 1.3",
            ))
        return out

    def _supports_version(self, domain: str, version: ssl.TLSVersion) -> bool:
        """
        Testet, ob der Server genau diese TLS-Version annimmt.

        Moderne OpenSSL-Builds verbieten dem Client das Anbieten von TLS 1.0/1.1
        (Security-Level). Damit der Test überhaupt aussagekräftig ist, senken wir für
        die Probe das Security-Level ab ('SECLEVEL=0') — sonst würden veraltete
        Protokolle fälschlich als 'nicht unterstützt' erscheinen.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = version
            ctx.maximum_version = version
        except ValueError:
            return False
        try:
            ctx.set_ciphers("DEFAULT@SECLEVEL=0")
        except ssl.SSLError:
            pass  # Security-Level nicht absenkbar — Probe mit Standardeinstellung
        try:
            with socket.create_connection((domain, HTTPS_PORT), timeout=CONNECT_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain):
                    return True
        except (ssl.SSLError, socket.timeout, OSError):
            return False

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
