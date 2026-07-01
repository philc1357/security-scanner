#!/usr/bin/env python3
"""
scan.py — Einstiegspunkt der Scan-Engine.

Ruft alle registrierten Scanner für eine Domain auf, aggregiert die Findings zu einem
Risiko-Summary und gibt das Gesamtergebnis als JSON aus. Das PHP-Frontend ruft genau
diesen Befehl auf und verarbeitet die JSON-Ausgabe weiter.

Verwendung:
    python3 scan.py --target example.com [--json] [--pretty]

Exit-Codes:
    0  Scan erfolgreich (auch wenn Sicherheitsmängel gefunden wurden)
    2  Ziel ungültig oder aus Sicherheitsgründen abgelehnt (SSRF-Schutz)
    1  unerwarteter Fehler
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime

# Eigenes Paket-Verzeichnis in den Importpfad aufnehmen, damit die Engine
# unabhängig vom Aufrufort (z.B. via PHP shell_exec) funktioniert.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import risk                                    # noqa: E402
from core.result import ScanResult                       # noqa: E402
from core.safety import UnsafeTargetError, assert_safe_target, normalize_domain  # noqa: E402
from scanners.email_dns import EmailDnsScanner           # noqa: E402
from scanners.headers import HeaderScanner               # noqa: E402
from scanners.privacy import PrivacyScanner              # noqa: E402
from scanners.tls import TlsScanner                       # noqa: E402

# ---------------------------------------------------------------------------
# Registrierte Scanner. Neue Phasen werden hier ergänzt:
#   from scanners.<bereich> import <Scanner>
#   SCANNERS.append(<Scanner>())
# ---------------------------------------------------------------------------
SCANNERS = [
    HeaderScanner(),
    TlsScanner(),
    EmailDnsScanner(),
    PrivacyScanner(),
]


def run_scan(raw_target: str) -> ScanResult:
    """Validiert das Ziel, führt alle Scanner aus und baut das Gesamtergebnis."""
    domain = normalize_domain(raw_target)
    assert_safe_target(domain)  # SSRF-Schutz: interne/private Ziele werden abgelehnt

    result = ScanResult(
        target=f"https://{domain}",
        domain=domain,
        scan_time=datetime.now().isoformat(timespec="seconds"),
    )

    context: dict = {}
    for scanner in SCANNERS:
        try:
            result.findings.extend(scanner.run(domain, context))
        except Exception as exc:  # ein fehlerhafter Scanner darf den Rest nicht abbrechen
            result.meta.setdefault("scanner_errors", []).append(
                {"scanner": scanner.__class__.__name__, "error": str(exc)}
            )

    result.meta.update(context.get("meta", {}))
    return result


def build_output(result: ScanResult) -> dict:
    """Kombiniert Findings und Risiko-Summary zum finalen Ausgabeobjekt."""
    out = result.to_dict()
    out["summary"] = risk.aggregate(result.findings)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan-Engine — IT-Sicherheits-Check für Websites",
    )
    parser.add_argument("--target", "-t", required=True, help="Domain (z.B. example.com)")
    parser.add_argument("--json", action="store_true", help="JSON-Ausgabe (Standard)")
    parser.add_argument("--pretty", action="store_true", help="JSON eingerückt ausgeben")
    args = parser.parse_args()

    try:
        result = run_scan(args.target)
    except UnsafeTargetError as exc:
        # Vom Frontend erwartetes, kontrolliertes Fehlerformat
        print(json.dumps({"error": str(exc), "error_type": "unsafe_target"}, ensure_ascii=False))
        return 2
    except Exception as exc:  # pragma: no cover
        print(json.dumps({"error": str(exc), "error_type": "internal"}, ensure_ascii=False))
        return 1

    output = build_output(result)
    indent = 2 if args.pretty else None
    print(json.dumps(output, ensure_ascii=False, indent=indent))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
