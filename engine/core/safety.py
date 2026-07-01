"""
safety.py — SSRF-Schutz für die Scan-Engine.

Da der Server HTTP-Anfragen an nutzergesteuerte Ziele stellt, muss verhindert werden,
dass jemand interne Adressen (localhost, private Netze, Cloud-Metadaten-Endpunkte)
scannen lässt, um an interne Dienste zu gelangen (Server-Side Request Forgery).

Vorgehen: Domain syntaktisch prüfen, alle DNS-A/AAAA-Records auflösen und jede
aufgelöste IP gegen eine Sperrliste privater/reservierter Bereiche prüfen.
"""

from __future__ import annotations

import ipaddress
import re
import socket


# Erlaubt: Domainnamen (Labels aus a-z0-9-, kein führender/abschließender Bindestrich)
# mit gültiger TLD. Keine Ports, keine Pfade, kein Schema, keine direkten IPs.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}$"
)


class UnsafeTargetError(ValueError):
    """Wird ausgelöst, wenn ein Ziel nicht gescannt werden darf."""


def normalize_domain(raw: str) -> str:
    """
    Bringt eine Nutzereingabe auf einen reinen Domainnamen.
    Entfernt Schema, Pfad, Port und Whitespace. Wirft UnsafeTargetError bei ungültiger Syntax.
    """
    if not raw:
        raise UnsafeTargetError("Keine Domain angegeben.")

    value = raw.strip().lower()
    # Schema und Pfad/Port abschneiden
    value = re.sub(r"^[a-z]+://", "", value)
    value = value.split("/")[0]
    value = value.split(":")[0]
    value = value.rstrip(".")

    if not _DOMAIN_RE.match(value):
        raise UnsafeTargetError(f"Ungültige Domain: {raw!r}")
    return value


def _is_blocked_ip(ip: str) -> bool:
    """True, wenn die IP in einem privaten/reservierten Bereich liegt."""
    addr = ipaddress.ip_address(ip)
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def assert_safe_target(domain: str) -> list[str]:
    """
    Löst die Domain auf und stellt sicher, dass keine der IPs intern/privat ist.
    Gibt die Liste der öffentlichen IPs zurück oder wirft UnsafeTargetError.
    """
    try:
        infos = socket.getaddrinfo(domain, None)
    except socket.gaierror as exc:
        raise UnsafeTargetError(f"Domain nicht auflösbar: {domain}") from exc

    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise UnsafeTargetError(f"Keine IP-Adresse für {domain} gefunden.")

    for ip in ips:
        if _is_blocked_ip(ip):
            raise UnsafeTargetError(
                f"Ziel {domain} verweist auf eine interne/private Adresse ({ip}) "
                "und wird aus Sicherheitsgründen nicht gescannt."
            )
    return ips
