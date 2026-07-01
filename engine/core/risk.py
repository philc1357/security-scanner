"""
risk.py — Risiko-Aggregation.

Wandelt die Findings aller Scanner in ein für Laien verständliches Gesamtbild um:
- einen Gesamt-Score (0–100),
- eine Ampel (gruen / gelb / rot),
- Teil-Scores je Kategorie,
- eine nach Priorität sortierte Maßnahmenliste.

Das verallgemeinert die GUT/MITTEL/KRITISCH-Logik des ursprünglichen headerscan.py.
"""

from __future__ import annotations

from .result import Finding, Severity, Status

# Ampel-Schwellen (Punkte). Bewusst streng: Eine fehlende kritische Maßnahme
# soll die Bewertung deutlich nach unten ziehen.
_GREEN_THRESHOLD = 80
_YELLOW_THRESHOLD = 50

_RATING_LABEL = {
    "gruen": "GUT",
    "gelb": "MITTEL",
    "rot": "KRITISCH",
}

_RATING_ASSESSMENT = {
    "gruen": (
        "Die Website erfüllt die meisten wichtigen Sicherheitsanforderungen. "
        "Das Schutzniveau ist solide. Verbleibende Hinweise sollten dennoch geprüft "
        "und bei Gelegenheit behoben werden."
    ),
    "gelb": (
        "Es sind grundlegende Schutzmaßnahmen vorhanden, aber es bestehen Lücken bei einzelnen "
        "Schutzschichten. Das bedeutet nicht automatisch, dass die Website bereits angreifbar ist "
        "— die Lücken sollten aber zeitnah geschlossen werden, um das Schutzniveau weiter zu erhöhen."
    ),
    "rot": (
        "Es fehlen mehrere wichtige Schutzmaßnahmen. Das bedeutet nicht automatisch, dass die "
        "Website bereits erfolgreich angegriffen werden kann — wohl aber, dass wichtige "
        "Sicherheitsnetze fehlen, die einen Angriff verhindern oder seine Folgen begrenzen würden. "
        "Eine zügige Überarbeitung wird empfohlen, idealerweise beginnend mit den unten "
        "priorisierten Punkten."
    ),
}


def _rating_from_score(score: int) -> str:
    if score >= _GREEN_THRESHOLD:
        return "gruen"
    if score >= _YELLOW_THRESHOLD:
        return "gelb"
    return "rot"


def _score_findings(findings: list[Finding]) -> int:
    """
    Score von 100 abwärts: pro FAIL voller, pro WARN halber Severity-Abzug.
    PASS/INFO ziehen keine Punkte ab. Ergebnis wird auf 0–100 begrenzt.
    """
    score = 100
    for f in findings:
        if f.status == Status.FAIL:
            score -= f.severity.weight
        elif f.status == Status.WARN:
            score -= f.severity.weight // 2
    return max(0, min(100, score))


def _prioritized(findings: list[Finding], limit: int = 6) -> list[dict]:
    """
    Liefert die wichtigsten Handlungsempfehlungen: nur FAIL/WARN, nach Schweregrad
    absteigend sortiert, auf `limit` begrenzt.
    """
    order = {s: i for i, s in enumerate(Severity)}  # CRITICAL=0 ... INFO=4
    actionable = [f for f in findings if f.status in (Status.FAIL, Status.WARN)]
    actionable.sort(key=lambda f: (order[f.severity], 0 if f.status == Status.FAIL else 1))
    return [
        {
            "title": f.title,
            "recommendation": f.recommendation,
            "severity": f.severity.value,
            "effort": f.effort.value,
            "category": f.category,
        }
        for f in actionable[:limit]
    ]


def aggregate(findings: list[Finding]) -> dict:
    """Erzeugt das vollständige Risiko-Summary aus allen Findings."""
    overall_score = _score_findings(findings)
    rating = _rating_from_score(overall_score)

    # --- Teil-Scores je Kategorie ---
    categories: dict[str, list[Finding]] = {}
    for f in findings:
        categories.setdefault(f.category, []).append(f)

    category_summaries = []
    for name, items in categories.items():
        cat_score = _score_findings(items)
        category_summaries.append({
            "category": name,
            "score": cat_score,
            "rating": _rating_from_score(cat_score),
            "counts": _count_by_status(items),
        })
    category_summaries.sort(key=lambda c: c["score"])  # schlechteste zuerst

    return {
        "score": overall_score,
        "rating": rating,
        "rating_label": _RATING_LABEL[rating],
        "assessment": _RATING_ASSESSMENT[rating],
        "counts": _count_by_status(findings),
        "categories": category_summaries,
        "priorities": _prioritized(findings),
    }


def _count_by_status(findings: list[Finding]) -> dict:
    counts = {s.value: 0 for s in Status}
    for f in findings:
        counts[f.status.value] += 1
    return counts
