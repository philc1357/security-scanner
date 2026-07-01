# Projektplan — IT-Sicherheits-Check für Kleinunternehmen

> Dieses Dokument beschreibt **Ziel, Architektur und Roadmap** des Projekts.
> Den aktuellen Umsetzungsstand findest du in [`FORTSCHRITT.md`](FORTSCHRITT.md).

## 1. Ziel & Zielgruppe

Ein Werkzeug, mit dem **kleine Unternehmen ohne eigene IT-Abteilung** die Sicherheit ihrer
Website selbst prüfen können. Der Nutzer gibt im Browser seine Domain ein und erhält eine
verständliche **Risikoanalyse mit Ampelbewertung** sowie **konkrete, priorisierte
Handlungsempfehlungen** (als PDF speicherbar, z.B. zur Weitergabe an den Webdienstleister).

Leitgedanken:
- **Verständlich statt fachlich:** Jeder Befund erklärt „Was bedeutet das für mein Unternehmen?"
  und „Was muss ich tun?" — ohne IT-Jargon.
- **Nur passiv:** ausschließlich Prüfungen öffentlich erreichbarer Informationen
  (kein Eindringen, kein Crawling, keine Exploits).
- **Priorisiert:** der Nutzer sieht sofort, was am dringendsten ist.

## 2. Grundsatzentscheidungen

| Thema | Entscheidung |
|---|---|
| Oberfläche | **Web-App** (für Nicht-Techniker bedienbar) |
| Technologie | **Python-Scan-Engine + PHP/Web-Frontend** (PDO/MySQL), sauber getrennt |
| Prüfumfang | **alle Bereiche, aber phasenweise** — kleiner Code-Umfang pro Schritt |
| Speicherort | `/home/boss/source_code/Website_Scanner/` |
| Herkunft | refaktoriert aus dem ursprünglichen `headerscan.py` |

## 3. Architektur

```
Website_Scanner/
├── engine/        Python-Scan-Engine (Kern) — gibt das Ergebnis als JSON aus
│   ├── scan.py            Einstieg:  python3 scan.py --target <domain> --json
│   ├── core/
│   │   ├── result.py      einheitliches Schema: Finding, Severity, Status, ScanResult
│   │   ├── risk.py        Aggregation: Score (0–100), Ampel, Kategorie-Scores, Priorisierung
│   │   ├── safety.py      SSRF-Schutz: interne/private Ziele ablehnen
│   │   └── recommendations.py  laienverständliche Texte (DE)
│   └── scanners/
│       ├── base.py        Scanner-Schnittstelle: run(domain, context) -> list[Finding]
│       └── headers.py     Phase 1: HTTP-Sicherheitsheader
├── web/           PHP-Frontend (PDO/MySQL)
│   ├── public/    index.php · scan.php · report.php · assets/style.css
│   ├── src/       Database · Validator · ScanRunner · Repository
│   ├── templates/ layout_top · layout_bottom · report_body
│   ├── bootstrap.php       Autoloader + Konfig-Helfer
│   └── config.php.example
└── db/schema.sql  MySQL/MariaDB-Schema (scans, findings)
```

**Datenfluss:**
Browser → `scan.php` (Domain strikt validieren) → `ScanRunner` ruft die Python-Engine sicher
auf (`escapeshellarg` + Timeout) → Ergebnis-JSON wird per PDO in `scans`/`findings` gespeichert
→ `report.php` rendert den Bericht (Ampel + Maßnahmen, druckbar).

**Einheitliches Finding-Schema** (Basis für alle Scanner und den Report):
```
Finding = { id, category, title, severity (critical|high|medium|low|info),
            status (pass|warn|fail|info), explanation ("Was bedeutet das?"),
            recommendation ("Was tun?"), effort (gering|mittel|hoch),
            affected, evidence, references[] }
```

## 4. Bewertungslogik

Score startet bei 100, wird je Befund nach Schweregrad reduziert (FAIL voll, WARN halb).
Gewichte: critical −40, high −20, medium −10, low −3, info 0.

| Score | Ampel | Bedeutung |
|---|---|---|
| 80–100 | 🟢 Gut | solides Schutzniveau |
| 50–79 | 🟡 Mittel | relevante Lücken, Nachbesserung empfohlen |
| 0–49 | 🔴 Kritisch | dringende Überarbeitung nötig |

## 5. Sicherheits-Anforderungen (verbindlich)

- **PDO + Prepared Statements** für alle DB-Zugriffe — keine SQL-Injection-Fläche.
- **Strikte Eingabevalidierung** der Domain per Allowlist-Regex (`web/src/Validator.php`),
  bevor irgendetwas die Engine erreicht.
- **SSRF-Schutz** (`engine/core/safety.py`): Ziele, die auf private/interne Adressen auflösen
  (localhost, 10/8, 172.16/12, 192.168/16, 169.254/16, ::1 …), werden abgelehnt.
- **Command-Injection-Schutz**: Engine-Aufruf nur mit `escapeshellarg()`, festem Befehlspfad
  und harter Laufzeitbegrenzung.

## 6. Roadmap (phasenweise)

Jede neue Phase = **ein neues Scanner-Modul** + eine Zeile Registrierung in `engine/scan.py`.
Schema, Risiko-Aggregation und Report bleiben unverändert.

| Phase | Bereich | Inhalt | Mögliche Libs |
|---|---|---|---|
| **1** | HTTP-Sicherheit | Security-Header, Cookies, HTTPS-Redirect, Disclosure | requests |
| **2** | TLS/SSL | Zertifikat, Ablaufdatum, veraltete Protokolle, schwache Cipher | stdlib `ssl` / `sslyze` |
| **3** | E-Mail/DNS | SPF, DKIM, DMARC (Schutz vor Spoofing/Phishing) | `dnspython` |
| **4** | DSGVO/Cookies | Cookie-Banner, Tracker, externe Ressourcen, Datenschutzhinweis | requests / HTML-Parsing |
| **5** | Ports/CMS | erreichbare Dienste, CMS-Erkennung, veraltete Versionen | socket / Fingerprinting |

### So wird ein neuer Scanner ergänzt
1. `engine/scanners/<bereich>.py` anlegen, von `Scanner` (`scanners/base.py`) erben,
   `category` setzen und `run(domain, context)` implementieren → `Finding`-Liste zurückgeben.
2. Neue Texte in `engine/core/recommendations.py` ablegen (laienverständlich).
3. In `engine/scan.py` die Instanz zu `SCANNERS` hinzufügen.

## 7. Ideen für später (nicht eingeplant)

- Asynchrone Scans / Warteschlange (relevant ab Phase 5, da Ports/TLS länger dauern).
- Echte PDF-Erzeugung serverseitig (aktuell: druckoptimiertes HTML / Browser-„Drucken").
- Verlauf je Domain (mehrere Scans vergleichen) — Datenmodell ist dafür schon vorbereitet.
- Mehrmandantenfähigkeit / Kundenkonten.
