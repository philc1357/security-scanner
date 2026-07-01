# IT-Sicherheits-Check für Kleinunternehmen

Ein Werkzeug, mit dem kleine Unternehmen **ohne eigene IT-Abteilung** die Sicherheit ihrer
Website prüfen können. Eingabe der Domain im Browser → verständliche **Risikoanalyse mit
Ampelbewertung** und **konkreten, priorisierten Handlungsempfehlungen** (als PDF speicherbar).

> Es werden ausschließlich **passive Prüfungen** öffentlich erreichbarer Informationen
> durchgeführt — kein Eindringen, kein Crawling, keine Exploits.

## Architektur

```
Website_Scanner/
├── engine/        Python-Scan-Engine (Kern) — gibt das Ergebnis als JSON aus
│   ├── scan.py            Einstiegspunkt:  python3 scan.py --target <domain> --json
│   ├── core/              Schema, Risiko-Aggregation, SSRF-Schutz, Texte
│   └── scanners/          je Prüfbereich ein Modul (Phase 1: headers.py)
├── web/           PHP-Frontend (PDO/MySQL)
│   ├── public/            index.php · scan.php · report.php · assets/
│   ├── src/               Database · Validator · ScanRunner · Repository
│   ├── templates/         Layout + Report-Darstellung
│   └── config.php.example Konfigurationsvorlage
└── db/schema.sql  MySQL/MariaDB-Schema (scans, findings)
```

**Datenfluss:** Browser → `scan.php` (validiert die Domain strikt) → `ScanRunner` ruft die
Python-Engine sicher auf (`escapeshellarg`, Timeout) → Ergebnis-JSON wird per PDO in
`scans`/`findings` gespeichert → `report.php` zeigt den Bericht.

## Einrichtung

### 1. Python-Engine

```bash
cd Website_Scanner/engine
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# Test:
python3 scan.py --target example.com --pretty
```

### 2. Datenbank (MySQL/MariaDB)

```bash
mysql -u root -p < db/schema.sql
# danach einen eigenen Benutzer anlegen und auf 'website_scanner' berechtigen
```

### 3. Web-Frontend

```bash
cd Website_Scanner/web
cp config.php.example config.php   # DB-Zugang & Python-Pfad eintragen
# Lokaler Entwicklungsserver:
php -S localhost:8000 -t public
```

Browser öffnen: <http://localhost:8000> → Domain eingeben → Bericht erscheint.

> **Wichtig für die Konfiguration:** In `config.php` unter `engine.python` möglichst den
> Interpreter des venv eintragen (`engine/.venv/bin/python3`), damit die Abhängigkeiten
> gefunden werden.

## Sicherheitsmerkmale

- **PDO + Prepared Statements** für alle Datenbankzugriffe (keine SQL-Injection-Fläche).
- **Strikte Eingabevalidierung** der Domain per Allowlist-Regex (`web/src/Validator.php`).
- **SSRF-Schutz** (`engine/core/safety.py`): Ziele, die auf interne/private Adressen
  (localhost, 10/8, 172.16/12, 192.168/16, 169.254/16, ::1 …) auflösen, werden abgelehnt.
- **Command-Injection-Schutz**: Engine-Aufruf nur mit `escapeshellarg()` und festem Befehlspfad,
  plus harte Laufzeitbegrenzung.

> Das Frontend nutzt **Bootstrap 5 via CDN**; `web/public/assets/style.css` enthält nur
> projektspezifische Ergänzungen (Ampel-Verlauf, Score-Gauge, Druck-Styles).

## Geprüft wird

### Phase 1 — HTTP-Sicherheit

| Prüfung | Risiko bei Fehlen |
|---|---|
| Strict-Transport-Security (HSTS) | Mitlesen via unverschlüsselter Verbindung |
| Content-Security-Policy | Cross-Site-Scripting (Schadcode) |
| X-Frame-Options | Clickjacking |
| X-Content-Type-Options | MIME-Sniffing |
| Referrer-Policy | Abfluss interner Adressen |
| Permissions-Policy | unkontrollierter Funktionszugriff |
| Cookie-Flags (Secure/HttpOnly/SameSite) | Session-Diebstahl |
| HTTP→HTTPS-Weiterleitung | unverschlüsselte Übertragung |
| Server-/Powered-By-Header | Information Disclosure |

### Phase 2 — Verschlüsselung (TLS/SSL)

| Prüfung | Risiko bei Fehlen |
|---|---|
| Zertifikat gültig & vertrauenswürdig | Browser-Warnseite, Vertrauensverlust |
| Zertifikat passt zur Domain | Sicherheitswarnung im Browser |
| Restlaufzeit des Zertifikats | Ausfall der Seite bei Ablauf |
| Keine veralteten Protokolle (TLS 1.0/1.1) | leichter aufzubrechende Verschlüsselung |
| Modernes Protokoll (TLS 1.2/1.3) vorhanden | Verbindungsabbrüche bei modernen Clients |

## Bewertung

Der Score startet bei 100 und wird je Befund nach Schweregrad reduziert (FAIL voll, WARN halb).
Daraus ergibt sich eine Ampel:

| Score | Ampel | Bedeutung |
|---|---|---|
| 80–100 | 🟢 Gut | solides Schutzniveau |
| 50–79 | 🟡 Mittel | relevante Lücken, Nachbesserung empfohlen |
| 0–49 | 🔴 Kritisch | dringende Überarbeitung nötig |

## Erweiterung um weitere Prüfbereiche (Phasen 2–5)

Jeder neue Prüfbereich ist ein eigenständiges Scanner-Modul. Vorgehen:

1. `engine/scanners/<bereich>.py` anlegen, von `Scanner` erben, `category` setzen,
   `run(domain, context)` implementieren und `Finding`-Objekte zurückgeben.
2. In `engine/scan.py` die Instanz zu `SCANNERS` hinzufügen.

Schema, Risiko-Aggregation und Report-Darstellung bleiben unverändert. Geplante Phasen:

- **Phase 2 — TLS/SSL:** Zertifikat, Ablaufdatum, veraltete Protokolle, schwache Cipher.
- **Phase 3 — E-Mail/DNS:** SPF, DKIM, DMARC (Schutz vor Spoofing/Phishing).
- **Phase 4 — DSGVO/Cookies:** Cookie-Banner, Tracker, externe Ressourcen.
- **Phase 5 — Ports/CMS:** erreichbare Dienste, CMS-Erkennung, veraltete Versionen.

## Rechtliches

Der Einsatz auf fremden Systemen ohne Genehmigung kann rechtliche Folgen haben (§ 202a StGB).
Das Tool führt nur passive Anfragen durch. Es ersetzt keine vollständige Sicherheitsberatung.
