# Fortschritt — IT-Sicherheits-Check

> Lebendes Statusdokument. Beschreibt, **wo wir gerade stehen**, damit in neuen Chats sofort
> klar ist, was erledigt ist und was als Nächstes ansteht. Gesamtplan: [`PLAN.md`](PLAN.md).

**Stand:** 2026-06-23
**Aktuelle Phase:** Phase 4 (DSGVO/Cookies) — **abgeschlossen & verifiziert**

---

## Phasenübersicht

| Phase | Bereich | Status |
|---|---|---|
| 1 | HTTP-Sicherheit (Header, Cookies, HTTPS-Redirect, Disclosure) | ✅ fertig |
| 2 | TLS/SSL (Zertifikat, Ablauf, Protokollversionen) | ✅ fertig |
| 3 | E-Mail/DNS (SPF/DKIM/DMARC) | ✅ fertig |
| 4 | DSGVO/Cookies | ✅ fertig |
| 5 | Ports/CMS | ⬜ offen |

---

## Phase 1 — Details (erledigt)

**Engine (`engine/`)**
- [x] `core/result.py` — Finding/ScanResult-Schema (Severity, Status, Effort)
- [x] `core/risk.py` — Score (0–100), Ampel, Kategorie-Scores, priorisierte Maßnahmen
- [x] `core/safety.py` — SSRF-Schutz + Domain-Normalisierung
- [x] `core/recommendations.py` — laienverständliche DE-Texte
- [x] `scanners/base.py` — Scanner-Schnittstelle
- [x] `scanners/headers.py` — Header, Cookies, HTTPS-Redirect, Disclosure
- [x] `scan.py` — CLI, JSON-Ausgabe, Scanner-Registrierung
- [x] `requirements.txt`

**Web (`web/`)**
- [x] `src/Database.php` — PDO-Singleton (echte Prepared Statements)
- [x] `src/Validator.php` — strikte Domain-Allowlist
- [x] `src/ScanRunner.php` — sicherer Engine-Aufruf (escapeshellarg + Timeout via proc_open)
- [x] `src/Repository.php` — Scans/Findings speichern & laden (PDO)
- [x] `bootstrap.php` — Autoloader + Konfig-Helfer + HTML-Escaping
- [x] `public/index.php` — Startseite + Scan-Formular
- [x] `public/scan.php` — validieren → Engine → speichern → Redirect
- [x] `public/report.php` — lädt Ergebnis, bindet Report-Template ein
- [x] `templates/` — layout_top, layout_bottom, report_body (entkoppelt, testbar)
- [x] `public/assets/style.css` — Ampel-Design inkl. Druck-/PDF-Styles

**Datenbank / Doku**
- [x] `db/schema.sql` — Tabellen `scans`, `findings`
- [x] `README.md`, `.gitignore` (schließt `web/config.php` aus)

### Verifikation Phase 1
- [x] Validator: alle Testfälle korrekt (inkl. Abweisung `'; DROP TABLE`, `localhost`, IPs)
- [x] Engine ↔ ScanRunner gegen echte Domains: `example.com` → 26/rot, `11880.com` → 46/rot
- [x] SSRF/ungültige Ziele werden abgelehnt (Engine + Frontend)
- [x] Report-Rendering visuell per Screenshot geprüft
- [ ] **Voller Web-Flow im Browser noch nicht live getestet** (siehe Offene Punkte)

---

## Phase 2 — Details (erledigt)

- [x] `core/recommendations.py` — TLS-Textbausteine ergänzt (Zertifikat, Ablauf, Protokolle)
- [x] `scanners/tls.py` — neuer Scanner (nur Standardbibliothek `ssl`, keine neue Abhängigkeit):
  - Zertifikat: vertrauenswürdig / nicht vertrauenswürdig / abgelaufen / Hostname-Fehler
  - Restlaufzeit: abgelaufen (FAIL) / läuft bald ab < 14 Tage (WARN) / OK (PASS)
  - veraltete Protokolle TLS 1.0/1.1 (WARN), modernes TLS 1.2/1.3 vorhanden (PASS/FAIL)
- [x] `scan.py` — `TlsScanner` registriert
- [x] Verifikation gegen `badssl.com`: expired/self-signed/wrong.host korrekt klassifiziert;
      Report rendert neue Kategorie „Verschlüsselung (TLS/SSL)" automatisch

### Wichtige technische Entscheidung (Phase 2)
- **Protokoll-Probe mit `DEFAULT@SECLEVEL=0`:** Moderne OpenSSL-Builds verbieten dem Client
  das Anbieten von TLS 1.0/1.1. Ohne Absenken des Security-Levels würden veraltete Protokolle
  fälschlich als „nicht aktiv" gemeldet. Mit SECLEVEL=0 wird die tatsächliche Server-Unterstützung
  korrekt erkannt (per openssl gegengeprüft).
- **Cipher-Detailanalyse** (schwache Cipher-Suites einzeln auflisten) bewusst zurückgestellt —
  würde `sslyze` o.ä. erfordern; aktueller Umfang deckt die für KMU wichtigsten Punkte ab.

---

## Phase 3 — Details (erledigt)

- [x] `requirements.txt` — `dnspython>=2.6.0` aktiviert (system-/venv-weit verfügbar)
- [x] `core/recommendations.py` — E-Mail/DNS-Textbausteine ergänzt
      (SPF fehlt/zu offen/ok, DMARC fehlt/p=none/ok, DKIM-Hinweis, DNS-Fehler)
- [x] `scanners/email_dns.py` — neuer Scanner `EmailDnsScanner`
      (Kategorie „E-Mail & DNS (Spoofing-Schutz)"):
  - SPF: TXT der Domain, `v=spf1` → fehlt (MEDIUM/FAIL) · `+all`/`all` zu offen (LOW/WARN) · sonst PASS
  - DMARC: TXT von `_dmarc.<domain>`, `v=DMARC1` → fehlt (MEDIUM/FAIL) · `p=none` (LOW/WARN) ·
    `p=quarantine`/`p=reject` (PASS)
  - DKIM: bewusst **nur INFO-Hinweis** (kein Probing)
  - eigener Resolver mit hartem Timeout (5 s); DNS-Störung → INFO (nicht bewertet, Score bleibt fair)
- [x] `scan.py` — `EmailDnsScanner` registriert
- [x] Verifikation gegen echte Domains:
  - `google.com`/`wikipedia.org`/`paypal.com` → SPF+DMARC PASS
  - `neverssl.com` → SPF & DMARC fehlen (MEDIUM/FAIL)
  - `iana.org` → DMARC `p=none` (LOW/WARN)
  - Rohdaten per `dig TXT` gegengeprüft; neue Kategorie erscheint automatisch in Report & Summary;
    stderr sauber, keine `scanner_errors`

### Wichtige Entscheidung (Phase 3)
- **DKIM nur als Hinweis, kein aktives Probing.** DKIM-Records liegen unter
  `<selector>._domainkey.<domain>`; der Selector ist passiv nicht zuverlässig ermittelbar.
  Statt durch Raten gängiger Selectors Fehlalarme zu riskieren, gibt der Scanner einen
  laienverständlichen INFO-Befund aus (beim Mail-Provider prüfen lassen).

---

## Phase 4 — Details (erledigt)

- [x] `requirements.txt` — `beautifulsoup4>=4.12.0` ergänzt (HTML-Auswertung;
      systemweit bereits verfügbar, Version 4.12.3)
- [x] `core/recommendations.py` — DSGVO-Textbausteine ergänzt (Tracker mit/ohne
      Einwilligung & ohne, Banner vorhanden/fehlt, externe Ressourcen, Datenschutz-Link, Parse-Fehler)
- [x] `scanners/privacy.py` — neuer Scanner `PrivacyScanner`
      (Kategorie „Datenschutz & DSGVO"), **rein passiv** auf der bereits vom HeaderScanner
      geholten HTML-Antwort (`context["response"]`) — kein erneuter Seitenabruf:
  - **Tracker:** bekannte Dienste (Google Analytics/GTM, Facebook-Pixel, Google Ads,
    Hotjar, LinkedIn, TikTok) in `src`/`href`/Inline-Skript. Tracker **ohne** erkanntes
    Banner → MEDIUM/WARN · **mit** Banner → LOW/INFO · keine → INFO/PASS
  - **Cookie-Banner:** bekannte Consent-Bibliotheken (Cookiebot, Usercentrics, OneTrust …)
    + generische Textheuristik. Banner → PASS · fehlt trotz Tracker → LOW/WARN
  - **Externe Ressourcen:** Drittanbieter-Hosts (≠ eigene Basis-Domain) in
    script/link/img/iframe → LOW/INFO (Google-Fonts-Thematik), sonst INFO/PASS
  - **Datenschutz-Link:** `a`-Tags mit `datenschutz`/`privacy` in href/Text →
    PASS · fehlt → MEDIUM/FAIL
  - defensiv: Parser-Fehler → INFO (`privacy.parse_error`), Score bleibt fair
- [x] `scan.py` — `PrivacyScanner` registriert (nach HeaderScanner, am Listenende)
- [x] Verifikation gegen echte Domains:
  - `example.com` → keine Tracker/Banner/externe, **kein** Datenschutz-Link (MEDIUM/FAIL); Kategorie-Score 90
  - `wikipedia.org` → keine Tracker, Datenschutz-Link PASS, externe Ressourcen INFO
  - `heise.de`/`t-online.de` → Google Ads/Analytics erkannt (MEDIUM/WARN), Datenschutz-Link PASS
  - Positivpfade per HTML-Fixture geprüft: Cookiebot→Banner PASS, Tracker **mit** Banner→LOW/INFO,
    Sub-Domain `shop.example.com` korrekt als **eigene** Partei (nicht „extern") eingestuft
  - neue Kategorie „Datenschutz & DSGVO" erscheint automatisch in Report & Summary;
    stderr sauber, keine `scanner_errors`

### Wichtige Entscheidungen (Phase 4)
- **Rein passive Prüfung — bewusste Grenze:** Banner/Tracker, die erst per JavaScript
  nachgeladen werden, können passiv übersehen werden (z.B. bei heise/t-online wird das
  JS-Consent-Banner nicht erkannt). Bewertung daher **vorsichtig** (eher WARN / LOW–MEDIUM),
  um Fehlalarme zu vermeiden; die Texte stellen klar, dass es Hinweise und keinen Rechtsrat gibt.
- **`beautifulsoup4` als HTML-Parser** (mit dem Nutzer abgestimmt) — kein lxml nötig,
  Standard-Parser `html.parser` genügt.
- **Basis-Domain vereinfacht** (letzte zwei Labels) zur Einstufung „eigene vs. dritte
  Partei" — bewusst ohne Public-Suffix-Liste, um keine weitere Abhängigkeit einzuführen.

---

## Offene Punkte / To-do beim nächsten Mal

1. **DB-Setup steht aus.** MariaDB läuft auf dem System, aber es gab keinen passwortlosen
   Zugang (kein sudo). Zum Aktivieren des Web-Flows nötig:
   - `mysql -u root -p < db/schema.sql`
   - DB-Benutzer anlegen und auf `website_scanner` berechtigen
   - `cp web/config.php.example web/config.php` und Zugangsdaten eintragen
   - In `config.php` unter `engine.python` den venv-Interpreter eintragen
     (`engine/.venv/bin/python3`)
2. **Web-Flow im Browser gegenchecken** (`php -S localhost:8000 -t web/public`),
   sobald die DB steht.
3. **Phase 5 (Ports/CMS)** als nächstes Feature — neues Modul `scanners/ports_cms.py`
   (erreichbare Dienste, CMS-Erkennung, veraltete Versionen) + Registrierung in `scan.py`.
   Hinweis: Port-/Dienst-Scans dauern länger — ggf. asynchrone Verarbeitung erwägen
   (siehe PLAN.md, Abschnitt „Ideen für später").

## Frontend (erledigt)

- [x] **Auf Bootstrap 5 via CDN umgestellt** (Vorgabe): `templates/layout_top.php` bindet
  Bootstrap-CSS ein, `layout_bottom.php` das JS-Bundle. `index.php` und `report_body.php`
  nutzen Bootstrap-Komponenten (Navbar, Cards, Badges, List-Group, Grid).
  `assets/style.css` enthält nur noch Ergänzungen (Ampel-Verlauf, Gauge, runde Status-Icons,
  Druck-Styles). Beide Seiten per Screenshot geprüft.
  - Hinweis: SRI-`integrity`-Attribut bewusst weggelassen (Hash nicht verifizierbar → würde
    bei falschem Wert das Laden blockieren).

---

## Wichtige Entscheidungen (für den Kontext)

- **Cookie-Befund auf Schweregrad HIGH:** Fehlende `Secure`/`HttpOnly`-Flags auf Session-Cookies
  ermöglichen Session-Diebstahl → bewusst als hohes Risiko gewertet (nicht mittel).
  Dadurch wurde `11880.com` korrekt von „mittel" auf „kritisch" eingestuft.
- **Report-Darstellung in eigenes Template `report_body.php` ausgelagert**, damit sie ohne
  Datenbank getestet werden kann (gleiche Darstellung für DB-Daten und Test-Daten).
- **Engine gibt kontrollierte Fehler als JSON** (`error_type: unsafe_target | internal`) zurück,
  damit das Frontend sauber reagieren kann.

---

## So aktuell halten
Am Ende jeder Arbeitssitzung: Phasen-Status anpassen, erledigte Punkte abhaken, „Offene Punkte"
und „Stand"-Datum aktualisieren.
