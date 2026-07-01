-- ---------------------------------------------------------------------------
-- Datenbank-Schema für den IT-Sicherheits-Check
-- MySQL / MariaDB. Einspielen z.B. mit:
--   mysql -u root -p < db/schema.sql
-- ---------------------------------------------------------------------------

CREATE DATABASE IF NOT EXISTS website_scanner
    CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE website_scanner;

-- ---------------------------------------------------------------------------
-- Benutzerkonten für die Login-Pflicht. Passwörter werden ausschließlich als
-- bcrypt-Hash (password_hash) gespeichert, niemals im Klartext. Die Registrierung
-- ist anwendungsseitig nur erlaubt, solange noch kein Konto existiert (Erstkonto).
-- Muss VOR der scans-Tabelle stehen, da scans per Fremdschlüssel darauf verweist.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    email         VARCHAR(254)    NOT NULL,
    password_hash VARCHAR(255)    NOT NULL,              -- bcrypt via password_hash()
    created_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- Ein Scan-Lauf je Domain, zugeordnet zum auslösenden Benutzer (user_id).
-- Das vollständige Engine-JSON wird zusätzlich in raw_json archiviert, damit der
-- Report jederzeit unverändert reproduzierbar ist. user_id ist NULL-erlaubt, damit
-- Bestandsdaten ohne Zuordnung bestehen bleiben können.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scans (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id       BIGINT UNSIGNED NULL,                  -- Eigentümer des Scans
    domain        VARCHAR(253)    NOT NULL,
    scanned_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    score         TINYINT UNSIGNED NULL,                 -- 0..100
    rating        ENUM('gruen','gelb','rot') NULL,
    reachable     TINYINT(1)      NOT NULL DEFAULT 0,
    raw_json      JSON            NOT NULL,              -- vollständige Engine-Ausgabe
    PRIMARY KEY (id),
    KEY idx_domain_time (domain, scanned_at),
    KEY idx_user_time (user_id, scanned_at),
    CONSTRAINT fk_scans_user FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- Einzelne Befunde, normalisiert für Auswertungen/Statistiken über mehrere Scans.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS findings (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    scan_id         BIGINT UNSIGNED NOT NULL,
    finding_key     VARCHAR(100)    NOT NULL,            -- z.B. "headers.hsts"
    category        VARCHAR(100)    NOT NULL,
    title           VARCHAR(255)    NOT NULL,
    severity        ENUM('critical','high','medium','low','info') NOT NULL,
    status          ENUM('pass','warn','fail','info')             NOT NULL,
    effort          ENUM('gering','mittel','hoch')                NOT NULL,
    explanation     TEXT            NOT NULL,
    recommendation  TEXT            NOT NULL,
    affected        VARCHAR(255)    NULL,
    evidence        TEXT            NULL,
    PRIMARY KEY (id),
    KEY idx_scan (scan_id),
    KEY idx_severity (severity),
    CONSTRAINT fk_findings_scan FOREIGN KEY (scan_id)
        REFERENCES scans (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- "Eingeloggt bleiben"-Tokens (Remember-Me-Cookie, 30 Tage). Nach dem Muster
-- Selector/Validator: Der Cookie enthält "selector:validator" im Klartext. Die
-- DB speichert NUR den Selector (Lookup-Schlüssel, kein Geheimnis) sowie den
-- SHA-256-Hash des Validators (echtes Geheimnis) — analog zum Passwort-Hash
-- nie im Klartext gespeichert. Bei jeder erfolgreichen Auto-Anmeldung wird der
-- Token rotiert (alte Zeile gelöscht, neue erzeugt), um die Folgen eines
-- gestohlenen Cookies zeitlich zu begrenzen.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS remember_tokens (
    id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id        BIGINT UNSIGNED NOT NULL,
    selector       CHAR(32)        NOT NULL,              -- Lookup-Schlüssel (kein Geheimnis)
    validator_hash CHAR(64)        NOT NULL,              -- SHA-256 des Validators
    expires_at     DATETIME        NOT NULL,
    created_at     DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_selector (selector),
    KEY idx_user (user_id),
    CONSTRAINT fk_remember_user FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- Login-Versuche (Auth-Log) — Grundlage für Brute-Force-Erkennung und ein
-- späteres Rate-Limiting. Es wird jeder Versuch protokolliert (erfolgreich wie
-- fehlgeschlagen). Bewusst KEIN Fremdschlüssel auf users, da auch Versuche mit
-- unbekannten E-Mail-Adressen festgehalten werden sollen.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS login_attempts (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    email       VARCHAR(254)    NULL,                  -- versuchte, normalisierte E-Mail
    ip_address  VARCHAR(45)     NULL,                  -- IPv4/IPv6 lesbar
    user_agent  VARCHAR(255)    NULL,
    success     TINYINT(1)      NOT NULL DEFAULT 0,
    created_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_email_time (email, created_at),
    KEY idx_ip_time (ip_address, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- Aktivitäts-/Audit-Log — wer hat wann was getan (Registrierung, Login, Logout,
-- Scan). user_id ist NULL-erlaubt und per ON DELETE SET NULL gekoppelt, damit der
-- Audit-Trail auch nach Löschung eines Kontos vollständig erhalten bleibt.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS activity_log (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id     BIGINT UNSIGNED NULL,
    action      VARCHAR(50)     NOT NULL,              -- z.B. register, login, logout, scan
    ip_address  VARCHAR(45)     NULL,
    detail      VARCHAR(255)    NULL,                  -- z.B. gescannte Domain / Scan-ID
    created_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_user_time (user_id, created_at),
    KEY idx_action_time (action, created_at),
    CONSTRAINT fk_activity_user FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- Scan-/Fehler-Log — protokolliert jeden Engine-Lauf inkl. Laufzeit, Timeouts
-- und Fehlern. scan_id ist NULL, wenn der Scan vor dem Speichern scheiterte;
-- beide Fremdschlüssel sind ON DELETE SET NULL, damit das Log erhalten bleibt.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_log (
    id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    scan_id      BIGINT UNSIGNED NULL,
    user_id      BIGINT UNSIGNED NULL,
    domain       VARCHAR(253)    NULL,
    status       ENUM('success','timeout','error') NOT NULL,
    duration_ms  INT UNSIGNED    NULL,
    message      TEXT            NULL,                 -- Fehlermeldung / stderr-Auszug
    created_at   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_scan (scan_id),
    KEY idx_status_time (status, created_at),
    CONSTRAINT fk_scanlog_scan FOREIGN KEY (scan_id)
        REFERENCES scans (id) ON DELETE SET NULL,
    CONSTRAINT fk_scanlog_user FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- Kontaktanfragen über die öffentliche Seite kontakt.php. Es gibt genau einen
-- Empfänger (den Betreiber, einzig möglicher angemeldeter Nutzer), daher KEIN
-- Fremdschlüssel auf users — die Nachricht ist unabhängig von einem Konto.
-- is_read erlaubt dem Betreiber, neue von bereits gesichteten Nachrichten auf
-- nachrichten.php zu unterscheiden. ip_address/user_agent dienen ausschließlich
-- der Spam-Erkennung (Rate-Limiting je IP), nicht der Nachverfolgung von Personen.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS contact_messages (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    name        VARCHAR(100)    NULL,                  -- optionale Angabe des Absenders
    email       VARCHAR(254)    NOT NULL,               -- Antwort-Adresse des Absenders
    message     TEXT            NOT NULL,
    ip_address  VARCHAR(45)     NULL,                   -- IPv4/IPv6 lesbar, nur für Rate-Limiting
    user_agent  VARCHAR(255)    NULL,
    is_read     TINYINT(1)      NOT NULL DEFAULT 0,
    created_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_ip_time (ip_address, created_at),
    KEY idx_read_time (is_read, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- Migration für BESTEHENDE Installationen, deren scans-Tabelle noch keine
-- user_id-Spalte besitzt. Auf einer frischen Datenbank werden die Statements
-- nicht benötigt (die Spalte ist oben bereits enthalten). Bei Bedarf einzeln
-- ausführen:
--
--   ALTER TABLE scans
--       ADD COLUMN user_id BIGINT UNSIGNED NULL AFTER id,
--       ADD KEY idx_user_time (user_id, scanned_at),
--       ADD CONSTRAINT fk_scans_user FOREIGN KEY (user_id)
--           REFERENCES users (id) ON DELETE CASCADE;
-- ---------------------------------------------------------------------------
