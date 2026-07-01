"""
recommendations.py — Zentrale, laienverständliche Texte (Deutsch).

Hier liegen die Erklärungs- und Maßnahmentexte, die in Findings einfließen.
Sie sind bewusst ohne Fachjargon formuliert, damit Kleinunternehmer ohne IT-Abteilung
verstehen, was ein Befund für sie bedeutet und was zu tun ist.

Format je Eintrag:
    {
      "title":          kurze Überschrift,
      "explanation":    "Was bedeutet das für mein Unternehmen?",
      "recommendation": "Was muss ich (bzw. mein Dienstleister) konkret tun?",
    }
"""

# ---------------------------------------------------------------------------
# HTTP-Sicherheitsheader (Phase 1)
# ---------------------------------------------------------------------------

HEADER_TEXTS = {
    "Strict-Transport-Security": {
        "title": "Verschlüsselung wird nicht erzwungen (HSTS)",
        "explanation": (
            "Ohne diese Einstellung kann ein Angreifer im selben Netzwerk (z.B. öffentliches WLAN) "
            "die Verbindung Ihrer Besucher auf eine unverschlüsselte Variante umleiten und "
            "mitlesen — etwa Login-Daten oder Formulareingaben."
        ),
        "recommendation": (
            "Lassen Sie den Header 'Strict-Transport-Security' mit einer Gültigkeit von mindestens "
            "einem Jahr (max-age=31536000) setzen. Ihr Webhoster oder Webentwickler kann das in "
            "wenigen Minuten konfigurieren."
        ),
    },
    "Content-Security-Policy": {
        "title": "Kein Schutz gegen eingeschleusten Schadcode (CSP)",
        "explanation": (
            "Eine Content-Security-Policy legt fest, welche Skripte auf Ihrer Seite laufen dürfen, "
            "und ist eine zusätzliche Schutzschicht gegen eingeschleusten Code (Cross-Site-Scripting). "
            "Dass sie fehlt, bedeutet nicht automatisch, dass Ihre Seite tatsächlich angreifbar ist — "
            "es fehlt aber ein Sicherheitsnetz, das im Fall einer anderen Schwachstelle den Schaden "
            "begrenzen oder den Angriff von vornherein verhindern würde."
        ),
        "recommendation": (
            "Führen Sie eine Content-Security-Policy ein und vermeiden Sie 'unsafe-inline' und "
            "'unsafe-eval'. Dies sollte ein Webentwickler umsetzen, da es auf die Seite abgestimmt werden muss."
        ),
    },
    "X-Frame-Options": {
        "title": "Seite kann in fremde Seiten eingebettet werden (Clickjacking)",
        "explanation": (
            "Ohne diesen Schutz lässt sich Ihre Website technisch unsichtbar in eine fremde Seite "
            "einbetten. Das allein bedeutet noch kein konkretes Risiko — entscheidend ist, ob Ihre "
            "Seite Schaltflächen für sensible Aktionen (z.B. Bestellungen, Logins) enthält, die sich "
            "darüber missbrauchen ließen. Der Header ist trotzdem eine einfache, risikolose "
            "Vorsichtsmaßnahme."
        ),
        "recommendation": (
            "Setzen Sie 'X-Frame-Options' auf 'SAMEORIGIN' oder 'DENY' (alternativ "
            "'frame-ancestors' in der Content-Security-Policy). Schnell und ohne Nebenwirkungen umsetzbar."
        ),
    },
    "X-Content-Type-Options": {
        "title": "Browser darf Dateitypen erraten (MIME-Sniffing)",
        "explanation": (
            "Ohne diese Einstellung 'rät' der Browser bei ausgelieferten Dateien den Typ. Das wird "
            "erst zum Problem, wenn an anderer Stelle bereits manipulierte oder nutzergesteuerte "
            "Inhalte ausgeliefert werden — ist das nicht der Fall, besteht durch das Fehlen dieses "
            "Headers allein kein konkretes Risiko. Er ist trotzdem eine einfache, zusätzliche "
            "Absicherung."
        ),
        "recommendation": (
            "Setzen Sie den Header 'X-Content-Type-Options' auf den Wert 'nosniff'. "
            "Eine einzeilige Konfiguration ohne Risiko."
        ),
    },
    "Referrer-Policy": {
        "title": "Interne Adressen können nach außen gelangen (Referrer)",
        "explanation": (
            "Beim Klick auf externe Links übermittelt der Browser standardmäßig, von welcher Seite "
            "der Besucher kam. Das kann interne Pfade oder Suchbegriffe an Fremdanbieter weitergeben."
        ),
        "recommendation": (
            "Setzen Sie eine 'Referrer-Policy', z.B. 'strict-origin-when-cross-origin'. "
            "Einfache, schnelle Konfiguration."
        ),
    },
    "Permissions-Policy": {
        "title": "Browser-Funktionen nicht eingeschränkt (Permissions-Policy)",
        "explanation": (
            "Diese Einstellung begrenzt, welche Browser-Funktionen (Kamera, Mikrofon, Standort) "
            "Ihre Seite und eingebettete Inhalte nutzen dürfen. Fehlt sie, ist der Zugriff unnötig offen."
        ),
        "recommendation": (
            "Fügen Sie eine 'Permissions-Policy' hinzu, die nicht benötigte Funktionen deaktiviert. "
            "Geringer Aufwand, erhöht aber die Kontrolle."
        ),
    },
    "X-XSS-Protection": {
        "title": "Veralteter Schutzmechanismus aktiv (X-XSS-Protection)",
        "explanation": (
            "Dieser Header steuert einen veralteten Filter, den moderne Browser ignorieren. "
            "In bestimmten Konstellationen kann er sogar neue Probleme verursachen."
        ),
        "recommendation": (
            "Entfernen Sie 'X-XSS-Protection' und setzen Sie stattdessen auf eine Content-Security-Policy."
        ),
    },
}

# ---------------------------------------------------------------------------
# Sonderfälle einzelner HTTP-Header (abweichende Bewertung je nach Wert)
# ---------------------------------------------------------------------------

# Eine CSP ist zwar vorhanden, enthält aber abschwächende Direktiven
# ('unsafe-eval' bzw. ein nicht durch 'strict-dynamic' neutralisiertes
# 'unsafe-inline'). Das ist kein fehlender Schutz, sondern ein nachschärfbarer.
CSP_WEAK = {
    "title": "Content-Security-Policy vorhanden, aber abgeschwächt",
    "explanation": (
        "Ihre Seite hat eine Content-Security-Policy — das ist gut. Sie enthält jedoch "
        "Lockerungen wie 'unsafe-inline' oder 'unsafe-eval', die diese Schutzschicht abschwächen. "
        "Auch das ist kein Beleg für eine konkrete Schwachstelle, sondern lediglich ein "
        "geschwächtes Sicherheitsnetz."
    ),
    "recommendation": (
        "Lassen Sie die Policy nachschärfen: 'unsafe-eval' möglichst entfernen und "
        "Inline-Skripte über Nonces/Hashes statt 'unsafe-inline' freigeben (idealerweise "
        "mit 'strict-dynamic'). Das stimmt ein Webentwickler auf Ihre Seite ab."
    ),
}

# Eine vorhandene, nicht abgeschwächte CSP bietet wirksamen Schutz vor
# eingeschleustem Schadcode — hier liegt kein Mangel vor.
CSP_OK = {
    "title": "Schutz gegen eingeschleusten Schadcode aktiv (CSP)",
    "explanation": (
        "Ihre Seite hat eine wirksame Content-Security-Policy. Sie legt fest, welche Skripte "
        "laufen dürfen, und erschwert damit das Einschleusen von fremdem Code (Cross-Site-Scripting)."
    ),
    "recommendation": "Keine Maßnahme nötig.",
}

# X-XSS-Protection: 0 deaktiviert den fehlerhaften Legacy-Filter bewusst —
# genau das empfiehlt OWASP. Hier liegt also kein Mangel vor.
XXSS_DISABLED_OK = {
    "title": "Veralteter XSS-Filter korrekt deaktiviert",
    "explanation": (
        "Der Header 'X-XSS-Protection' steht auf '0' und schaltet damit den veralteten, "
        "fehleranfälligen Browser-Filter bewusst ab. Das entspricht der aktuellen Empfehlung."
    ),
    "recommendation": "Keine Maßnahme nötig.",
}

# ---------------------------------------------------------------------------
# Allgemeine Bausteine
# ---------------------------------------------------------------------------

HTTPS_REDIRECT = {
    "title": "Keine automatische Weiterleitung auf verschlüsselte Verbindung",
    "explanation": (
        "Ruft jemand Ihre Seite ohne 'https://' auf, bleibt die Verbindung unverschlüsselt. "
        "Daten können dann mitgelesen oder verändert werden."
    ),
    "recommendation": (
        "Richten Sie eine automatische Weiterleitung von HTTP auf HTTPS ein. "
        "Jeder Webhoster bietet dafür eine Einstellung."
    ),
}

COOKIE_FLAGS = {
    "title": "Cookies unzureichend abgesichert",
    "explanation": (
        "Cookies ohne die Schutzkennzeichen 'Secure', 'HttpOnly' und 'SameSite' bieten weniger "
        "Schutz, falls an anderer Stelle bereits ein Angriff gelingt (z.B. eingeschleuster Code "
        "oder eine unverschlüsselte Verbindung) — sie verhindern dann nicht zusätzlich, dass "
        "Sitzungsdaten ausgelesen werden. Ihr Fehlen allein bedeutet nicht, dass ein solcher "
        "Zugriff bereits möglich ist."
    ),
    "recommendation": (
        "Lassen Sie für Cookies die Flags 'Secure', 'HttpOnly' und 'SameSite=Lax' (oder 'Strict') setzen. "
        "Das erledigt der Webentwickler in der Anwendungskonfiguration."
    ),
}

INFO_DISCLOSURE = {
    "title": "Server verrät unnötige technische Details",
    "explanation": (
        "Der Server gibt Software-Namen und teils Versionsnummern preis. Angreifer nutzen diese "
        "Informationen, um gezielt nach bekannten Schwachstellen dieser Software zu suchen."
    ),
    "recommendation": (
        "Lassen Sie verräterische Header (z.B. 'Server', 'X-Powered-By') entfernen oder anonymisieren. "
        "Geringer Aufwand in der Serverkonfiguration."
    ),
}

# ---------------------------------------------------------------------------
# Verschlüsselung / TLS-Zertifikat (Phase 2)
# ---------------------------------------------------------------------------

TLS_NO_CONNECTION = {
    "title": "Verschlüsselte Verbindung (HTTPS) nicht möglich",
    "explanation": (
        "Die Website konnte über den verschlüsselten Port (443) nicht erreicht werden. "
        "Ohne funktionierende HTTPS-Verbindung werden alle Daten unverschlüsselt übertragen "
        "und Browser warnen Ihre Besucher."
    ),
    "recommendation": (
        "Lassen Sie HTTPS einrichten. Ein gültiges Zertifikat ist bei den meisten Hostern "
        "kostenlos (z.B. über Let's Encrypt) und oft mit einem Klick aktivierbar."
    ),
}

TLS_CERT_TRUSTED = {
    "title": "Zertifikat gültig und vertrauenswürdig",
    "explanation": (
        "Das Sicherheitszertifikat der Website ist gültig, von einer anerkannten Stelle "
        "ausgestellt und passt zur Domain."
    ),
    "recommendation": "Keine Maßnahme nötig.",
}

TLS_CERT_UNTRUSTED = {
    "title": "Zertifikat nicht vertrauenswürdig",
    "explanation": (
        "Das Sicherheitszertifikat wird von Browsern nicht akzeptiert (z.B. selbst ausgestellt, "
        "abgelaufen oder von einer unbekannten Stelle). Besucher sehen dann eine Warnseite und "
        "verlassen die Website häufig wieder."
    ),
    "recommendation": (
        "Lassen Sie ein gültiges, von einer anerkannten Zertifizierungsstelle ausgestelltes "
        "Zertifikat einrichten (z.B. kostenlos über Let's Encrypt)."
    ),
}

TLS_CERT_HOSTNAME = {
    "title": "Zertifikat passt nicht zur Domain",
    "explanation": (
        "Das Zertifikat ist nicht für diese Domain ausgestellt. Browser zeigen deshalb eine "
        "Sicherheitswarnung an — die Verbindung gilt als nicht vertrauenswürdig."
    ),
    "recommendation": (
        "Lassen Sie ein Zertifikat ausstellen, das exakt auf Ihre Domain (inkl. 'www.') lautet."
    ),
}

TLS_CERT_EXPIRED = {
    "title": "Zertifikat ist abgelaufen",
    "explanation": (
        "Das Sicherheitszertifikat ist nicht mehr gültig. Browser blockieren die Seite mit einer "
        "deutlichen Warnung — die Website ist faktisch nicht mehr nutzbar."
    ),
    "recommendation": (
        "Erneuern Sie das Zertifikat umgehend. Richten Sie nach Möglichkeit eine automatische "
        "Verlängerung ein, damit das künftig nicht erneut passiert."
    ),
}

TLS_CERT_EXPIRING = {
    "title": "Zertifikat läuft bald ab",
    "explanation": (
        "Das Sicherheitszertifikat ist nur noch wenige Tage gültig. Läuft es ab, blockieren "
        "Browser die Website."
    ),
    "recommendation": (
        "Erneuern Sie das Zertifikat rechtzeitig und richten Sie eine automatische Verlängerung ein."
    ),
}

TLS_VALID_DAYS_OK = {
    "title": "Zertifikat noch ausreichend lange gültig",
    "explanation": "Die Restlaufzeit des Zertifikats ist unkritisch.",
    "recommendation": "Keine Maßnahme nötig.",
}

TLS_DEPRECATED_PROTOCOLS = {
    "title": "Veraltete Verschlüsselungsprotokolle aktiv",
    "explanation": (
        "Der Server erlaubt veraltete Protokolle (TLS 1.0/1.1). Diese gelten als unsicher und "
        "können von Angreifern leichter aufgebrochen werden."
    ),
    "recommendation": (
        "Lassen Sie TLS 1.0 und 1.1 abschalten und nur noch TLS 1.2 und 1.3 zulassen. "
        "Eine Einstellung in der Serverkonfiguration."
    ),
}

TLS_NO_DEPRECATED = {
    "title": "Keine veralteten Protokolle aktiv",
    "explanation": "Der Server verzichtet auf die unsicheren Protokolle TLS 1.0 und 1.1.",
    "recommendation": "Keine Maßnahme nötig.",
}

TLS_NO_MODERN = {
    "title": "Kein modernes Verschlüsselungsprotokoll verfügbar",
    "explanation": (
        "Der Server unterstützt weder TLS 1.2 noch TLS 1.3. Moderne Browser und Dienste "
        "verweigern dann zunehmend die Verbindung."
    ),
    "recommendation": (
        "Lassen Sie mindestens TLS 1.2, idealerweise zusätzlich TLS 1.3 aktivieren."
    ),
}

TLS_MODERN_OK = {
    "title": "Modernes Verschlüsselungsprotokoll verfügbar",
    "explanation": "Der Server unterstützt zeitgemäße Verschlüsselung (TLS 1.2/1.3).",
    "recommendation": "Keine Maßnahme nötig.",
}

# ---------------------------------------------------------------------------
# E-Mail & DNS / Schutz vor Spoofing & Phishing (Phase 3)
# Prüft per DNS, ob die Domain gegen das Fälschen von Absenderadressen
# abgesichert ist (SPF, DMARC) und erklärt DKIM laienverständlich.
# ---------------------------------------------------------------------------

EMAIL_SPF_MISSING = {
    "title": "Kein SPF-Eintrag (Schutz vor gefälschten Absendern fehlt)",
    "explanation": (
        "Ohne SPF-Eintrag kann praktisch jeder E-Mails im Namen Ihrer Domain verschicken — "
        "etwa gefälschte Rechnungen oder Phishing an Ihre Kunden. Empfänger-Mailserver haben "
        "keine Möglichkeit zu erkennen, dass solche Mails nicht von Ihnen stammen."
    ),
    "recommendation": (
        "Lassen Sie einen SPF-Eintrag in den DNS-Einstellungen Ihrer Domain hinterlegen. Das ist "
        "ein TXT-Eintrag wie 'v=spf1 include:ihr-mailanbieter.de -all', der festlegt, welche Server "
        "in Ihrem Namen senden dürfen. Ihr Mail- oder Hosting-Anbieter nennt Ihnen den passenden Wert."
    ),
}

EMAIL_SPF_WEAK = {
    "title": "SPF-Eintrag vorhanden, aber zu offen (+all)",
    "explanation": (
        "Ihr SPF-Eintrag endet auf '+all' und erlaubt damit jedem Server, in Ihrem Namen E-Mails "
        "zu versenden. Das hebt die Schutzwirkung von SPF praktisch wieder auf."
    ),
    "recommendation": (
        "Lassen Sie das abschließende '+all' auf '-all' (strikt) oder '~all' (weich) ändern, "
        "damit nur Ihre autorisierten Server als gültige Absender gelten."
    ),
}

EMAIL_SPF_OK = {
    "title": "SPF-Eintrag vorhanden",
    "explanation": (
        "Ihre Domain hat einen SPF-Eintrag. Empfänger-Mailserver können dadurch prüfen, ob eine "
        "E-Mail wirklich von einem für Sie autorisierten Server stammt."
    ),
    "recommendation": "Keine Maßnahme nötig.",
}

EMAIL_DMARC_MISSING = {
    "title": "Kein DMARC-Eintrag (keine Regel gegen Fälschungen)",
    "explanation": (
        "DMARC legt fest, was Empfänger mit gefälschten E-Mails in Ihrem Namen tun sollen, und "
        "schaltet SPF und DKIM erst wirksam zusammen. Ohne DMARC fehlt diese Anweisung — gefälschte "
        "Mails landen eher im Posteingang Ihrer Kunden statt im Spam."
    ),
    "recommendation": (
        "Lassen Sie einen DMARC-Eintrag als TXT-Record unter '_dmarc.ihre-domain.de' anlegen. "
        "Beginnen Sie zum Beobachten mit 'v=DMARC1; p=none; rua=mailto:postmaster@ihre-domain.de' "
        "und verschärfen Sie die Richtlinie später auf 'p=quarantine' oder 'p=reject'."
    ),
}

EMAIL_DMARC_WEAK = {
    "title": "DMARC vorhanden, aber ohne Schutzwirkung (p=none)",
    "explanation": (
        "Ihr DMARC-Eintrag steht auf 'p=none'. Das dient nur der Beobachtung — gefälschte E-Mails "
        "werden weder abgewiesen noch in den Spam verschoben. Der eigentliche Schutz ist also noch "
        "nicht aktiv."
    ),
    "recommendation": (
        "Stellen Sie die DMARC-Richtlinie nach einer Beobachtungsphase auf 'p=quarantine' (Spam-Ordner) "
        "oder 'p=reject' (Abweisung) um, damit Fälschungen tatsächlich blockiert werden."
    ),
}

EMAIL_DMARC_OK = {
    "title": "DMARC-Richtlinie aktiv",
    "explanation": (
        "Ihre Domain hat eine wirksame DMARC-Richtlinie (quarantine oder reject). Gefälschte "
        "E-Mails in Ihrem Namen werden bei den Empfängern aussortiert oder abgewiesen."
    ),
    "recommendation": "Keine Maßnahme nötig.",
}

EMAIL_DKIM_INFO = {
    "title": "DKIM (digitale Signatur Ihrer E-Mails) — bitte selbst prüfen",
    "explanation": (
        "DKIM versieht ausgehende E-Mails mit einer digitalen Signatur, an der Empfänger erkennen, "
        "dass die Nachricht echt und unverändert ist. Ob DKIM aktiv ist, lässt sich von außen nicht "
        "zuverlässig feststellen, da der dafür nötige Name (der „Selector\") nur Ihrem Mail-Anbieter "
        "bekannt ist — diese Prüfung wurde daher bewusst nicht automatisch durchgeführt."
    ),
    "recommendation": (
        "Fragen Sie Ihren Mail-Anbieter (z.B. Microsoft 365, Google Workspace, Ihren Hoster), ob DKIM "
        "für Ihre Domain eingerichtet ist. Falls nicht, lässt es sich dort meist mit wenigen Klicks "
        "aktivieren — zusammen mit SPF und DMARC ergibt das den vollen Schutz vor Absender-Fälschung."
    ),
}

EMAIL_DNS_ERROR = {
    "title": "E-Mail-Sicherheit konnte nicht geprüft werden",
    "explanation": (
        "Die DNS-Einträge der Domain waren zum Zeitpunkt des Scans nicht abrufbar (z.B. Zeitüberschreitung "
        "oder Namensauflösung gestört). Diese Prüfung konnte daher nicht abgeschlossen werden."
    ),
    "recommendation": (
        "Bitte führen Sie den Scan später erneut aus. Tritt das Problem wiederholt auf, kann ein "
        "Fehler in der DNS-Konfiguration Ihrer Domain vorliegen — Ihr Hosting-Anbieter kann das prüfen."
    ),
}

# ---------------------------------------------------------------------------
# Datenschutz / DSGVO (Phase 4)
#
# Hinweis: Die Prüfung erfolgt rein passiv anhand der ausgelieferten HTML-Seite.
# Erst per JavaScript nachgeladene Banner oder Tracker können dabei übersehen werden;
# die Befunde sind Hinweise und kein Rechtsrat. Das spiegelt sich in den Texten wider.
# ---------------------------------------------------------------------------

PRIVACY_TRACKERS_NO_CONSENT = {
    "title": "Tracker laden ohne erkennbare Einwilligung",
    "explanation": (
        "Auf Ihrer Seite wurden Dienste gefunden, die das Verhalten Ihrer Besucher auswerten "
        "(z.B. Google Analytics oder der Facebook-Pixel), ohne dass ein Einwilligungs-Banner "
        "erkennbar war. Nach DSGVO dürfen solche Tracker erst nach aktiver Zustimmung der Besucher "
        "laden — geschieht das vorher, drohen Abmahnungen und Bußgelder."
    ),
    "recommendation": (
        "Lassen Sie ein Einwilligungs-Banner (Consent-Tool) einrichten, das Tracker erst nach "
        "Zustimmung aktiviert, oder verzichten Sie auf die Dienste. Ihr Webentwickler oder ein "
        "Consent-Anbieter (z.B. Cookiebot, Usercentrics) kann das umsetzen."
    ),
}

PRIVACY_TRACKERS_WITH_CONSENT = {
    "title": "Tracker vorhanden — Einwilligung prüfen",
    "explanation": (
        "Auf Ihrer Seite wurden Tracking-Dienste und ein Einwilligungs-Banner gefunden. Das ist "
        "ein gutes Zeichen. Wichtig ist, dass die Tracker tatsächlich erst nach der Zustimmung "
        "laden — das lässt sich von außen nicht abschließend prüfen."
    ),
    "recommendation": (
        "Stellen Sie sicher, dass das Banner die Tracker wirklich blockiert, bis Besucher zustimmen "
        "(„Opt-in\"), und dass eine Ablehnung genauso einfach möglich ist wie die Zustimmung."
    ),
}

PRIVACY_TRACKERS_NONE = {
    "title": "Keine bekannten Tracker gefunden",
    "explanation": (
        "Auf der geprüften Seite wurden keine gängigen Tracking-Dienste erkannt. Das ist aus "
        "Datenschutz-Sicht erfreulich und reduziert den Aufwand für Einwilligungen."
    ),
    "recommendation": "Keine Maßnahme nötig.",
}

PRIVACY_BANNER_PRESENT = {
    "title": "Cookie-/Einwilligungs-Banner erkannt",
    "explanation": (
        "Es wurden Hinweise auf ein Einwilligungs-Banner gefunden. Damit holen Sie die nach DSGVO "
        "nötige Zustimmung Ihrer Besucher ein, bevor nicht zwingend nötige Cookies oder Tracker geladen werden."
    ),
    "recommendation": "Keine Maßnahme nötig — prüfen Sie gelegentlich, ob das Banner korrekt funktioniert.",
}

PRIVACY_BANNER_MISSING = {
    "title": "Kein Einwilligungs-Banner trotz Tracking erkannt",
    "explanation": (
        "Es wurden Tracking-Dienste, aber kein Einwilligungs-Banner gefunden. Nach DSGVO ist für "
        "nicht zwingend nötige Cookies und Tracker die vorherige Zustimmung der Besucher erforderlich."
    ),
    "recommendation": (
        "Lassen Sie ein Consent-Banner einrichten, das die Einwilligung einholt, bevor Tracker laden. "
        "Achten Sie auf eine gleichwertige „Ablehnen\"-Schaltfläche."
    ),
}

PRIVACY_EXTERNAL_RESOURCES = {
    "title": "Inhalte werden von Drittanbietern geladen",
    "explanation": (
        "Ihre Seite bindet Dateien von fremden Servern ein (z.B. Schriftarten, Skripte oder Bilder, "
        "etwa Google Fonts). Schon beim bloßen Aufruf wird dabei die IP-Adresse Ihrer Besucher an "
        "diese Anbieter übertragen — auch das ist datenschutzrechtlich relevant."
    ),
    "recommendation": (
        "Prüfen Sie, ob sich solche Inhalte lokal auf Ihrem eigenen Server einbinden lassen "
        "(z.B. Schriftarten selbst hosten). Wo Drittanbieter nötig sind, sollten ein "
        "Auftragsverarbeitungs-Vertrag und ein Hinweis in der Datenschutzerklärung vorliegen."
    ),
}

PRIVACY_EXTERNAL_NONE = {
    "title": "Keine Inhalte von Drittanbietern erkannt",
    "explanation": (
        "Die geprüfte Seite lädt ihre Inhalte offenbar vom eigenen Server. Dadurch werden keine "
        "Daten Ihrer Besucher ungewollt an Dritte übertragen."
    ),
    "recommendation": "Keine Maßnahme nötig.",
}

PRIVACY_POLICY_PRESENT = {
    "title": "Link zur Datenschutzerklärung gefunden",
    "explanation": (
        "Auf der Seite wurde ein Verweis auf eine Datenschutzerklärung gefunden. Diese ist nach "
        "DSGVO Pflicht und informiert Ihre Besucher darüber, welche Daten Sie verarbeiten."
    ),
    "recommendation": (
        "Keine Maßnahme nötig — achten Sie darauf, dass die Datenschutzerklärung aktuell ist und "
        "tatsächlich alle eingesetzten Dienste (Tracker, Drittanbieter) benennt."
    ),
}

PRIVACY_POLICY_MISSING = {
    "title": "Keine Datenschutzerklärung verlinkt",
    "explanation": (
        "Auf der Startseite wurde kein Link zu einer Datenschutzerklärung gefunden. Eine leicht "
        "auffindbare Datenschutzerklärung ist nach DSGVO verpflichtend; ihr Fehlen ist ein häufiger "
        "Abmahngrund."
    ),
    "recommendation": (
        "Lassen Sie eine Datenschutzerklärung erstellen und von jeder Seite aus gut sichtbar "
        "verlinken (üblicherweise im Fußbereich). Vorlagen-Generatoren und Ihr Webentwickler "
        "können dabei helfen."
    ),
}

PRIVACY_PARSE_ERROR = {
    "title": "Datenschutz-Prüfung konnte nicht abgeschlossen werden",
    "explanation": (
        "Die Inhalte der Seite konnten zum Zeitpunkt des Scans nicht ausgewertet werden (z.B. weil "
        "die Seite nicht erreichbar war oder kein lesbarer HTML-Inhalt geliefert wurde)."
    ),
    "recommendation": (
        "Bitte führen Sie den Scan später erneut aus. Tritt das Problem wiederholt auf, prüfen Sie, "
        "ob die Seite öffentlich und ohne Login erreichbar ist."
    ),
}
