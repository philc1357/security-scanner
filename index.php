<?php
declare(strict_types=1);

require __DIR__ . '/web/bootstrap.php';

use App\Auth;

// Öffentliche Landing-Page: Session starten, aber KEINE Login-Pflicht.
// Die Anmeldung wird erst für den eigentlichen Scan (scan.php) verlangt.
Auth::start();

// Diese Seite ist ausschließlich für Neukunden. Angemeldete Nutzer arbeiten
// im Dashboard und werden direkt dorthin geleitet.
if (Auth::check()) {
    header('Location: /dashboard.php');
    exit;
}

$pageTitle = 'IT-Sicherheits-Check — Website prüfen';
$error = isset($_GET['error']) ? (string) $_GET['error'] : '';

// ---------------------------------------------------------------------------
// Inhaltsdaten der Landing-Page an EINER Stelle gepflegt (Statistiken/OWASP).
//
// Es handelt sich um reale, belegbare Branchenwerte; die Quelle wird jeweils
// direkt am Element ausgewiesen. HINWEIS: Solche Kennzahlen schwanken jährlich
// — vor dem Go-Live gegen die jeweils aktuelle Quelle gegenprüfen (Mozilla
// HTTP Observatory, Scott Helmes Top-1-Mio-Crawl, aktueller Verizon DBIR,
// IBM Cost of a Data Breach Report, aktuelle OWASP-Edition).
// ---------------------------------------------------------------------------

// Drei plakative Kennzahlen für das Awareness-Band.
$keyStats = [
    ['value' => '9 von 10',     'text' => 'Websites fallen bei einer ersten Sicherheitsbewertung durch (Note F).', 'source' => 'Mozilla HTTP Observatory'],
    ['value' => '43 %',         'text' => 'der Cyberangriffe richten sich gezielt gegen kleine Unternehmen.',       'source' => 'Verizon Data Breach Investigations Report'],
    ['value' => '4,88 Mio. $',  'text' => 'durchschnittlicher Schaden pro Datenleck weltweit.',                    'source' => 'IBM Cost of a Data Breach Report 2024'],
];

// Anteil (%) der Websites, denen eine wichtige Schutzmaßnahme FEHLT.
// Bildet bewusst genau die Prüfungen der Engine ab (Balkendiagramm).
$missingProtections = [
    ['label' => 'Content-Security-Policy',   'percent' => 88, 'desc' => 'Bremst eingeschleusten Schad-Code aus (z. B. fremde Skripte).'],
    ['label' => 'HSTS — erzwungenes HTTPS',  'percent' => 75, 'desc' => 'Erzwingt die verschlüsselte Verbindung und verhindert Mitlesen.'],
    ['label' => 'X-Content-Type-Options',    'percent' => 65, 'desc' => 'Verhindert, dass der Browser Dateitypen falsch interpretiert.'],
    ['label' => 'X-Frame-Options',           'percent' => 60, 'desc' => 'Schützt davor, die Seite für Klick-Betrug einzubetten.'],
];

// OWASP Top 10 (2021) — verständlich auf Deutsch. "checked" markiert die
// Bereiche, die der Check tatsächlich abdeckt (ehrliche Zuordnung, kein
// Überversprechen): A02 (TLS), A05 (Header/Konfiguration), A06 (teilweise).
$owaspTop10 = [
    ['rank' => 'A01', 'title' => 'Fehlerhafte Zugriffskontrolle',            'desc' => 'Nutzer gelangen an Daten oder Funktionen, die ihnen nicht zustehen.', 'checked' => false],
    ['rank' => 'A02', 'title' => 'Schwache Verschlüsselung',                 'desc' => 'Daten werden unverschlüsselt oder mit veralteter Technik übertragen.', 'checked' => true],
    ['rank' => 'A03', 'title' => 'Einschleusen von Schad-Code (Injection)',  'desc' => 'Angreifer schmuggeln Befehle ein, etwa über Eingabefelder.', 'checked' => false],
    ['rank' => 'A04', 'title' => 'Unsicheres Grunddesign',                   'desc' => 'Die Schwachstelle steckt schon im Konzept der Anwendung.', 'checked' => false],
    ['rank' => 'A05', 'title' => 'Sicherheits-Fehlkonfiguration',            'desc' => 'Falsche oder fehlende Einstellungen am Server und in den Headern.', 'checked' => true],
    ['rank' => 'A06', 'title' => 'Veraltete Komponenten',                    'desc' => 'Bekannte Lücken in nicht aktualisierter Software.', 'checked' => true],
    ['rank' => 'A07', 'title' => 'Schwache Anmeldeverfahren',                'desc' => 'Unsichere Passwörter oder fehlerhafte Login-Mechanik.', 'checked' => false],
    ['rank' => 'A08', 'title' => 'Manipulierte Daten & Updates',             'desc' => 'Software-Updates oder Daten werden unbemerkt verändert.', 'checked' => false],
    ['rank' => 'A09', 'title' => 'Fehlende Überwachung',                     'desc' => 'Angriffe bleiben unentdeckt, weil nichts protokolliert wird.', 'checked' => false],
    ['rank' => 'A10', 'title' => 'Server-seitige Anfrage-Fälschung (SSRF)',  'desc' => 'Der Server wird missbraucht, um interne Systeme anzugreifen.', 'checked' => false],
];

// Vom Tool geprüfte Bereiche (spiegeln die Engine-Kategorien wider).
$checkAreas = [
    ['icon' => '🔒', 'title' => 'Verschlüsselung (TLS/SSL)',  'desc' => 'Ist die Verbindung sicher und zeitgemäß verschlüsselt?'],
    ['icon' => '🛡️', 'title' => 'HTTP-Sicherheit',            'desc' => 'Schutz-Header, Cookie-Kennzeichen und HTTPS-Weiterleitung.'],
    ['icon' => '✉️', 'title' => 'E-Mail & DNS',               'desc' => 'Schutz davor, dass in Ihrem Namen E-Mails gefälscht werden.'],
    ['icon' => '📋', 'title' => 'Datenschutz & DSGVO',        'desc' => 'Hinweise auf datenschutzrelevante Konfigurationsfehler.'],
];

/**
 * Gibt die zum Anmeldestatus passende Handlungsaufforderung aus:
 * angemeldet → Domain-Scan-Formular, sonst Anmelden/Registrieren-Buttons.
 * $autofocus nur einmal pro Seite setzen; $id hält die IDs eindeutig, weil die
 * CTA mehrfach (Hero + Abschluss) erscheint.
 */
function landing_cta(bool $autofocus = false, string $id = 'domain'): void
{
    if (Auth::check()): ?>
        <form action="/scan.php" method="post">
            <div class="input-group input-group-lg shadow-sm">
                <label for="<?= e($id) ?>" class="visually-hidden">Domain</label>
                <input type="text" id="<?= e($id) ?>" name="domain" class="form-control"
                       placeholder="z.B. meine-firma.de" autocomplete="off"<?= $autofocus ? ' autofocus' : '' ?> required>
                <button type="submit" class="btn btn-primary px-4">Jetzt prüfen</button>
            </div>
        </form>
        <p class="text-secondary small mt-2 mb-0">Es werden nur öffentlich erreichbare Daten geprüft.</p>
    <?php else: ?>
        <div class="d-flex flex-column flex-sm-row gap-2">
            <a href="/register.php" class="btn btn-primary btn-lg px-4">Kostenlos prüfen</a>
            <a href="/login.php" class="btn btn-outline-primary btn-lg px-4">Anmelden</a>
        </div>
        <p class="text-secondary small mt-2 mb-0">Für die Durchführung eines Scans ist eine kostenlose Anmeldung erforderlich.</p>
    <?php endif;
}

require __DIR__ . '/web/templates/layout_top.php';
?>

<!-- ===================================================================
     Hero: starke Botschaft + Handlungsaufforderung links,
     beispielhafte Bericht-Vorschau (spiegelt die Report-Optik) rechts.
==================================================================== -->
<section class="row align-items-center g-5">
    <div class="col-lg-7">
        <h1 class="display-5 fw-bold mb-3">
            Wie sicher ist Ihre Website?<br>
            <span class="text-danger">Die meisten sind es nicht.</span>
        </h1>
        <p class="fs-5 text-secondary mb-4">
            Der IT-Sicherheits-Check prüft Ihre Website in wenigen Sekunden auf typische
            Schwachstellen und liefert eine verständliche Risikoanalyse mit Ampelbewertung
            und klaren Handlungsempfehlungen — ganz ohne IT-Fachwissen.
        </p>

        <?php if ($error !== ''): ?>
            <div class="alert alert-danger" role="alert"><?= e($error) ?></div>
        <?php endif; ?>

        <?php landing_cta(true, 'domain'); ?>

        <!-- Vertrauen schaffende Kurzargumente -->
        <div class="d-flex flex-wrap gap-3 mt-3 text-secondary small">
            <span class="d-inline-flex align-items-center gap-1"><span class="text-success fw-bold" aria-hidden="true">✓</span> Kostenlos</span>
            <span class="d-inline-flex align-items-center gap-1"><span class="text-success fw-bold" aria-hidden="true">✓</span> In unter 60 Sekunden</span>
            <span class="d-inline-flex align-items-center gap-1"><span class="text-success fw-bold" aria-hidden="true">✓</span> Ohne IT-Wissen</span>
            <span class="d-inline-flex align-items-center gap-1"><span class="text-success fw-bold" aria-hidden="true">✓</span> Nur passive Prüfung</span>
        </div>
    </div>

    <div class="col-lg-5">
        <!-- Beispielhafte Ergebnis-Vorschau: zeigt sofort, was der Nutzer bekommt -->
        <div class="card border-0 shadow rating-rot text-white">
            <div class="card-body p-4">
                <div class="d-flex justify-content-between align-items-start gap-2">
                    <div>
                        <div class="text-uppercase small fw-semibold opacity-75" style="letter-spacing:.1em;">Beispielbericht</div>
                        <div class="h5 mb-0 text-break">ihre-firma.de</div>
                    </div>
                    <div class="gauge text-center rounded-3 px-3 py-2">
                        <div class="gauge-score lh-1 fw-bold">34<span class="fs-6 fw-normal opacity-75">/100</span></div>
                        <div class="text-uppercase fw-semibold small mt-1">Kritisch</div>
                    </div>
                </div>
                <ul class="list-unstyled mt-3 mb-0 small">
                    <li class="d-flex gap-2 align-items-center mb-2"><span class="badge rounded-circle text-bg-danger">✗</span> Verschlüsselung nicht erzwungen (HSTS)</li>
                    <li class="d-flex gap-2 align-items-center mb-2"><span class="badge rounded-circle text-bg-danger">✗</span> Content-Security-Policy fehlt</li>
                    <li class="d-flex gap-2 align-items-center"><span class="badge rounded-circle text-bg-warning">!</span> Server verrät die Software-Version</li>
                </ul>
            </div>
        </div>
        <p class="text-center text-secondary small mt-2 mb-0">So sieht Ihr Bericht aus — verständlich und mit klaren Empfehlungen.</p>
    </div>
</section>

<!-- ===================================================================
     Awareness-Band: belegte Kennzahlen + Donut-Diagramm.
     Macht greifbar, wie verbreitet das Problem ist.
==================================================================== -->
<section class="bg-dark text-white rounded-4 p-4 p-md-5 mt-5">
    <div class="row align-items-center g-4 g-md-5">
        <div class="col-lg-5 text-center">
            <!-- Donut: ~90 % unsicher (rot) vs. ~10 % gut abgesichert (grün) -->
            <div class="donut mx-auto" style="--value:90; --donut-hole:#212529;"
                 role="img" aria-label="Rund 90 Prozent der Websites sind unsicher konfiguriert, nur rund 10 Prozent sind gut abgesichert.">
                <div class="donut-label">
                    <div class="display-6 fw-bold mb-0">9/10</div>
                    <div class="small text-uppercase opacity-75">unsicher</div>
                </div>
            </div>
            <div class="d-flex justify-content-center flex-wrap gap-3 mt-3 small">
                <span class="d-inline-flex align-items-center gap-2"><span class="d-inline-block rounded-circle bg-danger" style="width:.75rem;height:.75rem;"></span> unsicher konfiguriert</span>
                <span class="d-inline-flex align-items-center gap-2"><span class="d-inline-block rounded-circle bg-success" style="width:.75rem;height:.75rem;"></span> gut abgesichert</span>
            </div>
        </div>
        <div class="col-lg-7">
            <h2 class="fw-bold mb-3">Das Problem ist größer, als die meisten denken</h2>
            <p class="opacity-75 mb-4">
                Die Mehrheit aller Websites ist nicht sicher konfiguriert — oft ohne dass die
                Betreiber es ahnen. Drei Zahlen, die das belegen:
            </p>
            <div class="row g-4">
                <?php foreach ($keyStats as $s): ?>
                    <div class="col-sm-4">
                        <div class="stat-num text-danger-emphasis"><?= e($s['value']) ?></div>
                        <div class="small opacity-75 mt-1"><?= e($s['text']) ?></div>
                        <div class="small opacity-50 mt-1">Quelle: <?= e($s['source']) ?></div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
    </div>
</section>

<!-- ===================================================================
     Balkendiagramm: Anteil der Websites, denen Schutzmaßnahmen fehlen.
     Bewusst genau die Punkte, die der Check prüft.
==================================================================== -->
<section class="mt-5">
    <h2 class="fw-bold mb-2">Diese Schutzmaßnahmen fehlen den meisten Websites</h2>
    <p class="text-secondary mb-4" style="max-width:65ch;">
        Selbst grundlegende Schutzfunktionen sind bei einem Großteil der Websites nicht aktiv.
        Genau diese Punkte prüft der IT-Sicherheits-Check automatisch für Sie.
    </p>
    <div class="row g-4">
        <?php foreach ($missingProtections as $p): ?>
            <div class="col-md-6">
                <div class="d-flex justify-content-between align-items-baseline">
                    <span class="fw-semibold"><?= e($p['label']) ?></span>
                    <span class="fw-bold text-danger"><?= (int) $p['percent'] ?>&nbsp;%</span>
                </div>
                <div class="progress mt-1" style="height:.9rem;" role="progressbar"
                     aria-label="<?= e($p['label']) ?> fehlt bei <?= (int) $p['percent'] ?> Prozent der Websites"
                     aria-valuenow="<?= (int) $p['percent'] ?>" aria-valuemin="0" aria-valuemax="100">
                    <div class="progress-bar bg-danger" style="width: <?= (int) $p['percent'] ?>%;"></div>
                </div>
                <p class="text-secondary small mt-2 mb-0"><?= e($p['desc']) ?></p>
            </div>
        <?php endforeach; ?>
    </div>
    <p class="text-secondary small fst-italic mt-4 mb-0">
        Anteil der Websites, denen die jeweilige Schutzmaßnahme fehlt.
        Quelle: Analysen der meistbesuchten Websites (Mozilla Observatory, Scott Helme).
    </p>
</section>

<!-- ===================================================================
     OWASP Top 10 — verständlich erklärt, mit Markierung der vom Tool
     abgedeckten Bereiche.
==================================================================== -->
<section class="bg-body-tertiary rounded-4 p-4 p-md-5 mt-5">
    <h2 class="fw-bold mb-2">Die häufigsten Schwachstellen — verständlich erklärt</h2>
    <p class="text-secondary mb-4" style="max-width:72ch;">
        Sicherheitsfachleute weltweit pflegen eine Rangliste der zehn häufigsten
        Web-Schwachstellen: die <strong>OWASP&nbsp;Top&nbsp;10</strong>. Der IT-Sicherheits-Check
        konzentriert sich auf die Bereiche, in denen Websites am häufigsten patzen —
        <span class="badge text-bg-success">✓ geprüft</span> zeigt, was er für Sie abdeckt.
    </p>
    <div class="row g-3">
        <?php foreach ($owaspTop10 as $o): ?>
            <div class="col-md-6">
                <div class="d-flex gap-3 h-100 p-3 bg-body rounded-3 border">
                    <span class="badge text-bg-secondary align-self-start"><?= e($o['rank']) ?></span>
                    <div>
                        <div class="fw-semibold">
                            <?= e($o['title']) ?>
                            <?php if ($o['checked']): ?>
                                <span class="badge text-bg-success ms-1">✓ geprüft</span>
                            <?php endif; ?>
                        </div>
                        <div class="text-secondary small"><?= e($o['desc']) ?></div>
                    </div>
                </div>
            </div>
        <?php endforeach; ?>
    </div>
    <p class="text-secondary small fst-italic mt-4 mb-0">Quelle: OWASP Top&nbsp;10 (2021).</p>
</section>

<!-- ===================================================================
     Warum Websites so oft angreifbar sind — Klartext für Laien.
==================================================================== -->
<section class="mt-5">
    <h2 class="fw-bold mb-4 text-center">Warum sind Websites so oft angreifbar?</h2>
    <div class="row g-4">
        <div class="col-md-4">
            <div class="card h-100 shadow-sm border-0">
                <div class="card-body">
                    <h3 class="h5 mt-2">Standard ist nicht „sicher“</h3>
                    <p class="text-secondary mb-0">Viele Websites gehen online, ohne dass Schutzmechanismen aktiviert werden — Sicherheit ist selten die Voreinstellung.</p>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card h-100 shadow-sm border-0">
                <div class="card-body">
                    <h3 class="h5 mt-2">Angriffe laufen automatisch</h3>
                    <p class="text-secondary mb-0">Bots durchsuchen das Internet rund um die Uhr nach verwundbaren Seiten — gezielt auch kleine Unternehmen.</p>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card h-100 shadow-sm border-0">
                <div class="card-body">
                    <h3 class="h5 mt-2">Niemand prüft es</h3>
                    <p class="text-secondary mb-0">Ohne Fachwissen bleibt unsichtbar, was falsch konfiguriert ist. Probleme fallen oft erst auf, wenn ein Schaden entstanden ist.</p>
                </div>
            </div>
        </div>
    </div>
</section>

<!-- ===================================================================
     Wie der Check hilft: Ablauf in 3 Schritten, geprüfte Bereiche,
     Kernvorteile.
==================================================================== -->
<section class="mt-5">
    <h2 class="fw-bold mb-4 text-center">In drei Schritten zu Ihrem Sicherheitsbericht</h2>
    <div class="row g-4">
        <div class="col-md-4 text-center">
            <span class="badge rounded-circle text-bg-primary fs-5 mb-3" style="width:3rem;height:3rem;">1</span>
            <h3 class="h5">Domain eingeben</h3>
            <p class="text-secondary mb-0">Nach der kostenlosen Anmeldung geben Sie einfach Ihre Internetadresse ein (z.&nbsp;B. <em>meine-firma.de</em>).</p>
        </div>
        <div class="col-md-4 text-center">
            <span class="badge rounded-circle text-bg-primary fs-5 mb-3" style="width:3rem;height:3rem;">2</span>
            <h3 class="h5">Automatische Prüfung</h3>
            <p class="text-secondary mb-0">Das Tool führt mehrere passive Sicherheitsprüfungen durch — ohne Ihre Website zu verändern oder zu belasten.</p>
        </div>
        <div class="col-md-4 text-center">
            <span class="badge rounded-circle text-bg-primary fs-5 mb-3" style="width:3rem;height:3rem;">3</span>
            <h3 class="h5">Verständlicher Bericht</h3>
            <p class="text-secondary mb-0">Sie erhalten eine Ampelbewertung, eine Punktzahl und priorisierte Empfehlungen — als PDF speicherbar.</p>
        </div>
    </div>

    <!-- Geprüfte Bereiche -->
    <h3 class="h5 fw-bold text-center mt-5 mb-3">Das wird geprüft</h3>
    <div class="row g-3">
        <?php foreach ($checkAreas as $a): ?>
            <div class="col-sm-6 col-lg-3">
                <div class="card h-100 shadow-sm border-0 text-center">
                    <div class="card-body">
                        <div class="fs-2" aria-hidden="true"><?= $a['icon'] ?></div>
                        <h4 class="h6 fw-bold mt-1"><?= e($a['title']) ?></h4>
                        <p class="text-secondary small mb-0"><?= e($a['desc']) ?></p>
                    </div>
                </div>
            </div>
        <?php endforeach; ?>
    </div>

    <!-- Kernvorteile -->
    <div class="row g-4 mt-1">
        <div class="col-md-4">
            <div class="card h-100 shadow-sm border-0">
                <div class="card-body">
                    <h3 class="h5 card-title">Verständlich</h3>
                    <p class="card-text text-secondary mb-0">Jeder Befund wird in einfacher Sprache erklärt: Was bedeutet das und was ist zu tun?</p>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card h-100 shadow-sm border-0">
                <div class="card-body">
                    <h3 class="h5 card-title">Priorisiert</h3>
                    <p class="card-text text-secondary mb-0">Sie sehen sofort, welche Maßnahmen am wichtigsten sind — sortiert nach Dringlichkeit.</p>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card h-100 shadow-sm border-0">
                <div class="card-body">
                    <h3 class="h5 card-title">Druckbar</h3>
                    <p class="card-text text-secondary mb-0">Den Bericht können Sie als PDF speichern und Ihrem Webentwickler weitergeben.</p>
                </div>
            </div>
        </div>
    </div>
</section>

<!-- ===================================================================
     Abschluss-Handlungsaufforderung mit Beruhigung.
==================================================================== -->
<section class="text-center bg-primary-subtle rounded-4 p-4 p-md-5 mt-5">
    <h2 class="fw-bold mb-2">Wie sicher ist Ihre Website wirklich?</h2>
    <p class="text-secondary mb-4">Finden Sie es in unter einer Minute heraus — kostenlos und ohne Risiko für Ihre Seite.</p>
    <div class="mx-auto text-start" style="max-width:520px;">
        <?php landing_cta(false, 'domain-cta'); ?>
    </div>
    <p class="text-secondary small mt-3 mb-0">
        Nur passive Prüfung öffentlich erreichbarer Daten — völlig ungefährlich für Ihre Website.
    </p>
</section>

<?php require __DIR__ . '/web/templates/layout_bottom.php'; ?>
