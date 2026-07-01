<?php
/**
 * report_body.php — Darstellung eines Sicherheitsberichts (Bootstrap 5).
 *
 * Erwartet die Variable $result (dekodiertes Engine-JSON). Bewusst frei von
 * Datenbank- oder Request-Logik, damit dieselbe Darstellung sowohl von report.php
 * (Daten aus der DB) als auch von Tests (Daten direkt aus der Engine) genutzt werden kann.
 */

$summary  = $result['summary'] ?? [];
$findings = $result['findings'] ?? [];
$meta     = $result['meta'] ?? [];
$rating   = (string) ($summary['rating'] ?? 'rot');
$score    = (int) ($summary['score'] ?? 0);

// --- Anzeige-Hilfen (Beschriftungen, Farbzuordnung zu Bootstrap-Kontextfarben) ---
$ratingText = ['gruen' => 'Gut', 'gelb' => 'Mittel', 'rot' => 'Kritisch'];
$severityLabel = [
    'critical' => 'Kritisch', 'high' => 'Hoch', 'medium' => 'Mittel',
    'low' => 'Niedrig', 'info' => 'Info',
];
// Status (pass/warn/fail/info) → Klassen-Suffix der .finding-/.stat-Komponenten
$statusColor = ['pass' => 'ok', 'warn' => 'warn', 'fail' => 'bad', 'info' => 'info'];
$statusLabel = ['pass' => 'OK', 'warn' => 'Warnung', 'fail' => 'Problem', 'info' => 'Info'];
$statusIcon  = ['pass' => '✓', 'warn' => '!', 'fail' => '✗', 'info' => 'i'];
$severityOrder = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3, 'info' => 4];
// Bewertung (Ampel) → Farbe der Score-Gauge
$ratingColor = ['gruen' => 'ok', 'gelb' => 'warn', 'rot' => 'bad'];

// Findings nach Kategorie gruppieren, innerhalb nach Schweregrad sortieren
$byCategory = [];
foreach ($findings as $f) {
    $byCategory[$f['category'] ?? 'Allgemein'][] = $f;
}
foreach ($byCategory as &$catItems) {
    usort($catItems, static fn($a, $b) =>
        ($severityOrder[$a['severity']] ?? 9) <=> ($severityOrder[$b['severity']] ?? 9));
}
unset($catItems);
?>

<article class="report">

    <!-- Kopf: Domain, Meta-Infos und Score-Gauge -->
    <section class="panel d-flex flex-wrap justify-content-between align-items-center gap-4 p-4 p-md-5 mb-3">
        <div style="min-width:240px;">
            <div class="label-eyebrow">Sicherheitsbericht</div>
            <h1 class="h2 text-break my-2"><?= e($result['domain'] ?? '') ?></h1>
            <div class="text-secondary small">
                Geprüft am <?= e(date('d.m.Y H:i', strtotime((string) ($result['scan_time'] ?? 'now')))) ?>
                <?php if (!empty($meta['reachable'])): ?>
                    &nbsp;·&nbsp; HTTP <?= e((string) ($meta['status_code'] ?? '')) ?>
                    &nbsp;·&nbsp; <?= e((string) ($meta['latency_ms'] ?? '')) ?> ms
                <?php endif; ?>
            </div>
        </div>
        <div class="gauge-ring" style="background:conic-gradient(var(--c-<?= e($ratingColor[$rating] ?? 'bad') ?>) 0 <?= max(0, min(100, $score)) ?>%, #e9ecf3 <?= max(0, min(100, $score)) ?>% 100%);">
            <div class="gauge-inner">
                <div class="gauge-score" style="color:var(--c-<?= e($ratingColor[$rating] ?? 'bad') ?>);"><?= $score ?><small>/100</small></div>
                <div class="gauge-label" style="color:var(--c-<?= e($ratingColor[$rating] ?? 'bad') ?>);"><?= e($ratingText[$rating] ?? '—') ?></div>
            </div>
        </div>
    </section>

    <!-- Verständliche Gesamteinschätzung + Zählung -->
    <section class="panel p-4 mb-3">
        <p class="fs-5 mb-3" style="line-height:1.55;color:#2b303c;"><?= e($summary['assessment'] ?? '') ?></p>
        <div class="d-flex flex-wrap gap-2 align-items-center">
            <span class="chip chip-bad"><span class="dot"></span><?= (int) ($summary['counts']['fail'] ?? 0) ?> Probleme</span>
            <span class="chip chip-warn"><span class="dot"></span><?= (int) ($summary['counts']['warn'] ?? 0) ?> Warnungen</span>
            <span class="chip chip-ok"><span class="dot"></span><?= (int) ($summary['counts']['pass'] ?? 0) ?> in Ordnung</span>
            <button type="button" class="btn-pdf ms-auto no-print" onclick="window.print()">Als PDF speichern</button>
        </div>
    </section>

    <!-- Wichtigste Maßnahmen, nach Priorität -->
    <?php if (!empty($summary['priorities'])): ?>
    <h2 class="section-title mt-5 mb-3">Ihre wichtigsten Maßnahmen</h2>
    <div class="measures">
        <?php foreach ($summary['priorities'] as $i => $p): ?>
            <div class="measure">
                <span class="num"><?= $i + 1 ?></span>
                <div class="flex-grow-1">
                    <div class="m-title"><?= e($p['title'] ?? '') ?></div>
                    <div class="m-desc"><?= e($p['recommendation'] ?? '') ?></div>
                </div>
                <div class="d-flex flex-column align-items-end gap-2">
                    <span class="sev sev-<?= e($severityLabel[$p['severity']] ?? 'Info') ?>"><?= e($severityLabel[$p['severity']] ?? '') ?></span>
                    <span class="effort">Aufwand: <?= e($p['effort'] ?? '') ?></span>
                </div>
            </div>
        <?php endforeach; ?>
    </div>
    <?php endif; ?>

    <!-- Detailbefunde je Kategorie -->
    <h2 class="section-title mt-5 mb-2">Alle Prüfergebnisse im Detail</h2>
    <?php foreach ($byCategory as $category => $items): ?>
        <h3 class="cat-title mt-4 mb-2"><?= e((string) $category) ?></h3>
        <?php foreach ($items as $f):
            $st = $f['status'] ?? 'info';
            $color = $statusColor[$st] ?? 'info'; ?>
            <div class="finding <?= e($color) ?> mb-2">
                <div class="d-flex align-items-center gap-2 flex-wrap">
                    <span class="stat stat-<?= e($color) ?>" title="<?= e($statusLabel[$st] ?? '') ?>"><?= e($statusIcon[$st] ?? '?') ?></span>
                    <span class="f-title flex-grow-1"><?= e($f['title'] ?? '') ?></span>
                    <span class="sev sev-<?= e($severityLabel[$f['severity']] ?? 'Info') ?>"><?= e($severityLabel[$f['severity']] ?? '') ?></span>
                </div>
                <?php if ($st !== 'pass'): ?>
                    <p class="f-desc mt-3 mb-0"><?= e($f['explanation'] ?? '') ?></p>
                    <div class="rec mt-3">
                        <strong>Empfehlung:</strong> <?= e($f['recommendation'] ?? '') ?>
                        <span class="text-secondary">(Aufwand: <?= e($f['effort'] ?? '') ?>)</span>
                    </div>
                <?php endif; ?>
                <?php if (!empty($f['affected']) || !empty($f['evidence'])): ?>
                    <div class="header-line d-flex gap-2 flex-wrap align-items-center mt-3">
                        <?php if (!empty($f['affected'])): ?><span><?= e($f['affected']) ?></span><?php endif; ?>
                        <?php if (!empty($f['evidence'])): ?><code><?= e($f['evidence']) ?></code><?php endif; ?>
                    </div>
                <?php endif; ?>
            </div>
        <?php endforeach; ?>
    <?php endforeach; ?>

    <p class="footnote mt-4 pt-3">Dieses Werkzeug führt ausschließlich passive Prüfungen öffentlich erreichbarer Informationen durch. Es ersetzt keine vollständige Sicherheitsberatung.</p>

    <p class="mt-4 no-print">
        <a class="link-primary text-decoration-none fw-semibold" href="/index.php">← Weitere Website prüfen</a>
    </p>
</article>
