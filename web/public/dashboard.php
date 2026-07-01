<?php
declare(strict_types=1);

/**
 * dashboard.php — Arbeitsbereich für angemeldete Nutzer.
 *
 * Hier startet der Nutzer neue Scans und sieht eine Übersicht aller eigenen
 * Scans. Die öffentliche Landing-Page (index.php) ist nur für Neukunden; wer
 * angemeldet ist, landet nach dem Login direkt auf dieser Seite.
 */

require __DIR__ . '/web/bootstrap.php';

use App\Auth;
use App\Database;
use App\Repository;

// Login-Pflicht: Das Dashboard ist nur für angemeldete Nutzer erreichbar.
Auth::start();
Auth::requireLogin();

$error = isset($_GET['error']) ? (string) $_GET['error'] : '';

// Scans des angemeldeten Nutzers für die Übersicht laden.
try {
    $repo  = new Repository(Database::connection());
    $scans = $repo->listScansForUser((int) Auth::userId());
} catch (\Throwable $e) {
    $scans = [];
    $error = $error !== '' ? $error : 'Die Scan-Übersicht konnte nicht geladen werden.';
}

// Abbildung der Engine-Bewertung auf Bootstrap-Badges und verständliche Labels.
$ratingBadge = ['gruen' => 'text-bg-success', 'gelb' => 'text-bg-warning', 'rot' => 'text-bg-danger'];
$ratingText  = ['gruen' => 'Gut', 'gelb' => 'Mittel', 'rot' => 'Kritisch'];

$pageTitle = 'Dashboard — IT-Sicherheits-Check';
require __DIR__ . '/web/templates/layout_top.php';
?>

<?php // === Fehlermeldung (z.B. nach fehlgeschlagenem Scan via scan.php) === ?>
<?php if ($error !== ''): ?>
    <div class="alert alert-danger" role="alert"><?= e($error) ?></div>
<?php endif; ?>

<?php // === Neuen Scan starten === ?>
<section class="mb-5">
    <h1 class="h3 fw-bold mb-3">Neuen Scan starten</h1>
    <form action="/scan.php" method="post">
        <div class="input-group input-group-lg shadow-sm">
            <label for="domain" class="visually-hidden">Domain</label>
            <input type="text" id="domain" name="domain" class="form-control"
                   placeholder="z.B. meine-firma.de" autocomplete="off" autofocus required>
            <button type="submit" class="btn btn-primary px-4">Jetzt prüfen</button>
        </div>
    </form>
    <p class="text-secondary small mt-2 mb-0">Es werden nur öffentlich erreichbare Daten geprüft.</p>
</section>

<?php // === Übersicht der eigenen Scans === ?>
<section>
    <h2 class="h4 fw-bold mb-3">Meine Scans</h2>

    <?php if ($scans === []): ?>
        <div class="card border-0 shadow-sm">
            <div class="card-body text-center text-secondary py-5">
                Noch keine Scans vorhanden. Starten Sie oben Ihren ersten Sicherheits-Check.
            </div>
        </div>
    <?php else: ?>
        <div class="card border-0 shadow-sm">
            <div class="table-responsive">
                <table class="table table-hover align-middle mb-0">
                    <thead class="table-light">
                        <tr>
                            <th scope="col">Domain</th>
                            <th scope="col">Datum</th>
                            <th scope="col" class="text-center">Score</th>
                            <th scope="col">Bewertung</th>
                            <th scope="col" class="text-end">Bericht</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($scans as $scan): ?>
                            <?php
                                $rating = (string) ($scan['rating'] ?? '');
                                // Datum freundlich formatieren; bei ungültigem Wert Rohwert zeigen.
                                try {
                                    $when = (new DateTime((string) $scan['scanned_at']))->format('d.m.Y H:i');
                                } catch (\Throwable $e) {
                                    $when = (string) $scan['scanned_at'];
                                }
                            ?>
                            <tr>
                                <td class="fw-semibold"><?= e((string) $scan['domain']) ?></td>
                                <td class="text-nowrap"><?= e($when) ?></td>
                                <td class="text-center">
                                    <?= $scan['score'] !== null ? (int) $scan['score'] : '—' ?>
                                </td>
                                <td>
                                    <?php if (isset($ratingText[$rating])): ?>
                                        <span class="badge <?= e($ratingBadge[$rating]) ?>"><?= e($ratingText[$rating]) ?></span>
                                    <?php else: ?>
                                        <span class="text-secondary">—</span>
                                    <?php endif; ?>
                                </td>
                                <td class="text-end">
                                    <a href="/report.php?id=<?= (int) $scan['id'] ?>" class="btn btn-sm btn-outline-primary">
                                        Bericht ansehen
                                    </a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    <?php endif; ?>
</section>

<?php require __DIR__ . '/web/templates/layout_bottom.php'; ?>
